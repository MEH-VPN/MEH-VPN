package com.example.telemetry

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.os.Bundle
import android.util.Log
import com.google.firebase.Firebase
import com.google.firebase.FirebaseApp
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.analytics.analytics
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONArray
import org.json.JSONObject

/**
 * Handles Firebase Analytics, Active User Tracking, and Error Telemetry for MEH VPN:
 * - Verifies and initializes `FirebaseApp` and `FirebaseAnalytics` across both UI (`MainActivity`)
 *   and background VPN service (`MehVpnService`) lifecycles.
 * - Assigns a persistent anonymous installation ID (`user_id`) and user properties (`app_version`,
 *   `android_sdk`, `device_model`, `vpn_status`) for accurate DAU/MAU and Realtime Active User metrics.
 * - Tracks `app_open`, `screen_view`, `vpn_connect_attempt`, `vpn_configs_fetched`, `vpn_connected`,
 *   `vpn_active_heartbeat`, and `vpn_disconnected`.
 * - Persists uncaught crashes (`uncaught_crash`) and pre-connection errors (`app_error_report`) in
 *   `SharedPreferences` and flushes them on next app launch and upon VPN tunnel connection so no
 *   error report is lost on restricted networks or fatal crashes.
 */
object MehTelemetry {

  private const val TAG = "MehTelemetry"
  private const val PREFS_NAME = "meh_telemetry_store"
  private const val KEY_CLIENT_ID = "client_user_id"
  private const val KEY_PENDING_ERRORS = "pending_error_reports"
  private const val KEY_TOTAL_SESSIONS = "total_active_sessions"
  private const val KEY_TOTAL_ERRORS = "total_error_reports"
  private const val MAX_PENDING_ERRORS = 25

  data class RecordedTelemetryEvent(
    val name: String,
    val params: Map<String, String>,
    val timestampMs: Long = System.currentTimeMillis(),
  )

  data class TelemetryDiagnostics(
    val isFirebaseInitialized: Boolean,
    val clientUserId: String,
    val activeSessionsCount: Int,
    val totalErrorsLogged: Int,
    val pendingBufferedErrorsCount: Int,
    val lastVpnStatus: String,
    val recentEvents: List<RecordedTelemetryEvent>,
  )

  @Volatile private var appContext: Context? = null
  @Volatile private var analyticsInstance: FirebaseAnalytics? = null
  @Volatile private var crashHandlerInstalled = false
  @Volatile private var clientUserId: String = ""
  @Volatile private var currentVpnStatus: String = "disconnected"

  private val recentEventsBuffer = CopyOnWriteArrayList<RecordedTelemetryEvent>()
  private val sessionCounter = AtomicInteger(0)
  private val errorCounter = AtomicInteger(0)

  fun initialize(context: Context) {
    val ctx = context.applicationContext ?: context
    appContext = ctx
    installUncaughtExceptionReporter()

    try {
      val prefs = getPrefs(ctx)
      var storedId = prefs?.getString(KEY_CLIENT_ID, null).orEmpty()
      if (storedId.isBlank()) {
        storedId = "meh_${UUID.randomUUID().toString().replace("-", "").take(16)}"
        prefs?.edit()?.putString(KEY_CLIENT_ID, storedId)?.apply()
      }
      clientUserId = storedId

      if (prefs != null) {
        sessionCounter.set(prefs.getInt(KEY_TOTAL_SESSIONS, 0))
        errorCounter.set(prefs.getInt(KEY_TOTAL_ERRORS, 0))
      }

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        try {
          if (FirebaseApp.getApps(ctx).isEmpty()) {
            FirebaseApp.initializeApp(ctx)
          }
        } catch (_: Throwable) {}

        val fa =
          analyticsInstance
            ?: FirebaseAnalytics.getInstance(ctx).also { analyticsInstance = it }
        fa.setAnalyticsCollectionEnabled(true)
        fa.setUserId(storedId)

        val appVersion = resolveAppVersion(ctx)
        fa.setUserProperty("app_version", appVersion.take(36))
        fa.setUserProperty("android_sdk", Build.VERSION.SDK_INT.toString())
        fa.setUserProperty("device_model", "${Build.MANUFACTURER}_${Build.MODEL}".take(36))
        fa.setUserProperty("vpn_status", currentVpnStatus.take(36))

        val defaultParams =
          Bundle().apply {
            putString("app_version", appVersion.take(36))
            putInt("android_sdk", Build.VERSION.SDK_INT)
            putString("device_model", "${Build.MANUFACTURER} ${Build.MODEL}".take(40))
          }
        fa.setDefaultEventParameters(defaultParams)
      }

      flushPendingErrorReports()
    } catch (t: Throwable) {
      Log.w(TAG, "Firebase Analytics init warning: ${t.message}")
    }
  }

  private fun analyticsOrNull(): FirebaseAnalytics? {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
    analyticsInstance?.let { return it }
    val ctx = appContext
    return try {
      if (ctx != null) {
        FirebaseAnalytics.getInstance(ctx).also { analyticsInstance = it }
      } else {
        Firebase.analytics.also { analyticsInstance = it }
      }
    } catch (_: Throwable) {
      null
    }
  }

  private fun installUncaughtExceptionReporter() {
    if (crashHandlerInstalled) return
    synchronized(this) {
      if (crashHandlerInstalled) return
      val previousHandler = Thread.getDefaultUncaughtExceptionHandler()
      Thread.setDefaultUncaughtExceptionHandler { thread, throwable ->
        try {
          logError(
            stage = "uncaught_crash",
            errorMessage =
              "${throwable.javaClass.simpleName}: ${throwable.message ?: "no_message"} (thread=${thread.name})",
            throwable = throwable,
            persistSynchronously = true,
          )
        } catch (_: Throwable) {}
        previousHandler?.uncaughtException(thread, throwable)
      }
      crashHandlerInstalled = true
    }
  }

  /**
   * Logs an active user session (`app_open` + `user_active_session` + `screen_view`) when the app
   * is launched or brought to foreground so Firebase Analytics counts active users accurately.
   */
  fun logAppOpen(screenName: String = "MehMinimalScreen") {
    val sessionNum = sessionCounter.incrementAndGet()
    appContext?.let { ctx ->
      getPrefs(ctx)?.edit()?.putInt(KEY_TOTAL_SESSIONS, sessionNum)?.apply()
    }

    val openParams =
      Bundle().apply {
        putString("client_id", clientUserId.ifBlank { "anonymous" }.take(40))
        putInt("session_number", sessionNum)
        putString("vpn_status", currentVpnStatus)
      }
    logEvent(FirebaseAnalytics.Event.APP_OPEN, openParams)
    logEvent("user_active_session", openParams)

    val screenParams =
      Bundle().apply {
        putString(FirebaseAnalytics.Param.SCREEN_NAME, screenName.take(60))
        putString(FirebaseAnalytics.Param.SCREEN_CLASS, "MainActivity")
      }
    logEvent(FirebaseAnalytics.Event.SCREEN_VIEW, screenParams)
  }

  fun logConnectAttempt() {
    updateVpnStatusProperty("connecting")
    val bundle =
      Bundle().apply {
        putString("connection_method", "V2RAY_SOLISPIRIT")
      }
    logEvent("vpn_connect_attempt", bundle)
  }

  fun logConfigsFetched(count: Int) {
    val bundle =
      Bundle().apply {
        putInt("config_count", count)
      }
    logEvent("vpn_configs_fetched", bundle)
  }

  fun logServerConnected(protocol: String, serverName: String, latencyMs: Long) {
    updateVpnStatusProperty("connected")
    val bundle =
      Bundle().apply {
        putString("protocol", protocol.take(36))
        putString("server_name", serverName.take(80))
        putLong("latency_ms", latencyMs)
      }
    logEvent("vpn_connected", bundle)
    // Now that the VPN tunnel is up, flush any errors that occurred while disconnected/filtered
    flushPendingErrorReports()
  }

  /**
   * Logs periodic active tunnel engagement while the VPN is connected in the background so
   * long-lived VPN users are accurately reflected in Firebase active user engagement metrics.
   */
  fun logActiveSessionHeartbeat(
    serverName: String,
    protocol: String,
    latencyMs: Long,
    uptimeSeconds: Long,
  ) {
    updateVpnStatusProperty("connected")
    val bundle =
      Bundle().apply {
        putString("server_name", serverName.take(80))
        putString("protocol", protocol.take(36))
        putLong("latency_ms", latencyMs)
        putLong("uptime_sec", uptimeSeconds)
      }
    logEvent("vpn_active_heartbeat", bundle)
    flushPendingErrorReports()
  }

  fun logDisconnected() {
    updateVpnStatusProperty("disconnected")
    logEvent("vpn_disconnected", Bundle())
  }

  fun logError(
    stage: String,
    errorMessage: String,
    throwable: Throwable? = null,
    persistSynchronously: Boolean = false,
  ) {
    Log.e(TAG, "Error in stage [$stage]: $errorMessage", throwable)
    val totalErrs = errorCounter.incrementAndGet()
    appContext?.let { ctx ->
      getPrefs(ctx)?.edit()?.putInt(KEY_TOTAL_ERRORS, totalErrs)?.apply()
    }

    val topFrame =
      throwable?.stackTrace?.firstOrNull()?.let {
        "${it.className.substringAfterLast('.')}.${it.methodName}:${it.lineNumber}"
      } ?: "none"

    val errorType = (throwable?.javaClass?.simpleName ?: "AppError").take(40)
    val cleanStage = stage.take(40)
    val cleanMsg = errorMessage.take(100)
    val cleanLoc = topFrame.take(80)

    if (cleanStage == "vpn_tunnel_session" ||
      cleanStage == "vpn_tunnel_establish" ||
      cleanStage == "connect_pipeline" ||
      cleanStage == "fetch_configs" ||
      cleanStage == "verify_candidates"
    ) {
      updateVpnStatusProperty("error")
    }

    val bundle =
      Bundle().apply {
        putString("error_stage", cleanStage)
        putString("error_type", errorType)
        putString("error_message", cleanMsg)
        putString("error_location", cleanLoc)
        putString("vpn_status", currentVpnStatus)
        putInt("error_seq", totalErrs)
      }

    // If the error is a crash or occurs while VPN is not connected, also persist it so it can be
    // guaranteed to flush on next startup or once the VPN connects.
    if (persistSynchronously || cleanStage == "uncaught_crash" || currentVpnStatus != "connected") {
      enqueuePendingError(
        stage = cleanStage,
        errorType = errorType,
        errorMessage = cleanMsg,
        errorLocation = cleanLoc,
        synchronous = persistSynchronously || cleanStage == "uncaught_crash",
      )
    }

    logEvent("app_error_report", bundle)
  }

  /**
   * Flushes any persisted crash or pre-connection error reports stored in `SharedPreferences`
   * to Firebase Analytics.
   */
  fun flushPendingErrorReports(): Int {
    val ctx = appContext ?: return 0
    val prefs = getPrefs(ctx) ?: return 0
    val rawJson = prefs.getString(KEY_PENDING_ERRORS, null)
    if (rawJson.isNullOrBlank()) return 0

    return try {
      val arr = JSONArray(rawJson)
      val count = arr.length()
      if (count == 0) return 0

      // Clear first to avoid duplicate re-emission
      prefs.edit().remove(KEY_PENDING_ERRORS).apply()

      for (i in 0 until count) {
        val obj = arr.optJSONObject(i) ?: continue
        val stage = obj.optString("stage", "unknown").take(40)
        val type = obj.optString("type", "AppError").take(40)
        val msg = obj.optString("msg", "").take(100)
        val loc = obj.optString("loc", "none").take(80)
        val ts = obj.optLong("ts", 0L)

        val bundle =
          Bundle().apply {
            putString("error_stage", stage)
            putString("error_type", type)
            putString("error_message", msg)
            putString("error_location", loc)
            putLong("original_timestamp_ms", ts)
            putString("delivery_mode", "flushed_from_queue")
          }
        val eventName =
          if (stage == "uncaught_crash") "app_crash_recovered" else "app_error_flushed"
        logEvent(eventName, bundle)
      }
      count
    } catch (_: Throwable) {
      0
    }
  }

  fun getDiagnostics(): TelemetryDiagnostics {
    val ctx = appContext
    val pendingCount =
      try {
        val raw = ctx?.let { getPrefs(it)?.getString(KEY_PENDING_ERRORS, null) }
        if (raw.isNullOrBlank()) 0 else JSONArray(raw).length()
      } catch (_: Throwable) {
        0
      }

    val isReady =
      try {
        analyticsInstance != null || (ctx != null && FirebaseApp.getApps(ctx).isNotEmpty())
      } catch (_: Throwable) {
        false
      }

    return TelemetryDiagnostics(
      isFirebaseInitialized = isReady,
      clientUserId = clientUserId,
      activeSessionsCount = sessionCounter.get(),
      totalErrorsLogged = errorCounter.get(),
      pendingBufferedErrorsCount = pendingCount,
      lastVpnStatus = currentVpnStatus,
      recentEvents = recentEventsBuffer.toList(),
    )
  }

  private fun updateVpnStatusProperty(status: String) {
    currentVpnStatus = status
    try {
      analyticsOrNull()?.setUserProperty("vpn_status", status.take(36))
    } catch (_: Throwable) {}
  }

  private fun enqueuePendingError(
    stage: String,
    errorType: String,
    errorMessage: String,
    errorLocation: String,
    synchronous: Boolean,
  ) {
    val ctx = appContext ?: return
    val prefs = getPrefs(ctx) ?: return
    try {
      val existing = prefs.getString(KEY_PENDING_ERRORS, null)
      val arr = if (existing.isNullOrBlank()) JSONArray() else JSONArray(existing)
      val trimmed = JSONArray()
      val startIdx = (arr.length() - (MAX_PENDING_ERRORS - 1)).coerceAtLeast(0)
      for (i in startIdx until arr.length()) {
        arr.optJSONObject(i)?.let { trimmed.put(it) }
      }
      val entry =
        JSONObject().apply {
          put("stage", stage)
          put("type", errorType)
          put("msg", errorMessage)
          put("loc", errorLocation)
          put("ts", System.currentTimeMillis())
        }
      trimmed.put(entry)
      val editor = prefs.edit().putString(KEY_PENDING_ERRORS, trimmed.toString())
      if (synchronous) {
        editor.commit()
      } else {
        editor.apply()
      }
    } catch (_: Throwable) {}
  }

  private fun getPrefs(context: Context): SharedPreferences? {
    return try {
      context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    } catch (_: Throwable) {
      null
    }
  }

  private fun resolveAppVersion(context: Context): String {
    return try {
      val pInfo = context.packageManager.getPackageInfo(context.packageName, 0)
      pInfo.versionName ?: "1.0"
    } catch (_: Throwable) {
      "1.0"
    }
  }

  private fun logEvent(name: String, params: Bundle) {
    try {
      val map = LinkedHashMap<String, String>()
      for (key in params.keySet()) {
        @Suppress("DEPRECATION")
        val v = params.get(key)
        if (v != null) {
          map[key] = v.toString()
        }
      }
      while (recentEventsBuffer.size >= 50) {
        recentEventsBuffer.removeAt(0)
      }
      recentEventsBuffer.add(RecordedTelemetryEvent(name = name, params = map))
    } catch (_: Throwable) {}

    try {
      analyticsOrNull()?.logEvent(name, params)
    } catch (_: Throwable) {
      // Safe fallback in unit tests or pre-M devices
    }
  }
}
