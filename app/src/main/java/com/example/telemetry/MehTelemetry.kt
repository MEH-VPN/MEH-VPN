package com.example.telemetry

import android.content.Context
import android.os.Build
import android.os.Bundle
import android.util.Log
import com.google.firebase.Firebase
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.analytics.analytics

/**
 * Handles Firebase Analytics & Error Telemetry for MEH VPN:
 * - Tracks app installs (first_open), active sessions, and VPN connection funnel.
 * - Captures and reports both non-fatal pipeline errors (config fetch, speed test, tunnel errors)
 *   and uncaught fatal exceptions to Firebase Analytics.
 */
object MehTelemetry {

  private const val TAG = "MehTelemetry"
  @Volatile private var crashHandlerInstalled = false

  private fun analyticsOrNull(): FirebaseAnalytics? {
    if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return null
    return try {
      Firebase.analytics
    } catch (_: Throwable) {
      null
    }
  }

  fun initialize(context: Context) {
    try {
      installUncaughtExceptionReporter()
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
        FirebaseAnalytics.getInstance(context.applicationContext).setAnalyticsCollectionEnabled(true)
      }
    } catch (t: Throwable) {
      Log.w(TAG, "Firebase Analytics init skipped: ${t.message}")
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
            errorMessage = "${throwable.javaClass.simpleName}: ${throwable.message ?: "no_message"}",
            throwable = throwable,
          )
        } catch (_: Throwable) {}
        previousHandler?.uncaughtException(thread, throwable)
      }
      crashHandlerInstalled = true
    }
  }

  fun logConnectAttempt() {
    logEvent("vpn_connect_attempt", Bundle())
  }

  fun logConfigsFetched(count: Int) {
    val bundle =
      Bundle().apply {
        putInt("config_count", count)
      }
    logEvent("vpn_configs_fetched", bundle)
  }

  fun logServerConnected(protocol: String, serverName: String, latencyMs: Long) {
    val bundle =
      Bundle().apply {
        putString("protocol", protocol.take(36))
        putString("server_name", serverName.take(80))
        putLong("latency_ms", latencyMs)
      }
    logEvent("vpn_connected", bundle)
  }

  fun logDisconnected() {
    logEvent("vpn_disconnected", Bundle())
  }

  fun logError(
    stage: String,
    errorMessage: String,
    throwable: Throwable? = null,
  ) {
    Log.e(TAG, "Error in stage [$stage]: $errorMessage", throwable)
    val topFrame =
      throwable?.stackTrace?.firstOrNull()?.let {
        "${it.className.substringAfterLast('.')}.${it.methodName}:${it.lineNumber}"
      } ?: "none"

    val bundle =
      Bundle().apply {
        putString("error_stage", stage.take(40))
        putString("error_type", (throwable?.javaClass?.simpleName ?: "AppError").take(40))
        putString("error_message", errorMessage.take(100))
        putString("error_location", topFrame.take(80))
      }
    logEvent("app_error_report", bundle)
  }

  private fun logEvent(name: String, params: Bundle) {
    try {
      analyticsOrNull()?.logEvent(name, params)
    } catch (_: Throwable) {
      // Safe fallback in unit tests or pre-M devices
    }
  }
}
