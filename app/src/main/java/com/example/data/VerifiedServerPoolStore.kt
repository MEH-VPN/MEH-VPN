package com.example.data

import android.content.Context
import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import com.example.vpn.V2RayOutboundClient
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import org.json.JSONArray
import org.json.JSONObject

/**
 * Shared persistent cache of freshly verified, low-latency V2Ray servers maintained by both
 * the gentle background [com.example.vpn.BackgroundServerScannerJobService] and live VPN sessions.
 *
 * - Survives app exit, VPN disconnects, and process restarts via SharedPreferences.
 * - Automatically prunes expired entries and nodes marked dead in [DeadServerStore].
 * - Broadcasts live updates via [poolUpdates] so an active [com.example.vpn.MehVpnService]
 *   can absorb newly discovered standby servers without disrupting the current tunnel.
 */
object VerifiedServerPoolStore {

  private const val PREFS_NAME = "meh_verified_server_pool_prefs"
  private const val KEY_VERIFIED_POOL_JSON = "verified_pool_json"
  private const val KEY_BATCH_CURSOR = "scan_batch_cursor"
  private const val KEY_LAST_SCAN_AT_MS = "last_scan_at_ms"
  private const val KEY_CACHE_APP_VERSION = "cache_app_version_code"
  private const val KEY_CACHE_INSTALL_TIME_MS = "cache_install_update_time_ms"
  private const val PREFS_LAST_SERVER = "meh_last_server_prefs"
  private const val KEY_SAVED_CANDIDATES_JSON = "saved_candidates_json"

  /** Maximum number of fastest verified servers kept in persistent storage. */
  const val MAX_POOL_SIZE = 15

  /** Entries tested within 45 minutes are treated as "fresh" for instant fast-connect. */
  const val FRESH_MAX_AGE_MS = 45L * 60L * 1000L

  /** Hard expiry for cached servers so stale configs never linger indefinitely. */
  const val DEFAULT_ENTRY_TTL_MS = 6L * 60L * 60L * 1000L

  private val storeLock = Any()

  private val _poolUpdates = MutableSharedFlow<List<V2RayConfig>>(extraBufferCapacity = 8)
  val poolUpdates: SharedFlow<List<V2RayConfig>> = _poolUpdates.asSharedFlow()

  internal data class StoredServerEntry(
    val config: V2RayConfig,
    val testedAtMs: Long,
  )

  /**
   * Merges newly verified [configs] into the persistent pool, updates timestamps/latencies for
   * existing endpoints, drops dead/expired/unsupported servers, keeps the fastest [MAX_POOL_SIZE],
   * and notifies live observers.
   */
  fun upsertVerified(
    context: Context,
    configs: List<V2RayConfig>,
    nowMs: Long = System.currentTimeMillis(),
  ): List<V2RayConfig> {
    if (configs.isEmpty()) return getFastest(context, nowMs = nowMs)
    val appCtx = context.applicationContext
    val deadKeys = DeadServerStore.deadKeys(appCtx)

    val sortedConfigs =
      synchronized(storeLock) {
        val existingByKey =
          loadRawEntries(appCtx)
            .filter { entry ->
              nowMs - entry.testedAtMs in 0L until DEFAULT_ENTRY_TTL_MS &&
                entry.config.endpointKey !in deadKeys &&
                V2RayOutboundClient.isSupportedByEngine(entry.config)
            }
            .associateBy { it.config.endpointKey }
            .toMutableMap()

        for (cfg in configs) {
          if (cfg.endpointKey.isBlank()) continue
          if (cfg.endpointKey in deadKeys) continue
          if (!V2RayOutboundClient.isSupportedByEngine(cfg)) continue
          val sanitized =
            cfg.copy(
              latencyMs = cfg.latencyMs.coerceAtLeast(1L),
            )
          existingByKey[sanitized.endpointKey] =
            StoredServerEntry(
              config = sanitized,
              testedAtMs = nowMs,
            )
        }

        val ranked =
          existingByKey.values
            .sortedWith(
              compareBy<StoredServerEntry> { it.config.latencyMs.coerceAtLeast(1L) }
                .thenByDescending { it.config.speedScore }
                .thenByDescending { it.testedAtMs }
            )
            .take(MAX_POOL_SIZE)

        saveRawEntries(appCtx, ranked)
        ranked.map { it.config }
      }

    if (sortedConfigs.isNotEmpty()) {
      _poolUpdates.tryEmit(sortedConfigs)
    }
    return sortedConfigs
  }

  /**
   * Returns cached verified servers tested within [maxAgeMs], excluding any endpoints currently
   * marked dead in [DeadServerStore], sorted fastest-first by latency.
   */
  fun getFastest(
    context: Context,
    maxAgeMs: Long = DEFAULT_ENTRY_TTL_MS,
    nowMs: Long = System.currentTimeMillis(),
  ): List<V2RayConfig> {
    val appCtx = context.applicationContext
    val deadKeys = DeadServerStore.deadKeys(appCtx)
    return synchronized(storeLock) {
      val allEntries = loadRawEntries(appCtx)
      val nonExpired =
        allEntries.filter { entry ->
          val age = nowMs - entry.testedAtMs
          age in 0L until DEFAULT_ENTRY_TTL_MS &&
            entry.config.endpointKey !in deadKeys &&
            V2RayOutboundClient.isSupportedByEngine(entry.config)
        }
      if (nonExpired.size != allEntries.size) {
        saveRawEntries(appCtx, nonExpired)
      }
      nonExpired
        .filter { entry -> (nowMs - entry.testedAtMs) <= maxAgeMs }
        .sortedWith(
          compareBy<StoredServerEntry> { it.config.latencyMs.coerceAtLeast(1L) }
            .thenByDescending { it.config.speedScore }
            .thenByDescending { it.testedAtMs }
        )
        .map { it.config }
    }
  }

  /** Convenience helper returning servers verified within [FRESH_MAX_AGE_MS]. */
  fun getFastestFresh(
    context: Context,
    nowMs: Long = System.currentTimeMillis(),
  ): List<V2RayConfig> = getFastest(context, maxAgeMs = FRESH_MAX_AGE_MS, nowMs = nowMs)

  /** Removes a failed endpoint from the cached pool immediately. */
  fun removeEndpoint(context: Context, endpointKey: String) {
    if (endpointKey.isBlank()) return
    val appCtx = context.applicationContext
    synchronized(storeLock) {
      val existing = loadRawEntries(appCtx)
      val filtered = existing.filter { it.config.endpointKey != endpointKey }
      if (filtered.size != existing.size) {
        saveRawEntries(appCtx, filtered)
      }
    }
  }

  /**
   * Returns the current subscription batch index in `0 until totalBatches` and advances the
   * persistent cursor so successive gentle background runs rotate smoothly across all sources.
   */
  fun nextScanBatchIndex(context: Context, totalBatches: Int): Int {
    if (totalBatches <= 0) return 0
    val appCtx = context.applicationContext
    return synchronized(storeLock) {
      val prefs = appCtx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      val current = prefs.getInt(KEY_BATCH_CURSOR, 0).coerceAtLeast(0) % totalBatches
      val next = (current + 1) % totalBatches
      prefs.edit().putInt(KEY_BATCH_CURSOR, next).apply()
      current
    }
  }

  fun getLastScanAtMs(context: Context): Long {
    val appCtx = context.applicationContext
    return appCtx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .getLong(KEY_LAST_SCAN_AT_MS, 0L)
  }

  fun markScanCompleted(context: Context, nowMs: Long = System.currentTimeMillis()) {
    val appCtx = context.applicationContext
    appCtx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .putLong(KEY_LAST_SCAN_AT_MS, nowMs)
      .apply()
  }

  fun clear(context: Context) {
    val appCtx = context.applicationContext
    synchronized(storeLock) {
      appCtx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .edit()
        .clear()
        .apply()
    }
  }

  /**
   * Automatically clears stale cached servers, last-connected server history, and dead-server
   * blacklists ONCE whenever the app is upgraded to a new [currentVersionCode] OR reinstalled in
   * place (detected via Android's [PackageInfo.lastUpdateTime]), so in-place APK updates behave
   * identically to a clean install and never inherit stale configs from older builds.
   */
  fun resetCachesIfAppUpdated(
    context: Context,
    currentVersionCode: Int,
    installUpdateTimeMs: Long = readPackageLastUpdateTimeMs(context),
  ): Boolean {
    val appCtx = context.applicationContext
    synchronized(storeLock) {
      val prefs = appCtx.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      val savedVersion = prefs.getInt(KEY_CACHE_APP_VERSION, -1)
      val savedInstallTimeMs = prefs.getLong(KEY_CACHE_INSTALL_TIME_MS, -1L)
      val versionChanged = savedVersion != currentVersionCode
      val installTimeChanged =
        installUpdateTimeMs > 0L && savedInstallTimeMs != installUpdateTimeMs
      if (!versionChanged && !installTimeChanged) return false
      prefs.edit()
        .remove(KEY_VERIFIED_POOL_JSON)
        .remove(KEY_LAST_SCAN_AT_MS)
        .putInt(KEY_CACHE_APP_VERSION, currentVersionCode)
        .putLong(KEY_CACHE_INSTALL_TIME_MS, installUpdateTimeMs)
        .apply()
      appCtx
        .getSharedPreferences(PREFS_LAST_SERVER, Context.MODE_PRIVATE)
        .edit()
        .remove(KEY_SAVED_CANDIDATES_JSON)
        .apply()
      DeadServerStore.clear(appCtx)
      return true
    }
  }

  private fun readPackageLastUpdateTimeMs(context: Context): Long {
    return try {
      val appCtx = context.applicationContext
      @Suppress("DEPRECATION")
      val pkgInfo = appCtx.packageManager.getPackageInfo(appCtx.packageName, 0)
      pkgInfo.lastUpdateTime
    } catch (_: Throwable) {
      0L
    }
  }

  private fun loadRawEntries(context: Context): List<StoredServerEntry> {
    val raw =
      context
        .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        .getString(KEY_VERIFIED_POOL_JSON, null)
        ?: return emptyList()
    return try {
      val arr = JSONArray(raw)
      val out = ArrayList<StoredServerEntry>(arr.length())
      for (i in 0 until arr.length()) {
        val obj = arr.optJSONObject(i) ?: continue
        val rawUri = obj.optString("rawUri", "")
        val parsed = V2RayConfigParser.parseSingleUri(rawUri) ?: continue
        val resolvedIp = obj.optString("resolvedIp", "")
        val fragmentProfile = obj.optString("fragmentProfile", parsed.fragmentProfile)
        val cipherSuites = obj.optString("cipherSuites", parsed.cipherSuites)
        val latencyMs = obj.optLong("latencyMs", parsed.latencyMs).coerceAtLeast(1L)
        val speedScore = obj.optDouble("speedScore", parsed.speedScore)
        val testedAtMs = obj.optLong("testedAtMs", 0L)
        if (testedAtMs <= 0L) continue
        out.add(
          StoredServerEntry(
            config =
              parsed.copy(
                resolvedIp = resolvedIp,
                fragmentProfile = fragmentProfile.ifBlank { parsed.fragmentProfile },
                cipherSuites = cipherSuites.ifBlank { parsed.cipherSuites },
                latencyMs = latencyMs,
                speedScore = speedScore,
              ),
            testedAtMs = testedAtMs,
          )
        )
      }
      out
    } catch (_: Throwable) {
      emptyList()
    }
  }

  private fun saveRawEntries(context: Context, entries: List<StoredServerEntry>) {
    val arr = JSONArray()
    for (entry in entries) {
      val cfg = entry.config
      val obj =
        JSONObject().apply {
          put("rawUri", cfg.rawUri)
          put("resolvedIp", cfg.resolvedIp)
          put("fragmentProfile", cfg.fragmentProfile)
          put("cipherSuites", cfg.cipherSuites)
          put("latencyMs", cfg.latencyMs)
          put("speedScore", cfg.speedScore)
          put("testedAtMs", entry.testedAtMs)
        }
      arr.put(obj)
    }
    context
      .getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
      .edit()
      .putString(KEY_VERIFIED_POOL_JSON, arr.toString())
      .apply()
  }
}
