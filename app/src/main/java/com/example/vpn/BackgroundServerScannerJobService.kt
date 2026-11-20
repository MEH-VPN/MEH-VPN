package com.example.vpn

import android.app.job.JobInfo
import android.app.job.JobParameters
import android.app.job.JobScheduler
import android.app.job.JobService
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.BatteryManager
import android.os.Build
import android.os.PowerManager
import android.util.Log
import com.example.data.DeadServerStore
import com.example.data.SoliSpiritRepository
import com.example.data.VerifiedServerPoolStore
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

/** Resource budget for one ultra-gentle background server discovery run. */
data class GentleScanLimits(
  val sourcesPerBatch: Int,
  val maxConfigsToProbe: Int,
  val stage1Concurrency: Int,
  val stage2Concurrency: Int,
  val maxResultCount: Int,
  val hardTimeoutMs: Long,
)

enum class GentleScanDecision {
  RUN,
  SKIP_POWER_SAVE_MODE,
  SKIP_LOW_BATTERY,
  SKIP_FOREGROUND_BUSY,
  SKIP_COOLDOWN,
}

/**
 * Pure, deterministic policy controlling when and how gently the background scanner runs so the
 * user never feels CPU spikes, battery drain, or mobile data waste.
 */
object GentleScanPolicy {
  const val LOW_BATTERY_THRESHOLD_PERCENT = 15
  const val NORMAL_COOLDOWN_MS = 10L * 60L * 1000L
  const val WARMUP_COOLDOWN_MS = 2L * 60L * 1000L
  const val WARMUP_MIN_FRESH_SERVERS = 4

  fun shouldRunGentleScan(
    isPowerSaveMode: Boolean,
    batteryPercent: Int,
    isCharging: Boolean,
    isForegroundConnectBusy: Boolean,
    lastScanAtMs: Long,
    nowMs: Long,
    cachedFreshCount: Int,
  ): GentleScanDecision {
    if (isPowerSaveMode) return GentleScanDecision.SKIP_POWER_SAVE_MODE
    if (!isCharging && batteryPercent in 0..LOW_BATTERY_THRESHOLD_PERCENT) {
      return GentleScanDecision.SKIP_LOW_BATTERY
    }
    if (isForegroundConnectBusy) return GentleScanDecision.SKIP_FOREGROUND_BUSY
    val requiredCooldown =
      if (cachedFreshCount < WARMUP_MIN_FRESH_SERVERS) {
        WARMUP_COOLDOWN_MS
      } else {
        NORMAL_COOLDOWN_MS
      }
    if (lastScanAtMs > 0L && (nowMs - lastScanAtMs) in 0L until requiredCooldown) {
      return GentleScanDecision.SKIP_COOLDOWN
    }
    return GentleScanDecision.RUN
  }

  fun computeLimits(isMetered: Boolean): GentleScanLimits {
    return if (isMetered) {
      GentleScanLimits(
        sourcesPerBatch = 1,
        maxConfigsToProbe = 18,
        stage1Concurrency = 2,
        stage2Concurrency = 1,
        maxResultCount = 4,
        hardTimeoutMs = 14_000L,
      )
    } else {
      GentleScanLimits(
        sourcesPerBatch = 2,
        maxConfigsToProbe = 36,
        stage1Concurrency = 4,
        stage2Concurrency = 2,
        maxResultCount = 6,
        hardTimeoutMs = 18_000L,
      )
    }
  }
}

/**
 * Schedules the OS-managed periodic and warm-up background server discovery jobs via Android's
 * built-in [JobScheduler] (API 21+, zero extra dependencies, zero persistent notification,
 * Doze/Battery-Saver compliant, works whether connected, disconnected, or after app exit/reboot).
 */
object BackgroundServerScanScheduler {
  const val PERIODIC_JOB_ID = 41021
  const val WARMUP_JOB_ID = 41022

  /** OS minimum periodic interval (15 min) with a 5 min flex window on API 24+. */
  const val PERIODIC_INTERVAL_MS = 15L * 60L * 1000L
  const val PERIODIC_FLEX_MS = 5L * 60L * 1000L
  const val WARMUP_MIN_LATENCY_MS = 30_000L
  const val WARMUP_DEADLINE_MS = 4L * 60L * 1000L

  /**
   * Ensures the gentle periodic background scanner is registered without resetting an already
   * pending schedule. Safe to call from `MainActivity.onCreate`, `MehVpnService.onCreate`, and
   * disconnect handlers.
   */
  fun ensurePeriodicScheduled(context: Context): Boolean {
    val appCtx = context.applicationContext
    val scheduler = appCtx.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return false

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      if (scheduler.getPendingJob(PERIODIC_JOB_ID) != null) {
        return true
      }
    } else {
      val alreadyScheduled = scheduler.allPendingJobs.any { it.id == PERIODIC_JOB_ID }
      if (alreadyScheduled) return true
    }

    val component = ComponentName(appCtx, BackgroundServerScannerJobService::class.java)
    val jobInfo = buildPeriodicJobInfo(component, persisted = true)
    return try {
      scheduler.schedule(jobInfo) == JobScheduler.RESULT_SUCCESS
    } catch (_: Throwable) {
      // Fallback if device/OEM blocks persisted jobs despite RECEIVE_BOOT_COMPLETED
      try {
        scheduler.schedule(buildPeriodicJobInfo(component, persisted = false)) == JobScheduler.RESULT_SUCCESS
      } catch (_: Throwable) {
        false
      }
    }
  }

  /**
   * Schedules a lightweight one-shot warm-up scan (~30s later) when the fresh pool has fewer than
   * [GentleScanPolicy.WARMUP_MIN_FRESH_SERVERS] servers so the user's next connect or server switch
   * already has fast servers ready.
   */
  fun scheduleWarmupIfNeeded(context: Context): Boolean {
    val appCtx = context.applicationContext
    val freshCount = VerifiedServerPoolStore.getFastestFresh(appCtx).size
    if (freshCount >= GentleScanPolicy.WARMUP_MIN_FRESH_SERVERS) return false

    val scheduler = appCtx.getSystemService(Context.JOB_SCHEDULER_SERVICE) as? JobScheduler ?: return false
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N && scheduler.getPendingJob(WARMUP_JOB_ID) != null) {
      return true
    }

    val component = ComponentName(appCtx, BackgroundServerScannerJobService::class.java)
    val builder =
      JobInfo.Builder(WARMUP_JOB_ID, component)
        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
        .setMinimumLatency(WARMUP_MIN_LATENCY_MS)
        .setOverrideDeadline(WARMUP_DEADLINE_MS)
        .setBackoffCriteria(60_000L, JobInfo.BACKOFF_POLICY_EXPONENTIAL)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      builder.setRequiresBatteryNotLow(true)
    }
    return try {
      scheduler.schedule(builder.build()) == JobScheduler.RESULT_SUCCESS
    } catch (_: Throwable) {
      false
    }
  }

  private fun buildPeriodicJobInfo(component: ComponentName, persisted: Boolean): JobInfo {
    val builder =
      JobInfo.Builder(PERIODIC_JOB_ID, component)
        .setRequiredNetworkType(JobInfo.NETWORK_TYPE_ANY)
        .setPersisted(persisted)
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      builder.setPeriodic(PERIODIC_INTERVAL_MS, PERIODIC_FLEX_MS)
    } else {
      builder.setPeriodic(PERIODIC_INTERVAL_MS)
    }
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      builder.setRequiresBatteryNotLow(true)
    }
    return builder.build()
  }
}

/**
 * Silent, ultra-lightweight [JobService] that keeps [VerifiedServerPoolStore] stocked with fresh,
 * verified low-latency V2Ray servers whether the user is connected, disconnected, or has closed
 * the app.
 *
 * When [MehVpnService] is active, the app package is disallowed from the TUN interface, so probes
 * opened by this JobService naturally test the real physical network without disrupting the live
 * VPN tunnel, and newly verified servers are immediately pushed to the live standby pool via
 * [VerifiedServerPoolStore.poolUpdates].
 */
class BackgroundServerScannerJobService : JobService() {

  private val jobScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var activeScanJob: Job? = null
  private val repository by lazy { SoliSpiritRepository() }

  override fun onStartJob(params: JobParameters?): Boolean {
    if (params == null) return false
    if (!scanInProgress.compareAndSet(false, true)) {
      return false
    }

    val nowMs = System.currentTimeMillis()
    val appCtx = applicationContext
    VerifiedServerPoolStore.resetCachesIfAppUpdated(appCtx, com.example.BuildConfig.VERSION_CODE)
    val (batteryPercent, isCharging) = readBatteryState(appCtx)
    val powerSaveMode = isDeviceInPowerSaveMode(appCtx)
    val lastScanAt = VerifiedServerPoolStore.getLastScanAtMs(appCtx)
    val freshCount = VerifiedServerPoolStore.getFastestFresh(appCtx, nowMs = nowMs).size

    val decision =
      GentleScanPolicy.shouldRunGentleScan(
        isPowerSaveMode = powerSaveMode,
        batteryPercent = batteryPercent,
        isCharging = isCharging,
        isForegroundConnectBusy = foregroundConnectBusy.get(),
        lastScanAtMs = lastScanAt,
        nowMs = nowMs,
        cachedFreshCount = freshCount,
      )

    if (decision != GentleScanDecision.RUN) {
      scanInProgress.set(false)
      Log.d(TAG, "Skipping gentle background scan: $decision")
      return false
    }

    activeScanJob?.cancel()
    activeScanJob =
      jobScope.launch {
        try {
          val metered = isActiveNetworkMetered(appCtx)
          val limits = GentleScanPolicy.computeLimits(metered)
          runGentleScanBatch(appCtx, limits)
        } catch (ce: CancellationException) {
          throw ce
        } catch (t: Throwable) {
          Log.w(TAG, "Gentle background scan failed: ${t.javaClass.simpleName}")
        } finally {
          scanInProgress.set(false)
          jobFinished(params, false)
        }
      }
    return true
  }

  override fun onStopJob(params: JobParameters?): Boolean {
    activeScanJob?.cancel()
    activeScanJob = null
    scanInProgress.set(false)
    // Do not request immediate reschedule on preemption; wait for the next OS-managed window.
    return false
  }

  override fun onDestroy() {
    activeScanJob?.cancel()
    scanInProgress.set(false)
    jobScope.cancel()
    super.onDestroy()
  }

  private suspend fun runGentleScanBatch(
    context: Context,
    limits: GentleScanLimits,
  ) {
    val deadKeys = DeadServerStore.deadKeys(context)
    val allBatches = SoliSpiritRepository.SOLISPIRIT_SOURCES.chunked(limits.sourcesPerBatch)
    if (allBatches.isEmpty()) return

    val batchIdx = VerifiedServerPoolStore.nextScanBatchIndex(context, allBatches.size)
    val batchSources = allBatches[batchIdx]
    val existingCached = VerifiedServerPoolStore.getFastest(context).take(3)

    withTimeoutOrNull(limits.hardTimeoutMs) {
      val fetched =
        repository.fetchBatchSupportedConfigs(
          sources = batchSources,
          excludedEndpointKeys = deadKeys,
        ).shuffled().take(limits.maxConfigsToProbe)

      if (fetched.isEmpty() && existingCached.isEmpty()) return@withTimeoutOrNull

      val verified =
        repository.testAndSelectFastestCandidates(
          configs = fetched,
          maxCount = limits.maxResultCount,
          prioritizedSavedNodes = existingCached,
          maxWaves = 1,
          concurrency = limits.stage1Concurrency,
          verifyConcurrency = limits.stage2Concurrency,
        ) { _ -> }

      if (verified.isNotEmpty()) {
        val updatedPool = VerifiedServerPoolStore.upsertVerified(context, verified)
        Log.i(
          TAG,
          "Gentle background scan found ${verified.size} server(s); pool size=${updatedPool.size}, fastest=${updatedPool.firstOrNull()?.latencyMs}ms",
        )
      }
    }

    VerifiedServerPoolStore.markScanCompleted(context)
  }

  private fun isDeviceInPowerSaveMode(context: Context): Boolean {
    return try {
      val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
      pm?.isPowerSaveMode == true
    } catch (_: Throwable) {
      false
    }
  }

  private fun isActiveNetworkMetered(context: Context): Boolean {
    return try {
      val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
      cm?.isActiveNetworkMetered == true
    } catch (_: Throwable) {
      false
    }
  }

  private fun readBatteryState(context: Context): Pair<Int, Boolean> {
    return try {
      val intent = context.registerReceiver(null, IntentFilter(Intent.ACTION_BATTERY_CHANGED))
      val level = intent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
      val scale = intent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
      val status = intent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
      val percent =
        if (level >= 0 && scale > 0) ((level * 100) / scale).coerceIn(0, 100) else 100
      val charging =
        status == BatteryManager.BATTERY_STATUS_CHARGING ||
          status == BatteryManager.BATTERY_STATUS_FULL
      percent to charging
    } catch (_: Throwable) {
      100 to false
    }
  }

  companion object {
    private const val TAG = "MehBgScanner"
    private val scanInProgress = AtomicBoolean(false)
    private val foregroundConnectBusy = AtomicBoolean(false)

    fun setForegroundConnectBusy(busy: Boolean) {
      foregroundConnectBusy.set(busy)
    }

    fun isForegroundConnectBusy(): Boolean = foregroundConnectBusy.get()
  }
}
