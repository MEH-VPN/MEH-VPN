package com.example.vpn

import android.content.Context
import android.net.TrafficStats
import android.os.Build
import com.example.BuildConfig
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.amnezia.awg.hevtunnel.TProxyService

enum class FullLogCategory(val tag: String, val persianLabel: String) {
  SYSTEM("SYS", "سیستم"),
  CALIBRATION("CAL", "بهینه‌سازی"),
  NETWORK("NET", "شبکه"),
  SERVER("SRV", "سرور"),
  XRAY("XRAY", "Xray"),
  TUNNEL("TUN", "تونل"),
  DNS("DNS", "DNS"),
  PROBE("PROBE", "تست مسیر"),
  ERROR("ERR", "خطا"),
}

data class FullLogEntry(
  val id: Long,
  val timestampMs: Long,
  val timeFormatted: String,
  val category: FullLogCategory,
  val message: String,
  val isError: Boolean = category == FullLogCategory.ERROR,
)

/**
 * Unfiltered, chronological diagnostic logger that captures every technical event across
 * calibration, network interfaces, Private DNS, server discovery, Xray core startup/config,
 * TUN / `hev-socks5-tunnel`, DNS probes, keep-alive ticks, failover/rollback, and exceptions.
 *
 * Designed so users on problematic devices (e.g., Samsung Galaxy S8 / Android 9 / MCI) can view
 * every detail live or copy a single complete diagnostic report for exact root-cause debugging.
 */
object MehFullLogger {

  private const val MAX_ENTRIES = 1200

  private val idGen = AtomicLong(1L)
  private val lock = Any()
  private val buffer = ArrayDeque<FullLogEntry>(MAX_ENTRIES)
  private val _entries = MutableStateFlow<List<FullLogEntry>>(emptyList())
  val entries: StateFlow<List<FullLogEntry>> = _entries.asStateFlow()

  private val timeFormat =
    object : ThreadLocal<SimpleDateFormat>() {
      override fun initialValue(): SimpleDateFormat =
        SimpleDateFormat("HH:mm:ss.SSS", Locale.US)
    }

  fun log(
    category: FullLogCategory,
    message: String,
    isError: Boolean = category == FullLogCategory.ERROR,
  ) {
    val clean = message.trim()
    if (clean.isEmpty()) return
    val now = System.currentTimeMillis()
    val formatted =
      try {
        timeFormat.get()?.format(Date(now)) ?: now.toString()
      } catch (_: Throwable) {
        now.toString()
      }
    val entry =
      FullLogEntry(
        id = idGen.getAndIncrement(),
        timestampMs = now,
        timeFormatted = formatted,
        category = category,
        message = clean,
        isError = isError,
      )
    synchronized(lock) {
      if (buffer.size >= MAX_ENTRIES) {
        buffer.removeFirst()
      }
      buffer.addLast(entry)
      _entries.value = buffer.toList()
    }
  }

  fun logError(category: FullLogCategory, message: String, throwable: Throwable? = null) {
    val detail =
      if (throwable != null) {
        "$message | ${throwable.javaClass.simpleName}: ${throwable.message ?: "no message"}"
      } else {
        message
      }
    log(category = category, message = detail, isError = true)
  }

  fun clear() {
    synchronized(lock) {
      buffer.clear()
      _entries.value = emptyList()
    }
  }

  fun snapshotEntries(): List<FullLogEntry> = synchronized(lock) { buffer.toList() }

  /** Safely reads native `hev-socks5-tunnel` TX/RX packet & byte stats if exposed by the AAR. */
  fun readHevTunnelStatsSummary(): String {
    return try {
      val method = TProxyService::class.java.getDeclaredMethod("TProxyGetStats")
      val stats = method.invoke(null) as? LongArray
      if (stats != null && stats.size >= 4) {
        "txPkts=${stats[0]}, txBytes=${stats[1]}, rxPkts=${stats[2]}, rxBytes=${stats[3]}"
      } else {
        "unavailable"
      }
    } catch (_: Throwable) {
      "not_exposed"
    }
  }

  /**
   * Captures a live system/TUN/stats snapshot line into the log stream (used when user taps
   * Refresh in the full log viewer or right after VPN establishment).
   */
  fun recordLiveTelemetrySnapshot(context: Context, reason: String = "manual") {
    val appCtx = context.applicationContext
    val cal = DeviceTunnelCalibrator.inspectDeviceAndNetwork(appCtx)
    val selectedMode = DeviceTunnelCalibrator.getSelectedMode(appCtx)
    val effective = DeviceTunnelCalibrator.resolveEffectiveProfile(appCtx)
    val session = MehVpnService.tunnelSession.value
    val hevStats = readHevTunnelStatsSummary()
    val totalRx = runCatching { TrafficStats.getTotalRxBytes() }.getOrDefault(-1L)
    val totalTx = runCatching { TrafficStats.getTotalTxBytes() }.getOrDefault(-1L)
    log(
      FullLogCategory.SYSTEM,
      "SNAPSHOT($reason) | mode=${selectedMode.id} -> effective=${effective.id} | " +
        "running=${session.isRunning} srv=${session.serverName} proto=${session.protocolLabel} " +
        "ping=${session.currentPingMs}ms socksPort=${session.localProxyPort} | " +
        "xrayRunning=${NativeXrayEngine.isRunning()} | hevStats=[$hevStats] | " +
        "net=${cal.transportLabel} cgnat100=${cal.hasCgnat100Interface} " +
        "privateDns=${cal.privateDnsModeRaw}(${cal.privateDnsHostname ?: "-"}) | " +
        "deviceRx=$totalRx deviceTx=$totalTx",
    )
  }

  /**
   * Builds a single complete, copy-paste-ready diagnostic report containing device/OS metadata,
   * calibration state, network interfaces, Private DNS raw settings, active `hev_socks5_tunnel.yml`,
   * redacted Xray config summary, `MehDiag` counters, and every single timestamped log line.
   */
  fun exportFullDiagnosticReport(context: Context): String {
    val appCtx = context.applicationContext
    val sb = StringBuilder(8192)
    val cal = DeviceTunnelCalibrator.inspectDeviceAndNetwork(appCtx)
    val selectedMode = DeviceTunnelCalibrator.getSelectedMode(appCtx)
    val effective = DeviceTunnelCalibrator.resolveEffectiveProfile(appCtx)
    val session = MehVpnService.tunnelSession.value

    sb.appendLine("================ MEH VPN FULL DIAGNOSTIC REPORT ================")
    sb.appendLine("App: ${BuildConfig.VERSION_NAME} (code=${BuildConfig.VERSION_CODE})")
    sb.appendLine("Device: ${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})")
    sb.appendLine("Android: ${Build.VERSION.RELEASE} (SDK ${Build.VERSION.SDK_INT}) | ABIs: ${Build.SUPPORTED_ABIS.joinToString(",")}")
    sb.appendLine("Xray Core: ${NativeXrayEngine.xrayVersion()} | running=${NativeXrayEngine.isRunning()}")
    sb.appendLine("Tunnel Mode Setting: ${selectedMode.id} -> Effective Profile: ${effective.id} (${effective.titleFa})")
    sb.appendLine("Calibration Reason: ${cal.recommendationReasonEn}")
    sb.appendLine("Active Session: running=${session.isRunning}, server=${session.serverName}, addr=${session.serverAddress}:${session.serverPort}, proto=${session.protocolLabel}, ping=${session.currentPingMs}ms, socksPort=${session.localProxyPort}, err=${session.errorMessage ?: "none"}")
    sb.appendLine("Network: transport=${cal.transportLabel}, metered=${cal.isMetered}, cgnat100=${cal.hasCgnat100Interface}, carrier10=${cal.hasCarrier10Interface}")
    sb.appendLine("Interfaces IPv4: ${cal.interfaceAddresses.ifEmpty { listOf("none") }.joinToString(", ")}")
    sb.appendLine("Link DNS Servers: ${cal.linkDnsServers.ifEmpty { listOf("none") }.joinToString(", ")}")
    sb.appendLine("Private DNS: globalMode=${cal.privateDnsModeRaw}, globalSpec=${cal.privateDnsHostname ?: "none"}, linkActive=${cal.linkPrivateDnsActive}, linkHost=${cal.linkPrivateDnsServerName ?: "none"}")
    sb.appendLine("Hev Tunnel Stats: ${readHevTunnelStatsSummary()}")
    sb.appendLine("MehDiag: ${MehDiag.formatCompactSummary()}")

    val hevFile = File(appCtx.filesDir, "hev_socks5_tunnel.yml")
    if (hevFile.exists()) {
      sb.appendLine("---------------- hev_socks5_tunnel.yml ----------------")
      sb.appendLine(runCatching { hevFile.readText().trim() }.getOrDefault("<read error>"))
    } else {
      sb.appendLine("---------------- hev_socks5_tunnel.yml: (not created) ----------------")
    }

    val xrayFile = File(appCtx.filesDir, "active_v2ray_config.json")
    if (xrayFile.exists()) {
      sb.appendLine("---------------- active_v2ray_config.json (redacted) ----------------")
      val raw = runCatching { xrayFile.readText() }.getOrDefault("<read error>")
      sb.appendLine(redactSecrets(raw).trim())
    }

    val allLogs = snapshotEntries()
    sb.appendLine("---------------- CHRONOLOGICAL LOGS (${allLogs.size} lines) ----------------")
    for (entry in allLogs) {
      val mark = if (entry.isError) "!" else " "
      sb.appendLine("[${entry.timeFormatted}][$mark${entry.category.tag}] ${entry.message}")
    }
    sb.appendLine("================ END OF REPORT ================")
    return sb.toString()
  }

  internal fun redactSecrets(rawJson: String): String {
    return rawJson
      .replace(Regex(""""(id|password|secretKey|auth|pass)"\s*:\s*"[^"]*""""), """"$1": "***"""")
  }
}
