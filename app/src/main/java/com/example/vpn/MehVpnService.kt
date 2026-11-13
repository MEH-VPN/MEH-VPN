package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.TrafficStats
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.BuildConfig
import com.example.MainActivity
import com.example.R
import com.example.data.DeadServerStore
import com.example.data.SoliSpiritRepository
import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import com.example.telemetry.MehTelemetry
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

enum class VpnLogLevel {
  SYSTEM,
  SOURCE,
  SCAN,
  SUCCESS,
  ERROR,
}

data class VpnRealtimeLog(
  val message: String,
  val level: VpnLogLevel = VpnLogLevel.SYSTEM,
)

data class VpnTunnelSession(
  val isRunning: Boolean = false,
  val serverName: String = "",
  val serverAddress: String = "",
  val serverPort: Int = 0,
  val protocolLabel: String = "",
  val currentPingMs: Long = 0L,
  val localProxyPort: Int = 0,
  val errorMessage: String? = null,
)

class MehVpnService : VpnService() {

  private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var vpnInterface: ParcelFileDescriptor? = null
  private val poolLock = Any()
  @Volatile private var serverPool: List<V2RayConfig> = emptyList()
  private val poolCursor = AtomicInteger(0)
  @Volatile private var activeConfigState: V2RayConfig? = null
  @Volatile private var localSocksPort: Int = 0
  @Volatile private var nativeCoreStarted: Boolean = false

  private var connectJob: Job? = null
  private var keepAliveJob: Job? = null
  private var refineJob: Job? = null
  private var topUpPoolJob: Job? = null

  private val nodeRepository by lazy { SoliSpiritRepository() }
  @Volatile private var refineBatchIndex: Int = 0
  private val allSubBatches by lazy { SoliSpiritRepository.SOLISPIRIT_SOURCES.chunked(4) }

  @Volatile private var underlyingPhysicalNetwork: Network? = null
  private var networkCallback: ConnectivityManager.NetworkCallback? = null

  override fun onCreate() {
    super.onCreate()
    MehTelemetry.initialize(this)
    registerPhysicalNetworkTracker()
  }

  private fun registerPhysicalNetworkTracker() {
    try {
      val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
      val requestBuilder =
        NetworkRequest.Builder()
          .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
          .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
      val callback =
        object : ConnectivityManager.NetworkCallback() {
          override fun onAvailable(network: Network) {
            underlyingPhysicalNetwork = network
          }

          override fun onLost(network: Network) {
            if (underlyingPhysicalNetwork == network) {
              underlyingPhysicalNetwork = null
            }
          }
        }
      cm.registerNetworkCallback(requestBuilder.build(), callback)
      networkCallback = callback
    } catch (_: Exception) {}
  }

  private fun unregisterPhysicalNetworkTracker() {
    try {
      val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
      val cb = networkCallback
      if (cm != null && cb != null) {
        cm.unregisterNetworkCallback(cb)
      }
    } catch (_: Exception) {}
    networkCallback = null
  }

  private fun protectOutboundSocket(socket: Socket): Boolean {
    return try {
      protect(socket)
    } catch (_: Exception) {
      false
    }
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_SWITCH_SERVER -> {
        handleManualSwitchServer()
        return START_STICKY
      }
      ACTION_DISCONNECT -> {
        stopTunnel()
        return START_NOT_STICKY
      }
      ACTION_CONNECT -> {
        val rawUri = intent.getStringExtra(EXTRA_RAW_URI).orEmpty()
        val resolvedIp = intent.getStringExtra(EXTRA_RESOLVED_IP).orEmpty()
        val primaryProfile = intent.getStringExtra(EXTRA_FRAGMENT_PROFILE).orEmpty()
        val primaryCiphers = intent.getStringExtra(EXTRA_CIPHER_SUITES).orEmpty()
        val candidateUris = intent.getStringArrayListExtra(EXTRA_CANDIDATE_URIS).orEmpty()
        val candidateIps = intent.getStringArrayListExtra(EXTRA_CANDIDATE_IPS).orEmpty()
        val candidateProfiles = intent.getStringArrayListExtra(EXTRA_CANDIDATE_PROFILES).orEmpty()
        val candidateCiphers = intent.getStringArrayListExtra(EXTRA_CANDIDATE_CIPHERS).orEmpty()

        val parsedPrimary = V2RayConfigParser.parseSingleUri(rawUri)
        val serverName =
          intent.getStringExtra(EXTRA_SERVER_NAME) ?: parsedPrimary?.cleanTitle ?: "V2Ray Server"
        val initialPing = intent.getLongExtra(EXTRA_INITIAL_PING, 80L)

        if (parsedPrimary == null) {
          stopTunnel("کانفیگ سرور نامعتبر است")
          return START_NOT_STICKY
        }

        val candidateConfigs = mutableListOf<V2RayConfig>()
        candidateConfigs.add(
          parsedPrimary.copy(
            resolvedIp = resolvedIp,
            latencyMs = initialPing,
            fragmentProfile = primaryProfile.ifBlank { parsedPrimary.fragmentProfile },
            cipherSuites = primaryCiphers.ifBlank { parsedPrimary.cipherSuites },
          )
        )
        for (i in candidateUris.indices) {
          val uri = candidateUris[i]
          val ip = candidateIps.getOrNull(i).orEmpty()
          val prof = candidateProfiles.getOrNull(i).orEmpty()
          val ciph = candidateCiphers.getOrNull(i).orEmpty()
          val cfg = V2RayConfigParser.parseSingleUri(uri)
          if (cfg != null) {
            val withProfile =
              cfg.copy(
                resolvedIp = ip,
                fragmentProfile = prof.ifBlank { cfg.fragmentProfile },
                cipherSuites = ciph.ifBlank { cfg.cipherSuites },
              )
            if (candidateConfigs.none { it.endpointKey == withProfile.endpointKey }) {
              candidateConfigs.add(withProfile)
            }
          }
        }

        createNotificationChannel()
        val notification = buildForegroundNotification(serverName, initialPing)
        startForeground(NOTIFICATION_ID, notification)

        connectJob?.cancel()
        connectJob =
          serviceScope.launch {
            startTunnelAsync(
              configs = candidateConfigs,
              serverName = serverName,
              initialPing = initialPing,
            )
          }
        return START_STICKY
      }
      else -> return START_NOT_STICKY
    }
  }

  private fun startTunnelAsync(
    configs: List<V2RayConfig>,
    serverName: String,
    initialPing: Long,
  ) {
    try {
      stopNativeXray()
      try {
        vpnInterface?.close()
      } catch (_: Exception) {}
      vpnInterface = null

      val effectiveConfigs =
        configs.map { cfg ->
          val ip =
            cfg.resolvedIp.ifBlank {
              V2RayOutboundClient.resolveEndpointIpv4(cfg.address).orEmpty()
            }
          cfg.copy(resolvedIp = ip)
        }

      synchronized(poolLock) {
        serverPool = effectiveConfigs
        poolCursor.set(0)
      }

      // Establish full-device Android TUN interface (0.0.0.0/0 and ::/0) excluding our own app.
      val builder =
        Builder()
          .setSession("MEH • $serverName")
          .setMtu(TUN_MTU)
          .addAddress("10.10.14.2", 24)
          .addRoute("0.0.0.0", 0)
          .addDnsServer("8.8.8.8")
          .addDnsServer("1.1.1.1")

      try {
        builder.addAddress("fd00::10:10:14:2", 64)
        builder.addRoute("::", 0)
      } catch (_: Exception) {}

      try {
        builder.addDisallowedApplication(packageName)
      } catch (_: Exception) {}

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
      }

      val establishedPfd =
        builder.establish() ?: throw IllegalStateException("TUN establish returned null")
      vpnInterface = establishedPfd

      // Try candidates in order with native Xray-core (libXray) until one boots cleanly
      var startedConfig: V2RayConfig? = null
      var lastError: String? = null
      for (idx in effectiveConfigs.indices) {
        val candidate = effectiveConfigs[idx]
        if (!NativeXrayEngine.supportsNativeXray(candidate)) continue
        val startErr = launchNativeXrayOnExistingTun(establishedPfd, candidate)
        if (startErr == null) {
          startedConfig = candidate
          synchronized(poolLock) { poolCursor.set(idx) }
          break
        } else {
          lastError = startErr
          DeadServerStore.markDead(applicationContext, candidate.endpointKey)
        }
      }

      val active =
        startedConfig
          ?: throw IllegalStateException(lastError ?: "Native Xray core failed to start")

      val effectiveName = active.cleanTitle.ifBlank { serverName }
      val effectivePing = if (active.latencyMs > 0L) active.latencyMs else initialPing

      _tunnelSession.value =
        VpnTunnelSession(
          isRunning = true,
          serverName = effectiveName,
          serverAddress = active.address,
          serverPort = active.port,
          protocolLabel = active.protocol.label,
          currentPingMs = effectivePing,
          localProxyPort = localSocksPort,
          errorMessage = null,
        )

      emitRealtimeLog(
        "متصل به $effectiveName (${active.protocol.label} • پینگ ${effectivePing}ms)",
        VpnLogLevel.SUCCESS,
      )

      startProtectedKeepAliveProbe(effectiveName, effectivePing)
      verifyActiveNodeAfterConnect()
      startBackgroundNodeRefinement()
      startPoolTopUpAfterConnect()
    } catch (e: Exception) {
      MehTelemetry.logError(
        stage = "vpn_tunnel_establish",
        errorMessage = e.localizedMessage ?: "Failed to establish native Xray tunnel",
        throwable = e,
      )
      stopTunnel("خطا در راه‌اندازی هسته Xray:\n${e.localizedMessage ?: "نامشخص"}")
    }
  }

  /**
   * Starts (or hot-restarts) native Go Xray-core on the already-open [establishedPfd] TUN
   * using a freshly duped+detached FD so Android `fdsan` never aborts when Xray closes it on stop.
   * Returns `null` on success, or an error description on failure.
   */
  private fun launchNativeXrayOnExistingTun(
    establishedPfd: ParcelFileDescriptor,
    config: V2RayConfig,
  ): String? {
    val resolvedConfig =
      if (config.resolvedIp.isNotBlank()) {
        config
      } else {
        val ip = V2RayOutboundClient.resolveEndpointIpv4(config.address).orEmpty()
        config.copy(resolvedIp = ip)
      }

    val socksPort = NativeXrayEngine.allocateLocalPort()
    val xrayJson =
      GfwKnockerXrayCore.buildXrayCoreJson(
        config = resolvedConfig,
        includeTunInbound = true,
        tunMtu = TUN_MTU,
        localSocksPort = socksPort,
      )
    try {
      File(filesDir, "active_v2ray_config.json").writeText(xrayJson)
    } catch (_: Exception) {}

    val tunFd =
      try {
        ParcelFileDescriptor.dup(establishedPfd.fileDescriptor)?.detachFd() ?: establishedPfd.fd
      } catch (_: Exception) {
        establishedPfd.fd
      }

    val result =
      NativeXrayEngine.startTunnel(
        datDir = filesDir.absolutePath,
        tunFd = tunFd,
        configJson = xrayJson,
        protectFd = { fd ->
          try {
            protect(fd)
          } catch (_: Throwable) {
            false
          }
        },
      )

    return if (result.success) {
      nativeCoreStarted = true
      activeConfigState = resolvedConfig
      localSocksPort = socksPort
      null
    } else {
      nativeCoreStarted = false
      result.error ?: "Failed to start Xray core"
    }
  }

  private fun stopNativeXray() {
    if (nativeCoreStarted || NativeXrayEngine.isRunning()) {
      nativeCoreStarted = false
      try {
        NativeXrayEngine.stopTunnel()
      } catch (_: Throwable) {}
    }
  }

  private fun currentActiveConfig(): V2RayConfig? =
    activeConfigState ?: synchronized(poolLock) { serverPool.firstOrNull() }

  private fun currentPoolSnapshot(): List<V2RayConfig> =
    synchronized(poolLock) { serverPool }

  private fun switchToNextHealthyNode(reason: String): V2RayConfig? {
    val pfd = vpnInterface ?: return currentActiveConfig()
    val candidate =
      synchronized(poolLock) {
        if (serverPool.isEmpty()) return currentActiveConfig()
        val nextIdx = (poolCursor.get() + 1) % serverPool.size
        poolCursor.set(nextIdx)
        serverPool[nextIdx]
      }
    val err = launchNativeXrayOnExistingTun(pfd, candidate)
    if (err == null) {
      android.util.Log.i(
        "MehVpnService",
        "Switched native Xray node ($reason) -> ${candidate.cleanTitle}",
      )
      return candidate
    }
    return currentActiveConfig()
  }

  private fun replaceServerPool(newPool: List<V2RayConfig>): V2RayConfig? {
    val clean =
      newPool
        .filter { NativeXrayEngine.supportsNativeXray(it) }
        .distinctBy { it.endpointKey }
    if (clean.isEmpty()) return currentActiveConfig()
    synchronized(poolLock) {
      serverPool = clean
      poolCursor.set(0)
    }
    val pfd = vpnInterface ?: return clean.first()
    val first = clean.first()
    launchNativeXrayOnExistingTun(pfd, first)
    return currentActiveConfig() ?: first
  }

  private fun appendToServerPool(more: List<V2RayConfig>): Int {
    if (more.isEmpty()) return currentPoolSnapshot().size
    synchronized(poolLock) {
      val merged =
        (serverPool + more.filter { NativeXrayEngine.supportsNativeXray(it) })
          .distinctBy { it.endpointKey }
      serverPool = merged
      return merged.size
    }
  }

  private fun verifyNodeCapability(config: V2RayConfig): Long? {
    val directProbe =
      V2RayOutboundClient.verifyHttpsAndDnsCapability(
        config = config,
        timeoutMs = 3500,
        protector = { socket -> protectOutboundSocket(socket) },
      )
    if (directProbe != null) return directProbe
    return NativeXrayEngine.pingConfig(
      datDir = filesDir.absolutePath,
      tempDir = cacheDir,
      config = config,
      timeoutSec = 4,
      protectFd = { fd -> protect(fd) },
    )
  }

  private fun verifyRealPathViaProxy(proxyPort: Int, timeoutMs: Int = 3500): Long? {
    if (proxyPort <= 0) return null
    val startedNs = System.nanoTime()
    var socket: Socket? = null
    return try {
      val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", proxyPort))
      socket = Socket(proxy)
      socket.soTimeout = timeoutMs
      socket.connect(InetSocketAddress.createUnresolved("www.google.com", 80), timeoutMs)
      val request = "GET /generate_204 HTTP/1.1\r\nHost: www.google.com\r\nConnection: close\r\n\r\n"
      socket.getOutputStream().write(request.toByteArray(Charsets.US_ASCII))
      socket.getOutputStream().flush()
      val statusLine = BufferedReader(InputStreamReader(socket.getInputStream(), Charsets.US_ASCII)).readLine()
      val code = statusLine?.split(" ")?.getOrNull(1)?.toIntOrNull()
      if (code == 204) {
        val ms = ((System.nanoTime() - startedNs) / 1_000_000L).coerceAtLeast(1L)
        MehDiag.recordBytesDownloaded(128L)
        ms
      } else {
        null
      }
    } catch (_: Exception) {
      null
    } finally {
      try { socket?.close() } catch (_: Exception) {}
    }
  }

  private fun verifyNodeFully(config: V2RayConfig, proxyPort: Int): Long? {
    val directPing = verifyNodeCapability(config)
    val realPing = verifyRealPathViaProxy(proxyPort)
    return realPing ?: directPing
  }

  private fun failoverToNextVerifiedNode(
    failedCfg: V2RayConfig,
    reason: String,
  ): Pair<V2RayConfig, Long?> {
    var abandonedCfg = failedCfg
    val poolSize = currentPoolSnapshot().size.coerceAtLeast(1)
    var attempts = 0
    while (attempts < poolSize) {
      val nextCfg = switchToNextHealthyNode(reason) ?: break
      attempts++
      if (nextCfg.endpointKey == abandonedCfg.endpointKey) break
      DeadServerStore.markDead(applicationContext, abandonedCfg.endpointKey)
      val ping = verifyRealPathViaProxy(localSocksPort)
      if (ping != null) {
        return nextCfg to ping
      }
      abandonedCfg = nextCfg
    }
    return (currentActiveConfig() ?: failedCfg) to null
  }

  private fun handleManualSwitchServer() {
    val beforeCfg = currentActiveConfig() ?: return
    val poolSize = currentPoolSnapshot().size
    if (poolSize <= 1) {
      serviceScope.launch {
        val found =
          try {
            refineNodesOnce(force = true)
          } catch (_: Exception) {
            false
          }
        if (found) {
          currentActiveConfig()?.let { freshCfg ->
            updateSessionAndNotification(freshCfg, freshCfg.latencyMs.coerceAtLeast(1L))
          }
        }
      }
      return
    }

    val switchedCfg = switchToNextHealthyNode("manual") ?: return
    emitRealtimeLog("تعویض دستی به سرور: ${switchedCfg.cleanTitle}", VpnLogLevel.SYSTEM)
    updateSessionAndNotification(switchedCfg, switchedCfg.latencyMs.coerceAtLeast(1L))
    serviceScope.launch {
      var candidate = switchedCfg
      var attempts = 0
      while (attempts < 3) {
        val realPing = verifyRealPathViaProxy(localSocksPort)
        if (realPing != null) {
          emitRealtimeLog(
            "سرور جدید متصل شد: ${candidate.cleanTitle} (پینگ ${realPing}ms)",
            VpnLogLevel.SUCCESS,
          )
          updateSessionAndNotification(candidate, realPing)
          return@launch
        }
        attempts++
        if (attempts >= 3) break
        DeadServerStore.markDead(applicationContext, candidate.endpointKey)
        val nextCfg = switchToNextHealthyNode("manual_verification") ?: break
        if (nextCfg.endpointKey == candidate.endpointKey) break
        candidate = nextCfg
        updateSessionAndNotification(candidate, candidate.latencyMs.coerceAtLeast(1L))
      }
    }
  }

  private fun updateSessionAndNotification(config: V2RayConfig, pingMs: Long) {
    val name = config.cleanTitle.ifBlank { config.address }
    _tunnelSession.value =
      _tunnelSession.value.copy(
        isRunning = true,
        serverName = name,
        serverAddress = config.address,
        serverPort = config.port,
        protocolLabel = config.protocol.label,
        currentPingMs = pingMs,
        localProxyPort = localSocksPort,
        errorMessage = null,
      )
    try {
      val nm = getSystemService(NotificationManager::class.java)
      nm?.notify(NOTIFICATION_ID, buildForegroundNotification(name, pingMs))
    } catch (_: Exception) {}
  }

  private fun verifyActiveNodeAfterConnect() {
    serviceScope.launch {
      val activeCfg = currentActiveConfig() ?: return@launch
      val realPing = verifyRealPathViaProxy(localSocksPort)
      if (realPing != null) {
        updateSessionAndNotification(activeCfg, realPing)
        emitRealtimeLog(
          "اتصال تایید شد: ${activeCfg.cleanTitle} (پینگ واقعی ${realPing}ms)",
          VpnLogLevel.SUCCESS,
        )
        return@launch
      }
      var attempts = 0
      var current = activeCfg
      while (attempts < 3) {
        attempts++
        DeadServerStore.markDead(applicationContext, current.endpointKey)
        val next = switchToNextHealthyNode("post_connect_verification") ?: break
        if (next.endpointKey == current.endpointKey) break
        current = next
        val nextPing = verifyRealPathViaProxy(localSocksPort)
        if (nextPing != null) {
          updateSessionAndNotification(current, nextPing)
          emitRealtimeLog(
            "تغییر به سرور پایدارتر: ${current.cleanTitle} (پینگ ${nextPing}ms)",
            VpnLogLevel.SUCCESS,
          )
          return@launch
        }
      }
      android.util.Log.w(
        "MehVpnService",
        "Post-connect verification failed; keeping current native Xray tunnel active",
      )
    }
  }

  private fun startProtectedKeepAliveProbe(
    serverName: String,
    initialPing: Long,
  ) {
    keepAliveJob?.cancel()
    keepAliveJob =
      serviceScope.launch {
        val startedAtMs = System.currentTimeMillis()
        var lastPing = initialPing
        var tickCount = 0
        var consecutiveFailures = 0
        var lastTotalRxBytes = safeTotalRxBytes()

        if (BuildConfig.DEBUG) {
          launch {
            while (isActive) {
              delay(DIAG_LOG_INTERVAL_MS)
              android.util.Log.i("MehDiag", MehDiag.formatCompactSummary())
            }
          }
        }

        while (isActive) {
          delay(KEEP_ALIVE_INTERVAL_MS)
          tickCount++
          var activeCfg = currentActiveConfig() ?: continue

          val nowRxBytes = safeTotalRxBytes()
          if (lastTotalRxBytes >= 0L && nowRxBytes > lastTotalRxBytes + 8192L) {
            MehDiag.recordBytesDownloaded(nowRxBytes - lastTotalRxBytes)
          }
          lastTotalRxBytes = nowRxBytes

          if (MehDiag.hasRecentRealDownloadTraffic(ACTIVE_TRAFFIC_SKIP_WINDOW_MS)) {
            MehDiag.recordKeepAliveSkippedActiveTraffic()
            consecutiveFailures = 0
          } else {
            MehDiag.recordKeepAliveProbeRun()
            val realPing = verifyRealPathViaProxy(localSocksPort)
            val confirmedPing = realPing ?: verifyNodeCapability(activeCfg)
            if (confirmedPing != null) {
              lastPing = confirmedPing
              consecutiveFailures = 0
            } else {
              consecutiveFailures++
              if (consecutiveFailures >= CONSECUTIVE_PROBE_FAILURES_FOR_FAILOVER) {
                val (switchedCfg, switchedPing) =
                  failoverToNextVerifiedNode(activeCfg, "keep_alive_timeout")
                if (switchedCfg.endpointKey != activeCfg.endpointKey) {
                  activeCfg = switchedCfg
                  consecutiveFailures = 0
                  emitRealtimeLog(
                    "افت یا قطع نود قبلی؛ انتقال خودکار به ${switchedCfg.cleanTitle}" +
                      if (switchedPing != null) " (${switchedPing}ms)" else "",
                    VpnLogLevel.SYSTEM,
                  )
                  if (switchedPing != null) {
                    lastPing = switchedPing
                  } else {
                    launch {
                      try {
                        refineNodesOnce(force = true)
                      } catch (_: Exception) {}
                    }
                  }
                } else {
                  launch {
                    try {
                      refineNodesOnce(force = true)
                    } catch (_: Exception) {}
                  }
                  if (consecutiveFailures == 3) {
                    MehTelemetry.logError(
                      stage = "keep_alive_probe",
                      errorMessage = "3 consecutive keep-alive probes timed out on ${activeCfg.cleanTitle}",
                    )
                  }
                }
              }
            }
          }

          val effectiveServerName = activeCfg.cleanTitle.ifBlank { serverName }
          updateSessionAndNotification(activeCfg.copy(remarks = effectiveServerName), lastPing)

          if (tickCount % HEARTBEAT_EVERY_N_TICKS == 0) {
            val uptimeSeconds = ((System.currentTimeMillis() - startedAtMs) / 1000L).coerceAtLeast(1L)
            MehTelemetry.logActiveSessionHeartbeat(
              serverName = effectiveServerName,
              protocol = activeCfg.protocol.label,
              latencyMs = lastPing,
              uptimeSeconds = uptimeSeconds,
            )
          }
        }
      }
  }

  private fun safeTotalRxBytes(): Long {
    return try {
      TrafficStats.getTotalRxBytes()
    } catch (_: Throwable) {
      -1L
    }
  }

  private fun startBackgroundNodeRefinement() {
    refineJob?.cancel()
    refineBatchIndex = 0
    refineJob =
      serviceScope.launch {
        delay(REFINE_FIRST_DELAY_MS)
        var lastSwitchAtMs = 0L
        while (isActive) {
          var switched = false
          try {
            if (System.currentTimeMillis() - lastSwitchAtMs >= REFINE_MIN_SWITCH_GAP_MS) {
              switched = refineNodesOnce()
              if (switched) {
                lastSwitchAtMs = System.currentTimeMillis()
              }
            }
          } catch (ce: CancellationException) {
            throw ce
          } catch (t: Throwable) {
            android.util.Log.w("MehRefine", "refinement cycle failed: ${t.javaClass.simpleName}")
          }
          val activePing = _tunnelSession.value.currentPingMs
          val nextDelay =
            when {
              isPhysicalNetworkMetered() -> REFINE_INTERVAL_METERED_MS
              activePing <= 0L || activePing > 300L -> REFINE_INTERVAL_FAST_HUNT_MS
              activePing > 150L -> REFINE_INTERVAL_MODERATE_MS
              else -> REFINE_INTERVAL_MS
            }
          delay(if (switched) nextDelay.coerceAtLeast(20_000L) else nextDelay)
        }
      }
  }

  private fun startPoolTopUpAfterConnect() {
    topUpPoolJob?.cancel()
    topUpPoolJob =
      serviceScope.launch {
        delay(POOL_TOP_UP_DELAY_MS)
        val currentPool = currentPoolSnapshot()
        val needed = POOL_TOP_UP_TARGET_SIZE - currentPool.size
        if (needed <= 0) return@launch
        val deadKeys = DeadServerStore.deadKeys(applicationContext)
        val excluded = currentPool.map { it.endpointKey }.toSet() + deadKeys
        val found =
          try {
            nodeRepository.findFirstPassingFromSources(
              sources = SoliSpiritRepository.MHCFP_SOURCES + SoliSpiritRepository.FALLBACK_SOURCES,
              poolSize = needed,
              excludedEndpointKeys = excluded,
            ) { _ -> }
          } catch (ce: CancellationException) {
            throw ce
          } catch (_: Exception) {
            emptyList()
          }
        if (found.isNotEmpty()) {
          appendToServerPool(found)
        }
      }
  }

  private suspend fun refineNodesOnce(force: Boolean = false): Boolean {
    val active = currentActiveConfig() ?: return false
    val others = currentPoolSnapshot().filter { it.endpointKey != active.endpointKey }
    val deadKeys = DeadServerStore.deadKeys(applicationContext)
    val batches = allSubBatches
    if (batches.isEmpty() && others.isEmpty()) return false

    val batchIdx = if (batches.isNotEmpty()) (refineBatchIndex++ % batches.size) else 0
    val batch = batches.getOrNull(batchIdx).orEmpty()
    val sourceLabel = batch.firstOrNull()?.repoLabel ?: "ساب‌ها"
    emitRealtimeLog(
      "جستجوی سرور سریع‌تر در پس‌زمینه ($sourceLabel • دسته ${batchIdx + 1}/${batches.size.coerceAtLeast(1)}) ...",
      VpnLogLevel.SOURCE,
    )

    val batchConfigs =
      if (batch.isNotEmpty()) {
        try {
          nodeRepository.fetchBatchSupportedConfigs(
            sources = batch,
            excludedEndpointKeys = deadKeys + setOf(active.endpointKey),
          )
        } catch (ce: CancellationException) {
          throw ce
        } catch (_: Exception) {
          emptyList()
        }
      } else {
        emptyList()
      }

    val challengers = batchConfigs.filter { it.endpointKey != active.endpointKey }
    if (challengers.isEmpty() && others.isEmpty()) return false

    emitRealtimeLog(
      "تست سرعت ${challengers.size} کانفیگ جدید در پس‌زمینه ...",
      VpnLogLevel.SCAN,
    )

    val currentScored =
      nodeRepository
        .testAndSelectFastestCandidates(
          configs = listOf(active),
          maxCount = 1,
          maxWaves = 1,
          concurrency = 1,
          verifyConcurrency = 1,
        ) { _ -> }
        .firstOrNull()

    val fresh =
      nodeRepository.testAndSelectFastestCandidates(
        configs = challengers,
        maxCount = REFINE_POOL_SIZE,
        prioritizedSavedNodes = others,
        maxWaves = 2,
        concurrency = REFINE_CONCURRENCY,
        verifyConcurrency = 3,
      ) { _ -> }
    val best = fresh.firstOrNull() ?: return false
    if (best.endpointKey == active.endpointKey) return false

    val currentPing = currentScored?.latencyMs ?: _tunnelSession.value.currentPingMs.coerceAtLeast(1L)
    val isClearlyFaster =
      when {
        currentScored == null -> force || verifyRealPathViaProxy(localSocksPort) == null
        force -> true
        best.latencyMs <= (currentPing * 0.82).toLong() -> true
        best.speedScore >= currentScored.speedScore * REFINE_SCORE_FACTOR &&
          best.latencyMs <= currentScored.latencyMs * REFINE_LATENCY_TOLERANCE -> true
        else -> false
      }
    if (!isClearlyFaster) {
      if (fresh.size > 1) {
        appendToServerPool(fresh.filter { it.endpointKey != active.endpointKey })
      }
      return false
    }

    emitRealtimeLog(
      "کانفیگ سریع‌تر پیدا شد: ${best.cleanTitle} (${best.protocol.label} • پینگ ${best.latencyMs}ms)",
      VpnLogLevel.SUCCESS,
    )

    val newPool =
      (fresh.take(REFINE_POOL_SIZE - 1) +
          listOfNotNull(currentScored?.let { active }) +
          others)
        .distinctBy { it.endpointKey }
        .take(REFINE_POOL_SIZE)
    val newActive = replaceServerPool(newPool) ?: return false
    updateSessionAndNotification(newActive, best.latencyMs.coerceAtLeast(1L))
    emitRealtimeLog(
      "اتصال به سرور سریع‌تر تغییر یافت: ${newActive.cleanTitle} (${best.latencyMs}ms)",
      VpnLogLevel.SUCCESS,
    )
    return true
  }

  private fun isPhysicalNetworkMetered(): Boolean {
    return try {
      val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return false
      val network = underlyingPhysicalNetwork ?: return false
      cm.getNetworkCapabilities(network)
        ?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
    } catch (_: Exception) {
      false
    }
  }

  private fun stopTunnel(errorMsg: String? = null) {
    connectJob?.cancel()
    connectJob = null
    keepAliveJob?.cancel()
    keepAliveJob = null
    refineJob?.cancel()
    refineJob = null
    topUpPoolJob?.cancel()
    topUpPoolJob = null
    stopNativeXray()
    localSocksPort = 0
    activeConfigState = null
    try {
      vpnInterface?.close()
    } catch (_: Exception) {}
    vpnInterface = null

    _tunnelSession.value =
      VpnTunnelSession(
        isRunning = false,
        errorMessage = errorMsg,
      )

    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
      stopForeground(STOP_FOREGROUND_REMOVE)
    } else {
      @Suppress("DEPRECATION")
      stopForeground(true)
    }
    stopSelf()
  }

  override fun onRevoke() {
    stopTunnel()
    super.onRevoke()
  }

  override fun onDestroy() {
    connectJob?.cancel()
    keepAliveJob?.cancel()
    refineJob?.cancel()
    topUpPoolJob?.cancel()
    stopNativeXray()
    try {
      vpnInterface?.close()
    } catch (_: Exception) {}
    vpnInterface = null
    unregisterPhysicalNetworkTracker()
    _tunnelSession.value = VpnTunnelSession(isRunning = false)
    serviceScope.cancel()
    super.onDestroy()
  }

  private fun createNotificationChannel() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      val channel =
        NotificationChannel(
          CHANNEL_ID,
          getString(R.string.vpn_notification_channel),
          NotificationManager.IMPORTANCE_LOW,
        ).apply {
          setShowBadge(false)
        }
      val manager = getSystemService(NotificationManager::class.java)
      manager?.createNotificationChannel(channel)
    }
  }

  private fun buildForegroundNotification(serverName: String, pingMs: Long): Notification {
    val immutableFlag =
      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) PendingIntent.FLAG_IMMUTABLE else 0

    val openIntent =
      Intent(this, MainActivity::class.java).apply {
        flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
      }
    val openPendingIntent =
      PendingIntent.getActivity(
        this,
        0,
        openIntent,
        PendingIntent.FLAG_UPDATE_CURRENT or immutableFlag,
      )

    val disconnectIntent =
      Intent(this, MehVpnService::class.java).apply {
        action = ACTION_DISCONNECT
      }
    val disconnectPendingIntent =
      PendingIntent.getService(
        this,
        1,
        disconnectIntent,
        PendingIntent.FLAG_UPDATE_CURRENT or immutableFlag,
      )

    return NotificationCompat.Builder(this, CHANNEL_ID)
      .setSmallIcon(android.R.drawable.ic_lock_lock)
      .setContentTitle(getString(R.string.vpn_notification_title))
      .setContentText("متصل به $serverName • پینگ ${pingMs}ms")
      .setContentIntent(openPendingIntent)
      .setOngoing(true)
      .addAction(
        0,
        getString(R.string.vpn_notification_disconnect),
        disconnectPendingIntent,
      )
      .build()
  }

  companion object {
    const val ACTION_CONNECT = "com.example.vpn.ACTION_CONNECT"
    const val ACTION_DISCONNECT = "com.example.vpn.ACTION_DISCONNECT"
    const val ACTION_SWITCH_SERVER = "com.example.vpn.ACTION_SWITCH_SERVER"

    const val EXTRA_RAW_URI = "extra_raw_uri"
    const val EXTRA_RESOLVED_IP = "extra_resolved_ip"
    const val EXTRA_FRAGMENT_PROFILE = "extra_fragment_profile"
    const val EXTRA_CIPHER_SUITES = "extra_cipher_suites"
    const val EXTRA_CANDIDATE_URIS = "extra_candidate_uris"
    const val EXTRA_CANDIDATE_IPS = "extra_candidate_ips"
    const val EXTRA_CANDIDATE_PROFILES = "extra_candidate_profiles"
    const val EXTRA_CANDIDATE_CIPHERS = "extra_candidate_ciphers"
    const val EXTRA_SERVER_NAME = "extra_server_name"
    const val EXTRA_SERVER_ADDRESS = "extra_server_address"
    const val EXTRA_SERVER_PORT = "extra_server_port"
    const val EXTRA_PROTOCOL_LABEL = "extra_protocol_label"
    const val EXTRA_INITIAL_PING = "extra_initial_ping"
    const val EXTRA_CORE_JSON = "extra_core_json"

    private const val TUN_MTU = 1400
    private const val CHANNEL_ID = "meh_vpn_channel"
    private const val NOTIFICATION_ID = 1001

    private const val REFINE_FIRST_DELAY_MS = 3_000L
    private const val REFINE_INTERVAL_FAST_HUNT_MS = 25_000L
    private const val REFINE_INTERVAL_MODERATE_MS = 90_000L
    private const val REFINE_INTERVAL_MS = 5 * 60_000L
    private const val REFINE_INTERVAL_METERED_MS = 10 * 60_000L
    private const val REFINE_MIN_SWITCH_GAP_MS = 12_000L
    private const val REFINE_SCORE_FACTOR = 1.20
    private const val REFINE_LATENCY_TOLERANCE = 1.15
    private const val REFINE_POOL_SIZE = 6
    private const val REFINE_CONCURRENCY = 16
    private const val POOL_TOP_UP_TARGET_SIZE = 5
    private const val POOL_TOP_UP_DELAY_MS = 15_000L

    private const val DIAG_LOG_INTERVAL_MS = 30_000L
    private const val KEEP_ALIVE_INTERVAL_MS = 45_000L
    private const val ACTIVE_TRAFFIC_SKIP_WINDOW_MS = 30_000L
    private const val CONSECUTIVE_PROBE_FAILURES_FOR_FAILOVER = 2
    private const val HEARTBEAT_EVERY_N_TICKS = 13

    private val _tunnelSession = MutableStateFlow(VpnTunnelSession())
    val tunnelSession: StateFlow<VpnTunnelSession> = _tunnelSession.asStateFlow()

    private val _realtimeLogs = MutableSharedFlow<VpnRealtimeLog>(extraBufferCapacity = 64)
    val realtimeLogs: SharedFlow<VpnRealtimeLog> = _realtimeLogs.asSharedFlow()

    fun emitRealtimeLog(message: String, level: VpnLogLevel = VpnLogLevel.SYSTEM) {
      _realtimeLogs.tryEmit(VpnRealtimeLog(message = message, level = level))
    }
  }
}
