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
import com.example.data.VerifiedServerPoolStore
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
import org.amnezia.awg.hevtunnel.TProxyService
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
  @Volatile private var activeUseFragment: Boolean = false
  @Volatile private var localSocksPort: Int = 0
  @Volatile private var nativeCoreStarted: Boolean = false
  @Volatile private var hevTunnelRunning: Boolean = false

  private var connectJob: Job? = null
  private var keepAliveJob: Job? = null
  private var refineJob: Job? = null
  private var topUpPoolJob: Job? = null
  @Volatile private var sessionConnectedAtMs: Long = 0L
  @Volatile private var initialUpgradeCompleted: Boolean = false

  private val nodeRepository by lazy { SoliSpiritRepository() }
  @Volatile private var refineBatchIndex: Int = 0
  private val allSubBatches by lazy { SoliSpiritRepository.SOLISPIRIT_SOURCES.chunked(4) }

  @Volatile private var underlyingPhysicalNetwork: Network? = null
  private var networkCallback: ConnectivityManager.NetworkCallback? = null

  override fun onCreate() {
    super.onCreate()
    MehTelemetry.initialize(this)
    registerPhysicalNetworkTracker()
    BackgroundServerScanScheduler.ensurePeriodicScheduled(applicationContext)
    observeBackgroundVerifiedPool()
  }

  private fun observeBackgroundVerifiedPool() {
    serviceScope.launch {
      VerifiedServerPoolStore.poolUpdates.collect { freshServers ->
        if (!_tunnelSession.value.isRunning || freshServers.isEmpty()) return@collect
        val added = appendFreshStandbyServers(freshServers)
        if (added > 0) {
          android.util.Log.i(
            "MehVpnService",
            "Added $added freshly verified background server(s) to standby pool",
          )
        }
      }
    }
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
      stopHevTunnel()
      stopNativeXray()
      try {
        vpnInterface?.close()
      } catch (_: Exception) {}
      vpnInterface = null

      val deadKeys = DeadServerStore.deadKeys(applicationContext)
      val backgroundBackups =
        VerifiedServerPoolStore.getFastest(applicationContext)
          .filter { it.endpointKey !in deadKeys }
      val mergedInputConfigs =
        (configs + backgroundBackups)
          .distinctBy { it.endpointKey }
          .take(MAX_STANDBY_POOL_SIZE)

      val effectiveConfigs =
        mergedInputConfigs.map { cfg ->
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

      // Allocate one fixed local SOCKS5 port for this VPN session.
      // We verify candidates on native Xray SOCKS5 FIRST (without touching TUN), then attach
      // pure-C `hev-socks5-tunnel` + `mapdns` ONCE to this fixed port (v2rayNG / MahsaNG model).
      val fixedSocksPort = NativeXrayEngine.allocateLocalPort()
      localSocksPort = fixedSocksPort

      var startedConfig: V2RayConfig? = null
      var verifiedPingMs: Long = initialPing
      var lastError: String? = null
      for (idx in effectiveConfigs.indices) {
        val candidate = effectiveConfigs[idx]
        if (!NativeXrayEngine.supportsNativeXray(candidate)) continue
        emitRealtimeLog(
          "راه‌اندازی و تست هسته Xray روی ${candidate.cleanTitle}...",
          VpnLogLevel.SCAN,
        )
        val (verifiedCfg, livePing, candidateErr) =
          launchVerifiedNativeXraySocks(
            candidate = candidate,
            socksPort = fixedSocksPort,
            verifyTimeoutMs = 4500,
          )
        if (verifiedCfg != null && livePing != null) {
          startedConfig = verifiedCfg
          verifiedPingMs = livePing
          synchronized(poolLock) { poolCursor.set(idx) }
          break
        }
        stopNativeXray()
        if (candidateErr != null) {
          lastError = candidateErr
        } else if (lastError == null) {
          lastError = "سرور ${candidate.cleanTitle} ترافیک اینترنت را عبور نداد"
        }
        DeadServerStore.markDead(applicationContext, candidate.endpointKey)
        VerifiedServerPoolStore.removeEndpoint(applicationContext, candidate.endpointKey)
      }

      val active =
        startedConfig
          ?: throw IllegalStateException(
            lastError ?: "هیچ‌یک از سرورها از هسته Xray عبور نکردند"
          )

      val effectiveName = active.cleanTitle.ifBlank { serverName }
      val effectivePing = verifiedPingMs.coerceAtLeast(1L)

      if (connectJob?.isActive == false) {
        stopNativeXray()
        return
      }

      // Establish IPv4-only Android TUN interface ONCE and bridge all device TCP/UDP/DNS traffic
      // to Xray's local SOCKS5 inbound via `hev-socks5-tunnel` with built-in `mapdns`.
      val builder =
        Builder()
          .setSession("MEH • $effectiveName")
          .setMtu(TUN_MTU)
          .addAddress(TUN_IPV4_ADDRESS, 30)
          .addRoute("0.0.0.0", 0)
          .addDnsServer(MAP_DNS_ADDRESS)

      try {
        builder.addDisallowedApplication(packageName)
      } catch (_: Exception) {}

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
      }

      val establishedPfd =
        builder.establish() ?: throw IllegalStateException("TUN establish returned null")
      vpnInterface = establishedPfd

      val hevYaml =
        GfwKnockerXrayCore.buildHevSocks5TunnelYaml(
          socksPort = fixedSocksPort,
          tunMtu = TUN_MTU,
          tunIpv4 = TUN_IPV4_ADDRESS,
          mapDnsAddress = MAP_DNS_ADDRESS,
        )
      val hevConfigFile = File(filesDir, "hev_socks5_tunnel.yml")
      hevConfigFile.writeText(hevYaml)

      TProxyService.TProxyStartService(hevConfigFile.absolutePath, establishedPfd.fd)
      hevTunnelRunning = true

      _tunnelSession.value =
        VpnTunnelSession(
          isRunning = true,
          serverName = effectiveName,
          serverAddress = active.address,
          serverPort = active.port,
          protocolLabel = active.protocol.label,
          currentPingMs = effectivePing,
          localProxyPort = fixedSocksPort,
          errorMessage = null,
        )

      sessionConnectedAtMs = System.currentTimeMillis()
      initialUpgradeCompleted = effectivePing <= FAST_ENOUGH_PING_MS
      VerifiedServerPoolStore.upsertVerified(
        applicationContext,
        listOf(active.copy(latencyMs = effectivePing)),
      )

      emitRealtimeLog(
        "متصل و تایید شد: $effectiveName (${active.protocol.label} • پینگ ${effectivePing}ms)",
        VpnLogLevel.SUCCESS,
      )

      startProtectedKeepAliveProbe(effectiveName, effectivePing)
      startBackgroundNodeRefinement(effectivePing)
    } catch (ce: CancellationException) {
      throw ce
    } catch (t: Throwable) {
      MehTelemetry.logError(
        stage = "vpn_tunnel_establish",
        errorMessage = t.localizedMessage ?: t.javaClass.simpleName,
        throwable = t,
      )
      stopTunnel("خطا در راه‌اندازی هسته Xray:\n${t.localizedMessage ?: t.javaClass.simpleName}")
    }
  }

  private fun launchVerifiedNativeXraySocks(
    candidate: V2RayConfig,
    socksPort: Int,
    verifyTimeoutMs: Int = 4500,
  ): Triple<V2RayConfig?, Long?, String?> {
    val defaultFrag =
      candidate.fragmentProfile.isNotBlank() &&
        !candidate.fragmentProfile.equals("direct_tls", ignoreCase = true)
    var lastError: String? = null
    for (fragMode in listOf(defaultFrag, !defaultFrag)) {
      val startErr =
        launchNativeXraySocksCore(
          config = candidate,
          socksPort = socksPort,
          useFragmentOverride = fragMode,
        )
      if (startErr != null) {
        lastError = startErr
        break
      }
      val livePing = verifyRealPathViaProxy(socksPort, timeoutMs = verifyTimeoutMs)
      if (livePing != null) {
        val verifiedCfg = activeConfigState ?: candidate
        return Triple(verifiedCfg, livePing, null)
      }
    }
    return Triple(null, null, lastError)
  }

  /**
   * Starts (or hot-restarts) native Go Xray-core in SOCKS5-only inbound mode on [socksPort].
   * `hev-socks5-tunnel` owns the Android TUN interface and forwards all traffic to `127.0.0.1:[socksPort]`,
   * so switching servers never touches or corrupts the Android TUN file descriptor.
   */
  private fun launchNativeXraySocksCore(
    config: V2RayConfig,
    socksPort: Int,
    useFragmentOverride: Boolean? = null,
  ): String? {
    if (socksPort <= 0) return "Invalid local SOCKS5 port"
    val resolvedConfig =
      if (config.resolvedIp.isNotBlank()) {
        config
      } else {
        val ip = V2RayOutboundClient.resolveEndpointIpv4(config.address).orEmpty()
        config.copy(resolvedIp = ip)
      }

    val effectiveFragment =
      useFragmentOverride
        ?: (resolvedConfig.fragmentProfile.isNotBlank() &&
          !resolvedConfig.fragmentProfile.equals("direct_tls", ignoreCase = true))
    val xrayJson =
      GfwKnockerXrayCore.buildXrayCoreJson(
        config = resolvedConfig,
        includeTunInbound = false,
        tunMtu = TUN_MTU,
        localSocksPort = socksPort,
        useFragment = effectiveFragment,
      )
    try {
      File(filesDir, "active_v2ray_config.json").writeText(xrayJson)
    } catch (_: Exception) {}

    val result =
      NativeXrayEngine.startTunnel(
        datDir = filesDir.absolutePath,
        tunFd = null,
        configJson = xrayJson,
        protectFd = { fd ->
          if (vpnInterface == null) {
            true
          } else {
            try {
              protect(fd)
            } catch (_: Throwable) {
              true
            }
          }
        },
      )

    return if (result.success) {
      nativeCoreStarted = true
      activeConfigState = resolvedConfig
      activeUseFragment = effectiveFragment
      localSocksPort = socksPort
      null
    } else {
      nativeCoreStarted = false
      result.error ?: "Failed to start Xray core"
    }
  }

  private fun stopHevTunnel() {
    if (hevTunnelRunning) {
      hevTunnelRunning = false
      try {
        TProxyService.TProxyStopService()
      } catch (_: Throwable) {}
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
    val socksPort = localSocksPort
    if (socksPort <= 0) return currentActiveConfig()
    val previousActive = currentActiveConfig()
    val previousFrag = activeUseFragment
    val candidate =
      synchronized(poolLock) {
        if (serverPool.isEmpty()) return previousActive
        val nextIdx = (poolCursor.get() + 1) % serverPool.size
        poolCursor.set(nextIdx)
        serverPool[nextIdx]
      }
    val err = launchNativeXraySocksCore(candidate, socksPort)
    if (err == null) {
      android.util.Log.i(
        "MehVpnService",
        "Switched native Xray node ($reason) -> ${candidate.cleanTitle}",
      )
      return candidate
    }
    if (previousActive != null) {
      launchNativeXraySocksCore(previousActive, socksPort, useFragmentOverride = previousFrag)
    }
    return previousActive
  }

  private fun replaceServerPool(newPool: List<V2RayConfig>): V2RayConfig? {
    val clean =
      newPool
        .filter { NativeXrayEngine.supportsNativeXray(it) }
        .distinctBy { it.endpointKey }
    if (clean.isEmpty()) return null
    val socksPort = localSocksPort
    if (socksPort <= 0) return clean.first()
    val previousActive = currentActiveConfig()
    val previousFrag = activeUseFragment

    val swapped =
      executeSafeServerSwap(
        candidates = clean.take(3),
        previousActive = previousActive,
        preVerifyIsolated = { candidate ->
          NativeXrayEngine.pingConfig(
            datDir = filesDir.absolutePath,
            tempDir = cacheDir,
            config = candidate,
            timeoutSec = 4,
            protectFd = { fd ->
              if (vpnInterface == null) true else try { protect(fd) } catch (_: Throwable) { true }
            },
          )
        },
        launchAndVerifyLive = { candidate ->
          val (verifiedCfg, livePing, _) =
            launchVerifiedNativeXraySocks(
              candidate = candidate,
              socksPort = socksPort,
              verifyTimeoutMs = 4000,
            )
          if (verifiedCfg != null && livePing != null) verifiedCfg to livePing else null
        },
        restorePrevious = { prev ->
          launchNativeXraySocksCore(prev, socksPort, useFragmentOverride = previousFrag)
        },
        isLiveCoreRunning = { NativeXrayEngine.isRunning() },
      )

    if (swapped != null) {
      val (idx, verifiedCfg, livePing) = swapped
      synchronized(poolLock) {
        serverPool = clean
        poolCursor.set(idx)
      }
      return verifiedCfg.copy(latencyMs = livePing)
    }
    return null
  }

  private fun appendToServerPool(more: List<V2RayConfig>): Int {
    if (more.isEmpty()) return currentPoolSnapshot().size
    synchronized(poolLock) {
      val merged =
        (serverPool + more.filter { NativeXrayEngine.supportsNativeXray(it) })
          .distinctBy { it.endpointKey }
          .take(MAX_STANDBY_POOL_SIZE)
      serverPool = merged
      return merged.size
    }
  }

  /**
   * Appends newly discovered verified servers that are not yet in [serverPool] without moving
   * [poolCursor] or interrupting the active tunnel, so repeated manual switches cycle smoothly
   * into newly found background servers.
   */
  private fun appendFreshStandbyServers(candidates: List<V2RayConfig>): Int {
    if (candidates.isEmpty()) return 0
    val deadKeys = DeadServerStore.deadKeys(applicationContext)
    val supported =
      candidates.filter {
        it.endpointKey !in deadKeys && NativeXrayEngine.supportsNativeXray(it)
      }
    if (supported.isEmpty()) return 0
    synchronized(poolLock) {
      val existingKeys = serverPool.map { it.endpointKey }.toSet()
      val brandNew = supported.filter { it.endpointKey !in existingKeys }
      if (brandNew.isEmpty()) return 0
      val merged = (serverPool + brandNew).distinctBy { it.endpointKey }.take(MAX_STANDBY_POOL_SIZE)
      val addedCount = (merged.size - serverPool.size).coerceAtLeast(0)
      serverPool = merged
      return addedCount
    }
  }

  /**
   * Places newly discovered fast standby servers immediately after [active] (index 0) so the next
   * automatic failover or manual switch picks the fastest verified standby server right away
   * without interrupting the current active connection.
   */
  private fun prioritizeStandbyPool(
    active: V2RayConfig,
    standbyCandidates: List<V2RayConfig>,
  ): Int {
    val supportedStandby = standbyCandidates.filter { NativeXrayEngine.supportsNativeXray(it) }
    if (supportedStandby.isEmpty()) return currentPoolSnapshot().size
    synchronized(poolLock) {
      val reordered =
        buildReorderedStandbyPool(
          active = active,
          standbyCandidates = supportedStandby,
          existingPool = serverPool,
          maxSize = MAX_STANDBY_POOL_SIZE,
        )
      serverPool = reordered
      poolCursor.set(0)
      return reordered.size
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

  /**
   * Verifies real TLS/HTTPS connectivity through the live local SOCKS5 Xray inbound.
   * Never falls back to plain HTTP port 80 so TLS-broken or captive proxies cannot pass.
   */
  private fun verifyRealPathViaProxy(proxyPort: Int, timeoutMs: Int = 3500): Long? =
    verifyRealPathOverSocks(proxyPort, timeoutMs)

  private fun verifyNodeFully(config: V2RayConfig, proxyPort: Int): Long? {
    val directPing = verifyNodeCapability(config)
    val realPing = verifyRealPathViaProxy(proxyPort)
    return realPing ?: directPing
  }

  private fun failoverToNextVerifiedNode(
    failedCfg: V2RayConfig,
    reason: String,
  ): Pair<V2RayConfig, Long?> {
    appendFreshStandbyServers(VerifiedServerPoolStore.getFastest(applicationContext))
    var abandonedCfg = failedCfg
    val poolSize = currentPoolSnapshot().size.coerceAtLeast(1)
    var attempts = 0
    while (attempts < poolSize) {
      val nextCfg = switchToNextHealthyNode(reason) ?: break
      attempts++
      if (nextCfg.endpointKey == abandonedCfg.endpointKey) break
      DeadServerStore.markDead(applicationContext, abandonedCfg.endpointKey)
      VerifiedServerPoolStore.removeEndpoint(applicationContext, abandonedCfg.endpointKey)
      val ping = verifyRealPathViaProxy(localSocksPort)
      if (ping != null) {
        VerifiedServerPoolStore.upsertVerified(applicationContext, listOf(nextCfg.copy(latencyMs = ping)))
        return nextCfg to ping
      }
      abandonedCfg = nextCfg
    }
    return (currentActiveConfig() ?: failedCfg) to null
  }

  private fun handleManualSwitchServer() {
    val beforeCfg = currentActiveConfig() ?: return
    appendFreshStandbyServers(VerifiedServerPoolStore.getFastest(applicationContext))
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
          VerifiedServerPoolStore.upsertVerified(applicationContext, listOf(candidate.copy(latencyMs = realPing)))
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
        VerifiedServerPoolStore.removeEndpoint(applicationContext, candidate.endpointKey)
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
        var lastOtherAppsRxBytes = safeOtherAppsRxBytes()

        if (BuildConfig.DEBUG) {
          launch {
            while (isActive) {
              delay(DIAG_LOG_INTERVAL_MS)
              android.util.Log.i("MehDiag", MehDiag.formatCompactSummary())
            }
          }
        }

        while (isActive) {
          delay(if (tickCount == 0) KEEP_ALIVE_FIRST_CHECK_MS else KEEP_ALIVE_INTERVAL_MS)
          tickCount++
          var activeCfg = currentActiveConfig() ?: continue

          val nowOtherRxBytes = safeOtherAppsRxBytes()
          val rxDelta =
            if (lastOtherAppsRxBytes >= 0L && nowOtherRxBytes >= lastOtherAppsRxBytes) {
              nowOtherRxBytes - lastOtherAppsRxBytes
            } else {
              0L
            }
          lastOtherAppsRxBytes = nowOtherRxBytes

          if (rxDelta > 16_384L) {
            MehDiag.recordRealDownloadBytes(rxDelta)
            MehDiag.recordKeepAliveSkippedActiveTraffic()
            consecutiveFailures = 0
          } else {
            MehDiag.recordKeepAliveProbeRun()
            if (!NativeXrayEngine.isRunning() && localSocksPort > 0) {
              launchNativeXraySocksCore(activeCfg, localSocksPort, useFragmentOverride = activeUseFragment)
            }
            var realPing = verifyRealPathViaProxy(localSocksPort, timeoutMs = 4000)
            if (realPing == null) {
              delay(1_500L)
              realPing = verifyRealPathViaProxy(localSocksPort, timeoutMs = 4000)
            }
            if (realPing != null) {
              lastPing = realPing
              consecutiveFailures = 0
            } else {
              consecutiveFailures++
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

  /**
   * Reads RX bytes for all apps EXCEPT our own process (using standard Android [TrafficStats] +
   * [android.os.Process.myUid]) so background probing never counts as user traffic and we avoid
   * extra JNI stats calls into `hev-socks5-tunnel`.
   */
  private fun safeOtherAppsRxBytes(): Long {
    return try {
      val totalRx = TrafficStats.getTotalRxBytes()
      if (totalRx < 0L) return -1L
      val ownRx = TrafficStats.getUidRxBytes(android.os.Process.myUid()).coerceAtLeast(0L)
      (totalRx - ownRx).coerceAtLeast(0L)
    } catch (_: Throwable) {
      -1L
    }
  }

  /** Reads combined TX + RX bytes for all other apps (excluding our own UID). */
  private fun safeOtherAppsTotalBytes(): Long {
    return try {
      val totalRx = TrafficStats.getTotalRxBytes()
      val totalTx = TrafficStats.getTotalTxBytes()
      if (totalRx < 0L || totalTx < 0L) return -1L
      val myUid = android.os.Process.myUid()
      val ownRx = TrafficStats.getUidRxBytes(myUid).coerceAtLeast(0L)
      val ownTx = TrafficStats.getUidTxBytes(myUid).coerceAtLeast(0L)
      ((totalRx - ownRx).coerceAtLeast(0L) + (totalTx - ownTx).coerceAtLeast(0L))
    } catch (_: Throwable) {
      -1L
    }
  }

  /**
   * Samples other-app network byte counters over [ACTIVE_TRAFFIC_SAMPLE_MS] to detect active
   * downloads, video playback, or calls so a background upgrade never drops an in-progress session.
   */
  private suspend fun isUserTunnelTrafficActive(): Boolean {
    val before = safeOtherAppsTotalBytes()
    if (before < 0L) return false
    delay(ACTIVE_TRAFFIC_SAMPLE_MS)
    val after = safeOtherAppsTotalBytes()
    if (after < before) return false
    return (after - before) >= ACTIVE_TRAFFIC_THRESHOLD_BYTES
  }

  /**
   * Smart, non-disruptive background refinement:
   * - If the initial server is already fast (<= 350ms), warms up a standby pool once and stops
   *   scanning so active calls/downloads and IP stability are never disturbed.
   * - If the initial server is slow (> 350ms), searches during a short 2-minute initial upgrade
   *   window to perform at most ONE upgrade when the tunnel is idle; afterwards (or if user
   *   traffic is active), faster servers are placed at the front of the standby pool for instant
   *   failover or manual switching.
   */
  private fun startBackgroundNodeRefinement(initialPingMs: Long) {
    refineJob?.cancel()
    refineBatchIndex = 0
    refineJob =
      serviceScope.launch {
        if (initialUpgradeCompleted) {
          delay(STANDBY_WARMUP_DELAY_MS)
          if (currentPoolSnapshot().size < STANDBY_POOL_TARGET_SIZE) {
            try {
              refineNodesOnce(force = false)
            } catch (ce: CancellationException) {
              throw ce
            } catch (t: Throwable) {
              android.util.Log.w("MehRefine", "standby warm-up failed: ${t.javaClass.simpleName}")
            }
          }
          return@launch
        }

        emitRealtimeLog(
          "سرور فعلی پینگ ${initialPingMs}ms دارد؛ جستجوی ارتقای یک‌باره در پس‌زمینه فعال شد...",
          VpnLogLevel.SYSTEM,
        )
        delay(REFINE_FIRST_DELAY_MS)
        var attempts = 0
        while (isActive && !initialUpgradeCompleted && attempts < MAX_INITIAL_UPGRADE_ATTEMPTS) {
          val elapsed = System.currentTimeMillis() - sessionConnectedAtMs
          if (elapsed > INITIAL_UPGRADE_WINDOW_MS) break
          attempts++
          var upgraded = false
          try {
            upgraded = refineNodesOnce(force = false)
          } catch (ce: CancellationException) {
            throw ce
          } catch (t: Throwable) {
            android.util.Log.w("MehRefine", "initial upgrade scan failed: ${t.javaClass.simpleName}")
          }
          if (upgraded || initialUpgradeCompleted) break
          val remainingMs = INITIAL_UPGRADE_WINDOW_MS - (System.currentTimeMillis() - sessionConnectedAtMs)
          if (remainingMs <= 3_000L) break
          val stepDelay =
            if (isPhysicalNetworkMetered()) {
              REFINE_RETRY_METERED_MS
            } else {
              REFINE_RETRY_IDLE_MS
            }
          delay(stepDelay.coerceAtMost(remainingMs))
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
    val standbyOnlyMode = !force && (initialUpgradeCompleted || (System.currentTimeMillis() - sessionConnectedAtMs) > INITIAL_UPGRADE_WINDOW_MS)
    emitRealtimeLog(
      if (standbyOnlyMode) {
        "آماده‌سازی صف سرورهای ذخیره ($sourceLabel • دسته ${batchIdx + 1}/${batches.size.coerceAtLeast(1)}) ..."
      } else {
        "جستجوی سرور سریع‌تر در پس‌زمینه ($sourceLabel • دسته ${batchIdx + 1}/${batches.size.coerceAtLeast(1)}) ..."
      },
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

    val fresh =
      nodeRepository.testAndSelectFastestCandidates(
        configs = challengers,
        maxCount = REFINE_POOL_SIZE,
        prioritizedSavedNodes = others,
        maxWaves = 2,
        concurrency = REFINE_CONCURRENCY,
        verifyConcurrency = 3,
      ) { _ -> }
    val nonActiveFresh = fresh.filter { it.endpointKey != active.endpointKey }
    val best = nonActiveFresh.firstOrNull() ?: return false

    // Always place freshly verified fast backups right after the active node in the standby pool
    // and persist them to VerifiedServerPoolStore for future fast reconnects & switches.
    val standbyCount = prioritizeStandbyPool(active, nonActiveFresh)
    VerifiedServerPoolStore.upsertVerified(applicationContext, nonActiveFresh)

    val currentPing = _tunnelSession.value.currentPingMs.coerceAtLeast(1L)
    val elapsedMs = (System.currentTimeMillis() - sessionConnectedAtMs).coerceAtLeast(0L)
    val shouldCheckTraffic =
      !force &&
        !initialUpgradeCompleted &&
        elapsedMs <= INITIAL_UPGRADE_WINDOW_MS &&
        currentPing > FAST_ENOUGH_PING_MS
    val userTrafficBusy = if (shouldCheckTraffic) isUserTunnelTrafficActive() else false

    val decision =
      decideBackgroundRefineAction(
        forceFailover = force,
        initialUpgradeCompleted = initialUpgradeCompleted,
        elapsedSinceConnectMs = elapsedMs,
        currentPingMs = currentPing,
        challengerPingMs = best.latencyMs,
        isUserTrafficActive = userTrafficBusy,
      )

    when (decision) {
      RefineAction.STORE_STANDBY_ONLY -> {
        emitRealtimeLog(
          "صف ذخیره به‌روز شد (${standbyCount - 1} سرور آماده • سریع‌ترین: ${best.cleanTitle} ${best.latencyMs}ms) — اتصال فعلی ثابت ماند.",
          VpnLogLevel.SYSTEM,
        )
        return false
      }
      RefineAction.DEFER_ACTIVE_TRAFFIC -> {
        emitRealtimeLog(
          "سرور سریع‌تر پیدا شد (${best.cleanTitle} • ${best.latencyMs}ms)؛ به‌دلیل مصرف فعال اینترنت، در صف ذخیره قرار گرفت تا اتصال قطع نشود.",
          VpnLogLevel.SYSTEM,
        )
        return false
      }
      RefineAction.UPGRADE_NOW -> {
        emitRealtimeLog(
          "کانفیگ سریع‌تر پیدا شد: ${best.cleanTitle} (${best.protocol.label} • پینگ ${best.latencyMs}ms)",
          VpnLogLevel.SUCCESS,
        )
        val newPool =
          (nonActiveFresh.take(REFINE_POOL_SIZE - 1) + listOf(active) + others)
            .distinctBy { it.endpointKey }
            .take(MAX_STANDBY_POOL_SIZE)
        val newActive = replaceServerPool(newPool) ?: return false
        val upgradedPing = newActive.latencyMs.coerceAtLeast(1L)
        if (!force) {
          initialUpgradeCompleted = true
        }
        updateSessionAndNotification(newActive, upgradedPing)
        emitRealtimeLog(
          if (force) {
            "اتصال به سرور جایگزین برقرار شد: ${newActive.cleanTitle} (${upgradedPing}ms)"
          } else {
            "ارتقای یک‌باره به سرور سریع‌تر انجام شد: ${newActive.cleanTitle} (${upgradedPing}ms) — اتصال برای پایداری ثابت می‌ماند."
          },
          VpnLogLevel.SUCCESS,
        )
        return true
      }
    }
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
    sessionConnectedAtMs = 0L
    initialUpgradeCompleted = false
    stopHevTunnel()
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
    BackgroundServerScanScheduler.ensurePeriodicScheduled(applicationContext)
    BackgroundServerScanScheduler.scheduleWarmupIfNeeded(applicationContext)
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
    stopHevTunnel()
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

  internal enum class RefineAction {
    UPGRADE_NOW,
    DEFER_ACTIVE_TRAFFIC,
    STORE_STANDBY_ONLY,
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

    internal const val TUN_MTU = 1400
    internal const val TUN_IPV4_ADDRESS = "10.10.14.1"
    internal const val MAP_DNS_ADDRESS = "10.10.14.2"
    private const val CHANNEL_ID = "meh_vpn_channel"
    private const val NOTIFICATION_ID = 1001

    private const val REFINE_FIRST_DELAY_MS = 4_000L
    private const val STANDBY_WARMUP_DELAY_MS = 6_000L
    private const val INITIAL_UPGRADE_WINDOW_MS = 120_000L
    private const val MAX_INITIAL_UPGRADE_ATTEMPTS = 4
    private const val REFINE_RETRY_IDLE_MS = 14_000L
    private const val REFINE_RETRY_METERED_MS = 25_000L
    private const val FAST_ENOUGH_PING_MS = 350L
    private const val FAST_TARGET_PING_MS = 250L
    private const val INITIAL_UPGRADE_RATIO = 0.60
    private const val ACTIVE_TRAFFIC_SAMPLE_MS = 1_200L
    private const val ACTIVE_TRAFFIC_THRESHOLD_BYTES = 12_288L
    private const val REFINE_POOL_SIZE = 6
    private const val MAX_STANDBY_POOL_SIZE = 8
    private const val STANDBY_POOL_TARGET_SIZE = 4
    private const val REFINE_CONCURRENCY = 16

    private const val DIAG_LOG_INTERVAL_MS = 30_000L
    private const val KEEP_ALIVE_FIRST_CHECK_MS = 10_000L
    private const val KEEP_ALIVE_INTERVAL_MS = 25_000L
    private const val HEARTBEAT_EVERY_N_TICKS = 24

    internal fun verifyRealPathOverSocks(proxyPort: Int, timeoutMs: Int = 3500): Long? {
      if (proxyPort <= 0) return null
      return verifyHttpsOverSocks(proxyPort, "www.google.com", timeoutMs)
        ?: verifyHttpsOverSocks(proxyPort, "cp.cloudflare.com", timeoutMs.coerceAtMost(3000))
    }

    internal fun verifyHttpsOverSocks(
      proxyPort: Int,
      targetHost: String = "www.google.com",
      timeoutMs: Int = 3500,
    ): Long? {
      val startedNs = System.nanoTime()
      var socket: Socket? = null
      return try {
        val proxy = Proxy(Proxy.Type.SOCKS, InetSocketAddress("127.0.0.1", proxyPort))
        socket = Socket(proxy)
        socket.soTimeout = timeoutMs
        socket.connect(InetSocketAddress.createUnresolved(targetHost, 443), timeoutMs)
        val (tlsIn, tlsOut) =
          GfwKnockerXrayCore.openSslEngineOverStreams(
            sslContext = javax.net.ssl.SSLContext.getDefault(),
            rawIn = socket.getInputStream(),
            rawOut = socket.getOutputStream(),
            sniHost = targetHost,
            port = 443,
            alpnProtocols = arrayOf("http/1.1"),
          )
        val request = "GET /generate_204 HTTP/1.1\r\nHost: $targetHost\r\nConnection: close\r\n\r\n"
        tlsOut.write(request.toByteArray(Charsets.US_ASCII))
        tlsOut.flush()
        val statusLine = BufferedReader(InputStreamReader(tlsIn, Charsets.US_ASCII)).readLine()
        val code = statusLine?.split(" ")?.getOrNull(1)?.toIntOrNull()
        if (code == 204 || code == 200) {
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

    internal fun executeSafeServerSwap(
      candidates: List<V2RayConfig>,
      previousActive: V2RayConfig?,
      preVerifyIsolated: (V2RayConfig) -> Long?,
      launchAndVerifyLive: (V2RayConfig) -> Pair<V2RayConfig, Long>?,
      restorePrevious: (V2RayConfig) -> Unit,
      isLiveCoreRunning: () -> Boolean,
    ): Triple<Int, V2RayConfig, Long>? {
      for ((idx, candidate) in candidates.withIndex()) {
        if (preVerifyIsolated(candidate) == null) continue
        val liveResult = launchAndVerifyLive(candidate)
        if (liveResult != null) {
          return Triple(idx, liveResult.first, liveResult.second)
        }
        if (previousActive != null) {
          restorePrevious(previousActive)
        }
      }
      if (previousActive != null && !isLiveCoreRunning()) {
        restorePrevious(previousActive)
      }
      return null
    }

    internal fun buildReorderedStandbyPool(
      active: V2RayConfig,
      standbyCandidates: List<V2RayConfig>,
      existingPool: List<V2RayConfig>,
      maxSize: Int = MAX_STANDBY_POOL_SIZE,
    ): List<V2RayConfig> {
      val cleanStandby =
        standbyCandidates
          .filter { it.endpointKey != active.endpointKey }
          .distinctBy { it.endpointKey }
      if (cleanStandby.isEmpty()) return existingPool
      val existingOthers =
        existingPool.filter { existing ->
          existing.endpointKey != active.endpointKey &&
            cleanStandby.none { it.endpointKey == existing.endpointKey }
        }
      return (listOf(active) + cleanStandby + existingOthers)
        .distinctBy { it.endpointKey }
        .take(maxSize)
    }

    internal fun decideBackgroundRefineAction(
      forceFailover: Boolean,
      initialUpgradeCompleted: Boolean,
      elapsedSinceConnectMs: Long,
      currentPingMs: Long,
      challengerPingMs: Long,
      isUserTrafficActive: Boolean,
    ): RefineAction {
      if (forceFailover) return RefineAction.UPGRADE_NOW
      if (initialUpgradeCompleted) return RefineAction.STORE_STANDBY_ONLY
      if (elapsedSinceConnectMs > INITIAL_UPGRADE_WINDOW_MS) return RefineAction.STORE_STANDBY_ONLY
      if (currentPingMs in 1L..FAST_ENOUGH_PING_MS) return RefineAction.STORE_STANDBY_ONLY
      if (challengerPingMs <= 0L || challengerPingMs >= currentPingMs) {
        return RefineAction.STORE_STANDBY_ONLY
      }
      val significantlyFaster =
        challengerPingMs <= FAST_TARGET_PING_MS ||
          challengerPingMs <= (currentPingMs * INITIAL_UPGRADE_RATIO).toLong()
      if (!significantlyFaster) return RefineAction.STORE_STANDBY_ONLY
      return if (isUserTrafficActive) {
        RefineAction.DEFER_ACTIVE_TRAFFIC
      } else {
        RefineAction.UPGRADE_NOW
      }
    }

    private val _tunnelSession = MutableStateFlow(VpnTunnelSession())
    val tunnelSession: StateFlow<VpnTunnelSession> = _tunnelSession.asStateFlow()

    private val _realtimeLogs = MutableSharedFlow<VpnRealtimeLog>(extraBufferCapacity = 64)
    val realtimeLogs: SharedFlow<VpnRealtimeLog> = _realtimeLogs.asSharedFlow()

    fun emitRealtimeLog(message: String, level: VpnLogLevel = VpnLogLevel.SYSTEM) {
      _realtimeLogs.tryEmit(VpnRealtimeLog(message = message, level = level))
    }
  }
}
