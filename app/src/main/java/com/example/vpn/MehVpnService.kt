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
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import com.example.telemetry.MehTelemetry
import engine.Engine
import engine.Key
import java.io.File
import java.net.DatagramSocket
import java.net.Socket
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

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
  private var localProxyServer: LocalV2RayProxyServer? = null
  private var tun2SocksStarted: Boolean = false
  private var connectJob: Job? = null
  private var keepAliveJob: Job? = null

  @Volatile private var underlyingPhysicalNetwork: Network? = null
  private var networkCallback: ConnectivityManager.NetworkCallback? = null

  override fun onCreate() {
    super.onCreate()
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
    val protectedOk =
      try {
        protect(socket)
      } catch (_: Exception) {
        false
      }
    try {
      underlyingPhysicalNetwork?.bindSocket(socket)
    } catch (_: Exception) {}
    return protectedOk
  }

  private fun protectOutboundDatagramSocket(datagramSocket: DatagramSocket): Boolean {
    val protectedOk =
      try {
        protect(datagramSocket)
      } catch (_: Exception) {
        false
      }
    try {
      underlyingPhysicalNetwork?.bindSocket(datagramSocket)
    } catch (_: Exception) {}
    return protectedOk
  }

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_DISCONNECT -> {
        stopTunnel()
        return START_NOT_STICKY
      }
      ACTION_CONNECT -> {
        val rawUri = intent.getStringExtra(EXTRA_RAW_URI).orEmpty()
        val resolvedIp = intent.getStringExtra(EXTRA_RESOLVED_IP).orEmpty()
        val candidateUris = intent.getStringArrayListExtra(EXTRA_CANDIDATE_URIS).orEmpty()
        val candidateIps = intent.getStringArrayListExtra(EXTRA_CANDIDATE_IPS).orEmpty()

        val parsedPrimary = V2RayConfigParser.parseSingleUri(rawUri)
        val serverName =
          intent.getStringExtra(EXTRA_SERVER_NAME) ?: parsedPrimary?.cleanTitle ?: "V2Ray Server"
        val initialPing = intent.getLongExtra(EXTRA_INITIAL_PING, 80L)
        val coreJson = intent.getStringExtra(EXTRA_CORE_JSON) ?: "{}"

        if (parsedPrimary == null) {
          stopTunnel("کانفیگ سرور نامعتبر است")
          return START_NOT_STICKY
        }

        val candidateConfigs = mutableListOf<V2RayConfig>()
        candidateConfigs.add(parsedPrimary.copy(resolvedIp = resolvedIp, latencyMs = initialPing))
        for (i in candidateUris.indices) {
          val uri = candidateUris[i]
          val ip = candidateIps.getOrNull(i).orEmpty()
          val cfg = V2RayConfigParser.parseSingleUri(uri)
          if (cfg != null && candidateConfigs.none { it.endpointKey == cfg.endpointKey }) {
            candidateConfigs.add(cfg.copy(resolvedIp = ip))
          }
        }

        // Must call startForeground synchronously on main thread before launching IO work
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
              coreJson = coreJson,
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
    coreJson: String,
  ) {
    try {
      File(filesDir, "active_v2ray_config.json").writeText(coreJson)

      // Stop any previous tunnel session cleanly
      stopNativeTun2Socks()
      localProxyServer?.stop()
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
      val primaryConfig = effectiveConfigs.first()

      // 1. Start local V2Ray SOCKS5 (TCP + UDP ASSOCIATE) & HTTP CONNECT proxy server with failover pool
      val proxyServer =
        LocalV2RayProxyServer(
          configs = effectiveConfigs,
          protector = { socket -> protectOutboundSocket(socket) },
          udpProtector = { datagramSocket -> protectOutboundDatagramSocket(datagramSocket) },
        )
      val proxyPort = proxyServer.start()
      localProxyServer = proxyServer

      // 2. Establish full-device Android TUN interface (0.0.0.0/0) excluding our own app
      val builder =
        Builder()
          .setSession("MEH • $serverName")
          .setMtu(1500)
          .addAddress("10.10.14.2", 24)
          .addRoute("0.0.0.0", 0)
          .addDnsServer("8.8.8.8")
          .addDnsServer("1.1.1.1")

      try {
        builder.addAddress("fd00:1:fd00:1::2", 64)
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

      // 3. Start native Go tun2socks engine with the established TUN file descriptor
      try {
        val key =
          Key().apply {
            mtu = 1500L
            device = "fd://${establishedPfd.fd}"
            proxy = "socks5://127.0.0.1:$proxyPort"
            logLevel = "error"
          }
        Engine.insert(key)
        Engine.start()
        tun2SocksStarted = true
      } catch (t: Throwable) {
        MehTelemetry.logError(
          stage = "tun2socks_start",
          errorMessage = t.localizedMessage ?: "Failed to start native tun2socks",
          throwable = t,
        )
      }

      _tunnelSession.value =
        VpnTunnelSession(
          isRunning = true,
          serverName = serverName,
          serverAddress = primaryConfig.address,
          serverPort = primaryConfig.port,
          protocolLabel = primaryConfig.protocol.label,
          currentPingMs = initialPing,
          localProxyPort = proxyPort,
          errorMessage = null,
        )

      startProtectedKeepAliveProbe(proxyServer, serverName, proxyPort, initialPing)
    } catch (e: Exception) {
      MehTelemetry.logError(
        stage = "vpn_tunnel_establish",
        errorMessage = e.localizedMessage ?: "Failed to establish TUN interface",
        throwable = e,
      )
      stopTunnel("خطا در راه‌اندازی تونل VPN: ${e.localizedMessage ?: "نامشخص"}")
    }
  }

  private fun stopNativeTun2Socks() {
    if (tun2SocksStarted) {
      tun2SocksStarted = false
      try {
        Engine.stop()
      } catch (_: Throwable) {}
    }
  }

  private fun startProtectedKeepAliveProbe(
    proxyServer: LocalV2RayProxyServer,
    serverName: String,
    proxyPort: Int,
    initialPing: Long,
  ) {
    keepAliveJob?.cancel()
    keepAliveJob =
      serviceScope.launch {
        var lastPing = initialPing
        while (isActive) {
          delay(15_000L)
          val activeCfg = proxyServer.activeConfig
          val measuredPing =
            V2RayOutboundClient.measureRealProxyDelay(
              config = activeCfg,
              timeoutMs = 3500,
              protector = { socket -> protectOutboundSocket(socket) },
            ) ?: lastPing
          lastPing = measuredPing
          _tunnelSession.value =
            VpnTunnelSession(
              isRunning = true,
              serverName = activeCfg.cleanTitle.ifBlank { serverName },
              serverAddress = activeCfg.address,
              serverPort = activeCfg.port,
              protocolLabel = activeCfg.protocol.label,
              currentPingMs = lastPing,
              localProxyPort = proxyPort,
              errorMessage = null,
            )
        }
      }
  }

  private fun stopTunnel(errorMsg: String? = null) {
    connectJob?.cancel()
    connectJob = null
    keepAliveJob?.cancel()
    keepAliveJob = null
    stopNativeTun2Socks()
    localProxyServer?.stop()
    localProxyServer = null
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
    stopNativeTun2Socks()
    localProxyServer?.stop()
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

    const val EXTRA_RAW_URI = "extra_raw_uri"
    const val EXTRA_RESOLVED_IP = "extra_resolved_ip"
    const val EXTRA_CANDIDATE_URIS = "extra_candidate_uris"
    const val EXTRA_CANDIDATE_IPS = "extra_candidate_ips"
    const val EXTRA_SERVER_NAME = "extra_server_name"
    const val EXTRA_SERVER_ADDRESS = "extra_server_address"
    const val EXTRA_SERVER_PORT = "extra_server_port"
    const val EXTRA_PROTOCOL_LABEL = "extra_protocol_label"
    const val EXTRA_INITIAL_PING = "extra_initial_ping"
    const val EXTRA_CORE_JSON = "extra_core_json"

    private const val CHANNEL_ID = "meh_vpn_channel"
    private const val NOTIFICATION_ID = 1001

    private val _tunnelSession = MutableStateFlow(VpnTunnelSession())
    val tunnelSession: StateFlow<VpnTunnelSession> = _tunnelSession.asStateFlow()
  }
}
