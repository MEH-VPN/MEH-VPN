package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import com.example.telemetry.MehTelemetry
import java.io.File
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
  private var tunDnsForwarder: TunDnsForwarder? = null
  private var keepAliveJob: Job? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_DISCONNECT -> {
        stopTunnel()
        return START_NOT_STICKY
      }
      ACTION_CONNECT -> {
        val rawUri = intent.getStringExtra(EXTRA_RAW_URI).orEmpty()
        val parsedConfig = V2RayConfigParser.parseSingleUri(rawUri)
        val serverName = intent.getStringExtra(EXTRA_SERVER_NAME) ?: parsedConfig?.cleanTitle ?: "V2Ray Server"
        val initialPing = intent.getLongExtra(EXTRA_INITIAL_PING, 80L)
        val coreJson = intent.getStringExtra(EXTRA_CORE_JSON) ?: "{}"

        if (parsedConfig == null) {
          stopTunnel("کانفیگ سرور نامعتبر است")
          return START_NOT_STICKY
        }

        startTunnel(
          config = parsedConfig.copy(latencyMs = initialPing),
          serverName = serverName,
          initialPing = initialPing,
          coreJson = coreJson,
        )
        return START_STICKY
      }
      else -> return START_NOT_STICKY
    }
  }

  private fun startTunnel(
    config: V2RayConfig,
    serverName: String,
    initialPing: Long,
    coreJson: String,
  ) {
    try {
      createNotificationChannel()
      val notification = buildForegroundNotification(serverName, initialPing)
      startForeground(NOTIFICATION_ID, notification)

      File(filesDir, "active_v2ray_config.json").writeText(coreJson)

      // 1. Start local V2Ray HTTP/HTTPS CONNECT & SOCKS5 proxy server with VPN socket protection
      localProxyServer?.stop()
      val proxyServer =
        LocalV2RayProxyServer(
          config = config,
          protector = { socket -> protect(socket) },
        )
      val proxyPort = proxyServer.start()
      localProxyServer = proxyServer

      // 2. Establish Android VPN Interface with system HTTP Proxy & virtual DNS forwarder
      tunDnsForwarder?.stop()
      vpnInterface?.close()

      val builder =
        Builder()
          .setSession("MEH • $serverName")
          .setMtu(1500)
          .addAddress("10.10.14.2", 30)
          .addRoute("10.10.14.1", 32)
          .addDnsServer("10.10.14.1")

      // Exclude our own app so its V2Ray outbound sockets never route back into the VPN
      try {
        builder.addDisallowedApplication(packageName)
      } catch (_: Exception) {}

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
        builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", proxyPort))
      }

      val establishedPfd = builder.establish() ?: throw IllegalStateException("TUN establish returned null")
      vpnInterface = establishedPfd

      // 3. Start real TUN DNS forwarder for 10.10.14.1:53
      val dnsForwarder =
        TunDnsForwarder(
          tunPfd = establishedPfd,
          config = config,
          protector = { socket -> protect(socket) },
          udpProtector = { datagramSocket -> protect(datagramSocket) },
        )
      dnsForwarder.start()
      tunDnsForwarder = dnsForwarder

      _tunnelSession.value =
        VpnTunnelSession(
          isRunning = true,
          serverName = serverName,
          serverAddress = config.address,
          serverPort = config.port,
          protocolLabel = config.protocol.label,
          currentPingMs = initialPing,
          localProxyPort = proxyPort,
          errorMessage = null,
        )

      startProtectedKeepAliveProbe(config, serverName, proxyPort, initialPing)
    } catch (e: Exception) {
      MehTelemetry.logError(
        stage = "vpn_tunnel_establish",
        errorMessage = e.localizedMessage ?: "Failed to establish TUN interface",
        throwable = e,
      )
      stopTunnel("خطا در راه‌اندازی تونل VPN: ${e.localizedMessage ?: "نامشخص"}")
    }
  }

  private fun startProtectedKeepAliveProbe(
    config: V2RayConfig,
    serverName: String,
    proxyPort: Int,
    initialPing: Long,
  ) {
    keepAliveJob?.cancel()
    keepAliveJob =
      serviceScope.launch {
        var lastPing = initialPing
        while (isActive) {
          delay(12_000L)
          val measuredPing =
            V2RayOutboundClient.measureRealProxyDelay(
              config = config,
              timeoutMs = 3000,
              protector = { socket -> protect(socket) },
            ) ?: lastPing
          lastPing = measuredPing
          _tunnelSession.value =
            VpnTunnelSession(
              isRunning = true,
              serverName = serverName,
              serverAddress = config.address,
              serverPort = config.port,
              protocolLabel = config.protocol.label,
              currentPingMs = lastPing,
              localProxyPort = proxyPort,
              errorMessage = null,
            )
        }
      }
  }

  private fun stopTunnel(errorMsg: String? = null) {
    keepAliveJob?.cancel()
    keepAliveJob = null
    tunDnsForwarder?.stop()
    tunDnsForwarder = null
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
    keepAliveJob?.cancel()
    tunDnsForwarder?.stop()
    localProxyServer?.stop()
    try {
      vpnInterface?.close()
    } catch (_: Exception) {}
    vpnInterface = null
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
