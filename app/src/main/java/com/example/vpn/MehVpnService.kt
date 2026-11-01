package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.telemetry.MehTelemetry
import java.io.File
import java.net.InetSocketAddress
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
import kotlin.system.measureNanoTime

data class VpnTunnelSession(
  val isRunning: Boolean = false,
  val serverName: String = "",
  val serverAddress: String = "",
  val serverPort: Int = 0,
  val protocolLabel: String = "",
  val currentPingMs: Long = 0L,
  val errorMessage: String? = null,
)

class MehVpnService : VpnService() {

  private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
  private var vpnInterface: ParcelFileDescriptor? = null
  private var keepAliveJob: Job? = null

  override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
    when (intent?.action) {
      ACTION_DISCONNECT -> {
        stopTunnel()
        return START_NOT_STICKY
      }
      ACTION_CONNECT -> {
        val serverName = intent.getStringExtra(EXTRA_SERVER_NAME) ?: "V2Ray Server"
        val serverAddress = intent.getStringExtra(EXTRA_SERVER_ADDRESS) ?: ""
        val serverPort = intent.getIntExtra(EXTRA_SERVER_PORT, 443)
        val protocolLabel = intent.getStringExtra(EXTRA_PROTOCOL_LABEL) ?: "VLESS"
        val initialPing = intent.getLongExtra(EXTRA_INITIAL_PING, 50L)
        val coreJson = intent.getStringExtra(EXTRA_CORE_JSON) ?: "{}"

        if (serverAddress.isBlank()) {
          stopTunnel("آدرس سرور نامعتبر است")
          return START_NOT_STICKY
        }

        startTunnel(
          serverName = serverName,
          serverAddress = serverAddress,
          serverPort = serverPort,
          protocolLabel = protocolLabel,
          initialPing = initialPing,
          coreJson = coreJson,
        )
        return START_STICKY
      }
      else -> return START_NOT_STICKY
    }
  }

  private fun startTunnel(
    serverName: String,
    serverAddress: String,
    serverPort: Int,
    protocolLabel: String,
    initialPing: Long,
    coreJson: String,
  ) {
    try {
      createNotificationChannel()
      val notification = buildForegroundNotification(serverName, initialPing)
      startForeground(NOTIFICATION_ID, notification)

      // Persist the active V2Ray JSON config in internal filesDir
      File(filesDir, "active_v2ray_config.json").writeText(coreJson)

      vpnInterface?.close()
      val builder =
        Builder()
          .setSession("MEH • $serverName")
          .setMtu(1500)
          .addAddress("10.10.14.2", 24)
          .addDnsServer("1.1.1.1")
          .addDnsServer("8.8.8.8")

      if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        builder.setMetered(false)
      }

      // Exclude our own package from routing loops if needed, and establish the TUN interface
      vpnInterface = builder.establish()

      _tunnelSession.value =
        VpnTunnelSession(
          isRunning = true,
          serverName = serverName,
          serverAddress = serverAddress,
          serverPort = serverPort,
          protocolLabel = protocolLabel,
          currentPingMs = initialPing,
          errorMessage = null,
        )

      startProtectedKeepAliveProbe(serverName, serverAddress, serverPort, protocolLabel, initialPing)
    } catch (e: Exception) {
      MehTelemetry.logError(
        stage = "vpn_tunnel_establish",
        errorMessage = e.localizedMessage ?: "Failed to establish TUN interface",
        throwable = e,
      )
      stopTunnel("خطا در راه‌اندازی تونل VPN: ${e.localizedMessage ?: "نامشخص"}")
    }
  }

  /**
   * Periodically probes the connected V2Ray server over a VPN-protected socket (`protect(socket)`)
   * to keep the live ping log accurate while the tunnel is active.
   */
  private fun startProtectedKeepAliveProbe(
    serverName: String,
    serverAddress: String,
    serverPort: Int,
    protocolLabel: String,
    initialPing: Long,
  ) {
    keepAliveJob?.cancel()
    keepAliveJob =
      serviceScope.launch {
        var lastPing = initialPing
        while (isActive) {
          delay(6000L)
          val measuredPing =
            try {
              val nanos =
                measureNanoTime {
                  Socket().use { socket ->
                    protect(socket)
                    socket.tcpNoDelay = true
                    socket.soTimeout = 2000
                    socket.connect(InetSocketAddress(serverAddress, serverPort), 2000)
                  }
                }
              (nanos / 1_000_000L).coerceAtLeast(1L)
            } catch (_: Exception) {
              lastPing
            }
          lastPing = measuredPing
          _tunnelSession.value =
            VpnTunnelSession(
              isRunning = true,
              serverName = serverName,
              serverAddress = serverAddress,
              serverPort = serverPort,
              protocolLabel = protocolLabel,
              currentPingMs = lastPing,
              errorMessage = null,
            )
        }
      }
  }

  private fun stopTunnel(errorMsg: String? = null) {
    keepAliveJob?.cancel()
    keepAliveJob = null
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
      .setSmallIcon(R.drawable.ic_launcher_foreground)
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
