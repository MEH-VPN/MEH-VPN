package com.example.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.example.MainActivity
import com.example.R
import com.example.data.V2RayParser
import com.example.model.ConnectionStage
import com.example.model.V2RayConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import java.io.File

class MehVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var vpnInterface: ParcelFileDescriptor? = null
    private var localProxyServer: V2RayLocalProxyServer? = null
    private var tunRouter: Tun2V2RayRouter? = null
    private var tunnelJob: Job? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopTunnel()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                val rawUri = intent.getStringExtra(EXTRA_CONFIG_URI).orEmpty()
                val sourceRepo = intent.getStringExtra(EXTRA_SOURCE_REPO) ?: "GitHub"
                val initialPing = intent.getIntExtra(EXTRA_INITIAL_PING, 55)
                val parsed = V2RayParser.parseSingleUri(rawUri, sourceRepo)?.copy(pingMs = initialPing)
                if (parsed != null) {
                    startTunnel(parsed)
                } else {
                    stopTunnel()
                }
            }
        }
        return START_STICKY
    }

    private fun startTunnel(config: V2RayConfig) {
        VpnStateBus.updateStage(ConnectionStage.CONNECTING, config)
        startVpnForegroundNotification(config)

        tunnelJob?.cancel()
        tunnelJob = serviceScope.launch {
            runCatching {
                File(filesDir, "meh_v2ray_active_config.json").writeText(config.toV2RayCoreJson())
            }

            // 1. Start local V2Ray HTTP/HTTPS CONNECT & SOCKS5 Proxy Server
            localProxyServer?.destroy()
            val proxy = V2RayLocalProxyServer(this@MehVpnService, config)
            val boundProxyPort = proxy.start()
            localProxyServer = proxy

            // 2. Establish full-device Android VPN TUN interface (0.0.0.0/0) + Tun2V2RayRouter
            val tunEstablished = runCatching {
                tunRouter?.destroy()
                vpnInterface?.close()

                val builder = Builder()
                    .setSession("MEH (مه) • ${config.countryNameFa}")
                    .setMtu(1500)
                    .addAddress("10.0.0.2", 24)
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("8.8.8.8")
                    // Route all IPv4 traffic through the VPN TUN interface
                    .addRoute("0.0.0.0", 0)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", boundProxyPort))
                }

                // Prevent our own app's outbound V2Ray sockets from looping back into TUN
                runCatching { builder.addDisallowedApplication(packageName) }

                val establishedPfd = builder.establish()
                vpnInterface = establishedPfd
                if (establishedPfd != null) {
                    val router = Tun2V2RayRouter(this@MehVpnService, config)
                    router.start(establishedPfd.fileDescriptor)
                    tunRouter = router
                }
                establishedPfd != null
            }.getOrDefault(false)

            VpnStateBus.updateConnected(config = config, tunEstablished = tunEstablished)
        }
    }

    private fun stopTunnel() {
        tunnelJob?.cancel()
        tunnelJob = null
        runCatching { tunRouter?.destroy() }
        tunRouter = null
        runCatching { localProxyServer?.destroy() }
        localProxyServer = null
        runCatching { vpnInterface?.close() }
        vpnInterface = null
        VpnStateBus.resetDisconnected()
        runCatching {
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
        }
    }

    override fun onRevoke() {
        stopTunnel()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun startVpnForegroundNotification(config: V2RayConfig) {
        val channelId = "meh_tunnel_channel"
        val manager = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && manager != null) {
            val channel = NotificationChannel(
                channelId,
                "MEH VPN (مه)",
                NotificationManager.IMPORTANCE_LOW
            )
            manager.createNotificationChannel(channel)
        }

        val openIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingOpen = PendingIntent.getActivity(
            this,
            0,
            openIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val notification: Notification = NotificationCompat.Builder(this, channelId)
            .setSmallIcon(R.drawable.ic_power)
            .setContentTitle("مه (MEH) • متصل به ${config.flagEmoji} ${config.countryNameFa}")
            .setContentText("تونل فعال ${config.protocol.label} (${config.network.uppercase()})")
            .setContentIntent(pendingOpen)
            .setOngoing(true)
            .build()

        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        }
    }

    companion object {
        const val ACTION_CONNECT = "com.example.vpn.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.example.vpn.ACTION_DISCONNECT"
        const val EXTRA_CONFIG_URI = "extra_config_uri"
        const val EXTRA_SOURCE_REPO = "extra_source_repo"
        const val EXTRA_INITIAL_PING = "extra_initial_ping"
        private const val NOTIFICATION_ID = 2048
    }
}
