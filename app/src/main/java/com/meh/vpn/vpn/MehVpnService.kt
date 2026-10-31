package com.meh.vpn.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import com.meh.vpn.MainActivity
import com.meh.vpn.R
import com.meh.vpn.data.GitHubSubscriptionAggregator
import com.meh.vpn.data.V2RayParser
import com.meh.vpn.model.ConnectionStage
import com.meh.vpn.model.V2RayConfig
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.File
import java.util.concurrent.atomic.AtomicBoolean

class MehVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val aggregator = GitHubSubscriptionAggregator()
    private var vpnInterface: ParcelFileDescriptor? = null
    private var localProxyServer: V2RayLocalProxyServer? = null
    private var tunRouter: Tun2V2RayRouter? = null
    private var tunnelJob: Job? = null
    private var watchdogJob: Job? = null

    @Volatile
    private var currentActiveConfig: V2RayConfig? = null
    private val isHealing = AtomicBoolean(false)
    private val healTriggerChannel = Channel<Unit>(Channel.CONFLATED)

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
                    serviceScope.launch {
                        val fallbackConfig = findNextHealthyConfigOrNull(null)
                        if (fallbackConfig != null) {
                            startTunnel(fallbackConfig)
                        } else {
                            stopTunnel()
                        }
                    }
                }
            }
        }
        return START_STICKY
    }

    /**
     * Resolves a new working V2Ray configuration from GitHub when the current config drops or fails.
     * Returns null if all tested nodes fail verification so the VPN can auto-disconnect cleanly.
     */
    private suspend fun findNextHealthyConfigOrNull(failedConfig: V2RayConfig?): V2RayConfig? {
        if (failedConfig != null) {
            V2RayOutboundClient.markNodeDead(failedConfig)
        }

        VpnStateBus.updateStage(ConnectionStage.TESTING_SERVERS, failedConfig)
        val githubConfigs = runCatching { aggregator.fetchAllGitHubConfigs() }.getOrDefault(emptyList())
        if (githubConfigs.isNotEmpty()) {
            val (bestV2Ray, _) = aggregator.findFastestServer(githubConfigs)
            if (bestV2Ray != null) {
                return bestV2Ray
            }
        }
        return null
    }

    private fun startTunnel(initialConfig: V2RayConfig) {
        VpnStateBus.updateStage(ConnectionStage.CONNECTING, initialConfig)
        startVpnForegroundNotification(initialConfig)

        watchdogJob?.cancel()
        tunnelJob?.cancel()
        tunnelJob = serviceScope.launch {
            val livePing = V2RayOutboundClient.verifyRealInternetConnectivity(
                config = initialConfig,
                vpnService = this@MehVpnService,
                timeoutMs = 2600
            )
            val activeConfig: V2RayConfig? = if (livePing in 1..4999) {
                initialConfig.copy(pingMs = livePing)
            } else {
                findNextHealthyConfigOrNull(initialConfig)
            }

            if (activeConfig == null) {
                stopTunnel()
                return@launch
            }

            currentActiveConfig = activeConfig
            persistActiveConfig(activeConfig)
            startVpnForegroundNotification(activeConfig)

            // 1. Start local V2Ray HTTP/HTTPS CONNECT & SOCKS5 Proxy Server
            localProxyServer?.destroy()
            val proxy = V2RayLocalProxyServer(this@MehVpnService, activeConfig)
            proxy.start()
            localProxyServer = proxy

            // 2. Establish full-device Android VPN TUN interface (0.0.0.0/0) + Tun2V2RayRouter
            val tunEstablished = runCatching {
                tunRouter?.destroy()
                vpnInterface?.close()

                val builder = Builder()
                    .setSession("MEH (مه) • ${activeConfig.countryNameFa}")
                    // 1360 MTU prevents cellular GTP packet fragmentation on Irancell/MCI
                    .setMtu(1360)
                    .addAddress("10.0.0.2", 24)
                    // Explicitly route FakeDNS IPv4 range
                    .addRoute("198.18.0.0", 15)
                    // Route all IPv4 traffic through the VPN TUN interface
                    .addRoute("0.0.0.0", 0)
                    // IPv6 ULA address and default route (::/0) to capture dual-stack mobile data on Irancell & MCI
                    // This is CRITICAL: without this, cellular rmnet0 handles IPv6 and leaks all traffic outside VPN!
                    .addAddress("fd00:1::2", 128)
                    .addRoute("::", 0)
                    // Configure well-known trusted public DNS servers so Android netd accepts them without RFC 1918 Private DNS rejection
                    .addDnsServer("8.8.8.8")
                    .addDnsServer("1.1.1.1")
                    .addDnsServer("2001:4860:4860::8888")

                // Prevent our own app's outbound sockets from looping back into TUN
                runCatching { builder.addDisallowedApplication(packageName) }

                val establishedPfd = builder.establish()
                vpnInterface = establishedPfd
                if (establishedPfd != null) {
                    val router = Tun2V2RayRouter(this@MehVpnService, activeConfig)
                    router.start(establishedPfd.fileDescriptor)
                    tunRouter = router
                }
                establishedPfd != null
            }.getOrDefault(false)

            VpnStateBus.updateConnected(config = activeConfig, tunEstablished = tunEstablished)

            // 3. Start Continuous Self-Healing Watchdog to detect mid-session config drops
            startWatchdogLoop(tunEstablished)
        }
    }

    /**
     * Continuously monitors the active VPN tunnel every 15 seconds (or immediately when
     * 3 consecutive outbound stream failures occur) and seamlessly hot-swaps to a new live
     * V2Ray config if open internet access drops.
     */
    private fun startWatchdogLoop(tunEstablished: Boolean) {
        watchdogJob?.cancel()
        V2RayOutboundClient.onTunnelDegradedListener = {
            healTriggerChannel.trySend(Unit)
        }

        watchdogJob = serviceScope.launch {
            while (isActive) {
                withTimeoutOrNull(15_000L) {
                    healTriggerChannel.receive()
                }
                if (!isActive) break

                val configToCheck = currentActiveConfig ?: continue
                if (isHealing.get()) continue

                val isAlive = verifyConfigStillAlive(configToCheck)
                if (!isAlive && isActive) {
                    performHotSwapAutoHeal(configToCheck, tunEstablished)
                }
            }
        }
    }

    private fun verifyConfigStillAlive(config: V2RayConfig): Boolean {
        for (attempt in 0..1) {
            val ping = V2RayOutboundClient.verifyRealInternetConnectivity(
                config = config,
                vpnService = this@MehVpnService,
                timeoutMs = 2600
            )
            if (ping in 1..4999) {
                return true
            }
        }
        return false
    }

    private suspend fun performHotSwapAutoHeal(deadConfig: V2RayConfig, tunEstablished: Boolean) {
        if (!isHealing.compareAndSet(false, true)) return
        try {
            val newConfig = findNextHealthyConfigOrNull(deadConfig)
            if (newConfig == null) {
                stopTunnel()
                return
            }
            currentActiveConfig = newConfig
            persistActiveConfig(newConfig)

            localProxyServer?.updateConfig(newConfig)
            tunRouter?.updateConfig(newConfig)

            startVpnForegroundNotification(newConfig)
            VpnStateBus.updateConnected(config = newConfig, tunEstablished = tunEstablished)
            delay(1500)
        } finally {
            isHealing.set(false)
        }
    }

    private fun persistActiveConfig(config: V2RayConfig) {
        runCatching {
            File(filesDir, "meh_v2ray_active_config.json").writeText(config.toV2RayCoreJson())
            getSharedPreferences("meh_fast_prefs", Context.MODE_PRIVATE)
                .edit()
                .putString("last_best_uri", config.rawUri)
                .putString("last_best_source", config.sourceRepo)
                .apply()
        }
    }

    private fun stopTunnel() {
        V2RayOutboundClient.onTunnelDegradedListener = null
        watchdogJob?.cancel()
        watchdogJob = null
        tunnelJob?.cancel()
        tunnelJob = null
        currentActiveConfig = null
        isHealing.set(false)
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
        const val ACTION_CONNECT = "com.meh.vpn.vpn.ACTION_CONNECT"
        const val ACTION_DISCONNECT = "com.meh.vpn.vpn.ACTION_DISCONNECT"
        const val EXTRA_CONFIG_URI = "extra_config_uri"
        const val EXTRA_SOURCE_REPO = "extra_source_repo"
        const val EXTRA_INITIAL_PING = "extra_initial_ping"
        private const val NOTIFICATION_ID = 2048
    }
}
