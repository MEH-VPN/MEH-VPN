package com.meh.vpn.ui

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.meh.vpn.R
import com.meh.vpn.data.AetherGatewayEngine
import com.meh.vpn.data.GitHubSubscriptionAggregator
import com.meh.vpn.data.MehFirebaseRepository
import com.meh.vpn.data.PatternihaBypassEngine
import com.meh.vpn.data.V2RayParser
import com.meh.vpn.model.ConnectionStage
import com.meh.vpn.model.V2RayConfig
import com.meh.vpn.model.V2RayProtocol
import com.meh.vpn.vpn.V2RayOutboundClient
import com.meh.vpn.vpn.VpnStateBus
import com.google.firebase.FirebaseApp
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.concurrent.atomic.AtomicInteger

data class VpnUiState(
    val stage: ConnectionStage = ConnectionStage.DISCONNECTED,
    val selectedServer: V2RayConfig? = null,
    val progressPercent: Int = 0,
    val testedCount: Int = 0,
    val maxTestCount: Int = VpnViewModel.MAX_TOTAL_TESTS,
    val discoveredCount: Int = 0,
    val scanDetailText: String = ""
)

class VpnViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences("meh_fast_prefs", Context.MODE_PRIVATE)
    private val aggregator = GitHubSubscriptionAggregator()
    private val _uiState = MutableStateFlow(VpnUiState())
    val uiState: StateFlow<VpnUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null
    private val scanSessionId = AtomicInteger(0)

    init {
        ensureFirebaseInitialized()
        logAnalyticsEvent("meh_app_opened")
        observeVpnRuntimeBus()
    }

    private fun ensureFirebaseInitialized() {
        runCatching {
            val appContext = getApplication<Application>()
            if (FirebaseApp.getApps(appContext).isEmpty()) {
                FirebaseApp.initializeApp(appContext)
            }
        }
    }

    private fun observeVpnRuntimeBus() {
        viewModelScope.launch {
            VpnStateBus.runtimeStats.collect { runtime ->
                val previousStage = _uiState.value.stage
                val isScanRunning = scanJob?.isActive == true
                _uiState.update { current ->
                    val resolvedStage = when {
                        runtime.stage == ConnectionStage.CONNECTED -> ConnectionStage.CONNECTED
                        runtime.stage == ConnectionStage.TESTING_SERVERS -> ConnectionStage.TESTING_SERVERS
                        runtime.stage == ConnectionStage.AETHER_FALLBACK -> ConnectionStage.AETHER_FALLBACK
                        runtime.stage == ConnectionStage.SERVERLESS_FALLBACK -> ConnectionStage.SERVERLESS_FALLBACK
                        runtime.stage == ConnectionStage.SNI_SPOOF_FALLBACK -> ConnectionStage.SNI_SPOOF_FALLBACK
                        runtime.stage == ConnectionStage.CONNECTING -> ConnectionStage.CONNECTING
                        isScanRunning && (
                            current.stage == ConnectionStage.FETCHING_SUBSCRIPTIONS ||
                                current.stage == ConnectionStage.TESTING_SERVERS ||
                                current.stage == ConnectionStage.AETHER_FALLBACK ||
                                current.stage == ConnectionStage.SERVERLESS_FALLBACK ||
                                current.stage == ConnectionStage.SNI_SPOOF_FALLBACK
                            ) -> current.stage
                        else -> ConnectionStage.DISCONNECTED
                    }
                    val clearedDetail = if (resolvedStage == ConnectionStage.CONNECTED) "" else current.scanDetailText
                    current.copy(
                        stage = resolvedStage,
                        selectedServer = runtime.activeConfig ?: current.selectedServer,
                        progressPercent = if (resolvedStage == ConnectionStage.CONNECTED) 100 else if (resolvedStage == ConnectionStage.DISCONNECTED) 0 else current.progressPercent,
                        scanDetailText = clearedDetail
                    )
                }

                if (runtime.stage == ConnectionStage.CONNECTED && previousStage != ConnectionStage.CONNECTED) {
                    val cfg = runtime.activeConfig ?: _uiState.value.selectedServer
                    logAnalyticsEvent("meh_vpn_connected") {
                        putString("country", cfg?.countryNameFa?.substringBefore("•")?.trim() ?: "unknown")
                        putString("protocol", cfg?.protocol?.name ?: "unknown")
                        putString("source_repo", cfg?.sourceRepo ?: "unknown")
                        putLong("ping_ms", (cfg?.pingMs ?: 0).toLong())
                    }
                }
            }
        }
    }

    fun findBestServerAndConnect(onReadyToStartService: (V2RayConfig) -> Unit) {
        val sessionId = scanSessionId.incrementAndGet()
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            try {
                logAnalyticsEvent("meh_connect_clicked")

                // =========================================================================
                // Phase 1 (0%..20%): دریافت سریع کانفیگ‌ها از گیت‌هاب و آینه‌های CDN
                // =========================================================================
                _uiState.update {
                    it.copy(
                        stage = ConnectionStage.FETCHING_SUBSCRIPTIONS,
                        progressPercent = 5,
                        testedCount = 0,
                        maxTestCount = MAX_TOTAL_TESTS,
                        discoveredCount = 0,
                        scanDetailText = "در حال دریافت کانفیگ از منابع گیت‌هاب..."
                    )
                }

                val configs = aggregator.fetchAllGitHubConfigs { completedSources, totalSources, totalFound ->
                    if (scanSessionId.get() == sessionId) {
                        val pct = (5 + (completedSources * 15) / totalSources.coerceAtLeast(1)).coerceIn(5, 20)
                        _uiState.update { current ->
                            if (current.stage == ConnectionStage.DISCONNECTED) current
                            else current.copy(
                                progressPercent = pct,
                                discoveredCount = totalFound,
                                scanDetailText = if (totalFound > 0) {
                                    "دریافت $totalFound کانفیگ (منبع $completedSources از $totalSources)"
                                } else {
                                    "بررسی منبع $completedSources از $totalSources..."
                                }
                            )
                        }
                    }
                }

                ensureActive()
                if (scanSessionId.get() != sessionId) return@launch

                // =========================================================================
                // Phase 2 (20%..100%): انتخاب و تست حداکثر ۱۵ کانفیگ برتر (شامل V2Ray + روش‌های جایگزین)
                // در صورت عدم اتصال پس از ۱۵ تست، به صورت خودکار قطع می‌شود.
                // =========================================================================
                _uiState.update {
                    it.copy(
                        stage = ConnectionStage.TESTING_SERVERS,
                        progressPercent = 22,
                        discoveredCount = configs.size,
                        scanDetailText = if (configs.isNotEmpty()) {
                            "${configs.size} کانفیگ دریافت شد • اولویت‌بندی ۱۵ تست برتر..."
                        } else {
                            "آماده‌سازی ۱۵ تست ضد فیلتر..."
                        }
                    )
                }

                val candidateQueue = buildPrioritizedTestQueue(configs, MAX_TOTAL_TESTS)
                val totalToTest = candidateQueue.size.coerceIn(1, MAX_TOTAL_TESTS)

                var verifiedBest: V2RayConfig? = null

                for ((zeroIdx, candidate) in candidateQueue.withIndex()) {
                    ensureActive()
                    if (scanSessionId.get() != sessionId) return@launch

                    val testNumber = zeroIdx + 1
                    val pct = (22 + (testNumber * 76) / totalToTest).coerceIn(24, 98)
                    val stageForCandidate = when (candidate.protocol) {
                        V2RayProtocol.AETHER -> ConnectionStage.AETHER_FALLBACK
                        V2RayProtocol.SERVERLESS -> ConnectionStage.SERVERLESS_FALLBACK
                        V2RayProtocol.SNI_SPOOF -> ConnectionStage.SNI_SPOOF_FALLBACK
                        else -> ConnectionStage.TESTING_SERVERS
                    }
                    val countryOnly = candidate.countryNameFa.substringBefore("•").trim()
                    val methodName = when (candidate.protocol) {
                        V2RayProtocol.AETHER -> "Aether"
                        V2RayProtocol.SERVERLESS -> "Serverless"
                        V2RayProtocol.SNI_SPOOF -> "SNI-Spoof"
                        else -> candidate.protocol.name
                    }

                    _uiState.update {
                        it.copy(
                            stage = stageForCandidate,
                            progressPercent = pct,
                            testedCount = testNumber,
                            maxTestCount = totalToTest,
                            discoveredCount = configs.size,
                            scanDetailText = "تست $testNumber از $totalToTest • بررسی ${candidate.flagEmoji} $countryOnly ($methodName)"
                        )
                    }

                    val ping = withContext(Dispatchers.IO) {
                        V2RayOutboundClient.verifyRealInternetConnectivity(candidate, null, 2000)
                    }

                    ensureActive()
                    if (scanSessionId.get() != sessionId) return@launch

                    if (ping in 1..4999) {
                        verifiedBest = candidate.copy(pingMs = ping)
                        _uiState.update {
                            it.copy(
                                progressPercent = 100,
                                testedCount = testNumber,
                                maxTestCount = totalToTest,
                                scanDetailText = "پیدا شد: ${candidate.flagEmoji} $countryOnly (${ping}ms)"
                            )
                        }
                        break
                    }
                }

                if (verifiedBest == null) {
                    // طبق درخواست کاربر: بعد از ۱۰ الی ۲۰ تست (۱۵ تست) اگر متصل نشد، خودکار قطع شود
                    logAnalyticsEvent("meh_scan_failed_auto_disconnect") {
                        putLong("tested_count", totalToTest.toLong())
                        putLong("discovered_count", configs.size.toLong())
                    }
                    VpnStateBus.resetDisconnected()
                    _uiState.update {
                        VpnUiState(
                            stage = ConnectionStage.DISCONNECTED,
                            selectedServer = null,
                            progressPercent = 0,
                            testedCount = totalToTest,
                            maxTestCount = totalToTest,
                            discoveredCount = configs.size,
                            scanDetailText = "عدم اتصال پس از $totalToTest تست (قطع خودکار)"
                        )
                    }
                    return@launch
                }

                cacheBestServer(verifiedBest)
                val countryOnly = verifiedBest.countryNameFa.substringBefore("•").trim()
                logAnalyticsEvent("meh_server_selected") {
                    putString("country", countryOnly)
                    putString("protocol", verifiedBest.protocol.name)
                    putString("source_repo", verifiedBest.sourceRepo)
                    putLong("ping_ms", verifiedBest.pingMs.toLong())
                }
                runCatching {
                    val app = getApplication<Application>()
                    ensureFirebaseInitialized()
                    if (FirebaseAuth.getInstance().currentUser != null) {
                        val databaseId = app.getString(R.string.firestore_database_id)
                        val db = FirebaseFirestore.getInstance(databaseId)
                        MehFirebaseRepository(db).saveConnectionLog(
                            countryNameFa = countryOnly,
                            flagEmoji = verifiedBest.flagEmoji,
                            rawUri = verifiedBest.rawUri,
                            sourceRepo = verifiedBest.sourceRepo,
                            pingMs = verifiedBest.pingMs.toLong()
                        )
                    }
                }

                // Final Stage: در حال اتصال -> متصل
                _uiState.update {
                    it.copy(
                        stage = ConnectionStage.CONNECTING,
                        selectedServer = verifiedBest,
                        progressPercent = 100
                    )
                }
                onReadyToStartService(verifiedBest)
            } catch (_: CancellationException) {
                // Cancelled by user tap
            }
        }
    }

    /**
     * Builds a bounded queue of at most [maxTests] (15) candidates in strict priority order:
     * 1. Cached last-working server (if available and not blacklisted)
     * 2. Top TCP-reachable GitHub V2Ray configs (VLESS / Trojan)
     * 3. CluvexStudio/Aether gateways
     * 4. patterniha/Serverless-for-Iran candidates
     * 5. patterniha/SNI-Spoofing candidates
     */
    private suspend fun buildPrioritizedTestQueue(
        githubConfigs: List<V2RayConfig>,
        maxTests: Int
    ): List<V2RayConfig> = withContext(Dispatchers.IO) {
        val queue = mutableListOf<V2RayConfig>()

        // 1. Last working cached server for fast initial reconnection on Irancell
        val cachedUri = prefs.getString(KEY_LAST_BEST_URI, null)
        val cachedSource = prefs.getString(KEY_LAST_BEST_SOURCE, "SoliSpirit/v2ray-configs") ?: "GitHub"
        if (!cachedUri.isNullOrBlank()) {
            val parsedCached = V2RayParser.parseSingleUri(cachedUri, cachedSource)
            if (parsedCached != null && !V2RayOutboundClient.isNodeBlacklisted(parsedCached)) {
                queue.add(parsedCached)
            }
        }

        // 2. Top TCP-reachable GitHub V2Ray servers (up to 9 slots)
        if (githubConfigs.isNotEmpty()) {
            val tcpRanked = aggregator.rankTopTcpCandidates(
                configs = githubConfigs,
                maxCandidates = 9,
                timeoutMs = 700
            )
            for (cfg in tcpRanked) {
                if (queue.size < 10 && queue.none { it.address == cfg.address && it.port == cfg.port }) {
                    queue.add(cfg)
                }
            }
        }

        // 3. Method 2: CluvexStudio/Aether candidates (2 slots)
        for (gw in AetherGatewayEngine.defaultAetherGateways.take(4)) {
            if (queue.size >= maxTests - 3) break
            val cfg = AetherGatewayEngine.buildAetherConfig(
                address = gw.address,
                port = gw.port,
                sni = gw.sni,
                countryCode = gw.defaultCountryCode,
                pingMs = 60
            )
            if (!V2RayOutboundClient.isNodeBlacklisted(cfg) &&
                queue.none { it.address == cfg.address && it.port == cfg.port && it.protocol == cfg.protocol }
            ) {
                queue.add(cfg)
            }
        }

        // 4. Method 3: patterniha/Serverless-for-Iran candidates (2 slots)
        for (sc in PatternihaBypassEngine.defaultServerlessCandidates.take(4)) {
            if (queue.size >= maxTests - 1) break
            val cfg = PatternihaBypassEngine.buildServerlessConfig(
                address = sc.address,
                port = sc.port,
                sni = sc.sni,
                countryCode = sc.countryCode,
                pingMs = 55
            )
            if (!V2RayOutboundClient.isNodeBlacklisted(cfg) &&
                queue.none { it.address == cfg.address && it.port == cfg.port && it.protocol == cfg.protocol }
            ) {
                queue.add(cfg)
            }
        }

        // 5. Method 4: patterniha/SNI-Spoofing candidates (remaining slots up to maxTests = 15)
        val spoofDomain = PatternihaBypassEngine.defaultSpoofDomains.first()
        for (sc in PatternihaBypassEngine.defaultServerlessCandidates) {
            if (queue.size >= maxTests) break
            val cfg = PatternihaBypassEngine.buildSniSpoofConfig(
                address = sc.address,
                port = sc.port,
                fakeSni = spoofDomain,
                countryCode = sc.countryCode,
                pingMs = 58
            )
            if (!V2RayOutboundClient.isNodeBlacklisted(cfg) &&
                queue.none { it.address == cfg.address && it.port == cfg.port && it.protocol == cfg.protocol }
            ) {
                queue.add(cfg)
            }
        }

        queue.take(maxTests)
    }

    private fun cacheBestServer(config: V2RayConfig) {
        prefs.edit()
            .putString(KEY_LAST_BEST_URI, config.rawUri)
            .putString(KEY_LAST_BEST_SOURCE, config.sourceRepo)
            .apply()
    }

    fun cancelScanAndReset() {
        scanSessionId.incrementAndGet()
        scanJob?.cancel()
        scanJob = null
        aggregator.cancelAllRequests()
        logAnalyticsEvent("meh_vpn_disconnected")
        VpnStateBus.resetDisconnected()
        _uiState.value = VpnUiState(
            stage = ConnectionStage.DISCONNECTED,
            selectedServer = null,
            progressPercent = 0,
            testedCount = 0,
            maxTestCount = MAX_TOTAL_TESTS,
            discoveredCount = 0,
            scanDetailText = ""
        )
    }

    private fun logAnalyticsEvent(name: String, block: (Bundle.() -> Unit)? = null) {
        runCatching {
            val appContext = getApplication<Application>()
            ensureFirebaseInitialized()
            val bundle = Bundle()
            block?.invoke(bundle)
            FirebaseAnalytics.getInstance(appContext).logEvent(name, bundle)
        }
    }

    companion object {
        const val MAX_TOTAL_TESTS = 15
        private const val KEY_LAST_BEST_URI = "last_best_uri"
        private const val KEY_LAST_BEST_SOURCE = "last_best_source"
    }
}
