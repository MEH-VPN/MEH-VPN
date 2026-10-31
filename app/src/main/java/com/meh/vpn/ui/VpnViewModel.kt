package com.meh.vpn.ui

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.meh.vpn.R
import com.meh.vpn.data.GitHubSubscriptionAggregator
import com.meh.vpn.data.MehFirebaseRepository
import com.meh.vpn.data.V2RayParser
import com.meh.vpn.model.ConnectionStage
import com.meh.vpn.model.V2RayConfig
import com.meh.vpn.vpn.V2RayOutboundClient
import com.meh.vpn.vpn.VpnStateBus
import com.google.firebase.FirebaseApp
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
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
                        runtime.stage == ConnectionStage.CONNECTING -> ConnectionStage.CONNECTING
                        isScanRunning && (
                            current.stage == ConnectionStage.FETCHING_SUBSCRIPTIONS ||
                                current.stage == ConnectionStage.TESTING_SERVERS
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

    /**
     * Fetches V2Ray configs from GitHub repositories, tests up to [MAX_TOTAL_TESTS] top candidates
     * with real end-to-end TLS 443 verification, and connects immediately upon finding a healthy server.
     */
    fun findBestServerAndConnect(onReadyToStartService: (V2RayConfig) -> Unit) {
        val sessionId = scanSessionId.incrementAndGet()
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            try {
                logAnalyticsEvent("meh_connect_clicked")

                // Phase 1 (0%..20%): دریافت سریع کانفیگ‌ها از گیت‌هاب
                _uiState.update {
                    it.copy(
                        stage = ConnectionStage.FETCHING_SUBSCRIPTIONS,
                        progressPercent = 5,
                        testedCount = 0,
                        maxTestCount = MAX_TOTAL_TESTS,
                        discoveredCount = 0,
                        scanDetailText = "دریافت منابع • مخازن گیت‌هاب"
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
                                    "منبع $completedSources از $totalSources • $totalFound کانفیگ"
                                } else {
                                    "بررسی منابع • $completedSources از $totalSources"
                                }
                            )
                        }
                    }
                }

                ensureActive()
                if (scanSessionId.get() != sessionId) return@launch

                // Phase 2 (20%..100%): تست واقعی کانفیگ‌های V2Ray (حداکثر ۱۵ تست)
                _uiState.update {
                    it.copy(
                        stage = ConnectionStage.TESTING_SERVERS,
                        progressPercent = 22,
                        discoveredCount = configs.size,
                        scanDetailText = if (configs.isNotEmpty()) {
                            "${configs.size} کانفیگ • انتخاب $MAX_TOTAL_TESTS تست برتر"
                        } else {
                            "بررسی کانفیگ ذخیره شده"
                        }
                    )
                }

                val candidateQueue = buildPrioritizedTestQueue(configs, MAX_TOTAL_TESTS)
                if (candidateQueue.isEmpty()) {
                    VpnStateBus.resetDisconnected()
                    _uiState.update {
                        it.copy(
                            stage = ConnectionStage.DISCONNECTED,
                            selectedServer = null,
                            progressPercent = 0,
                            scanDetailText = "عدم دریافت کانفیگ • بررسی اینترنت"
                        )
                    }
                    return@launch
                }

                val totalToTest = candidateQueue.size.coerceIn(1, MAX_TOTAL_TESTS)
                var verifiedBest: V2RayConfig? = null
                var testedSoFar = 0

                for (batch in candidateQueue.chunked(3)) {
                    ensureActive()
                    if (scanSessionId.get() != sessionId) return@launch

                    val leadCandidate = batch.first()
                    val nextTestedCount = (testedSoFar + batch.size).coerceAtMost(totalToTest)
                    val pct = (22 + (nextTestedCount * 76) / totalToTest).coerceIn(24, 98)
                    val countryOnly = leadCandidate.countryNameFa.substringBefore("•").trim()

                    _uiState.update {
                        it.copy(
                            stage = ConnectionStage.TESTING_SERVERS,
                            progressPercent = pct,
                            testedCount = nextTestedCount,
                            maxTestCount = totalToTest,
                            discoveredCount = configs.size,
                            scanDetailText = "تست $nextTestedCount از $totalToTest • ${leadCandidate.flagEmoji} $countryOnly (${leadCandidate.protocol.name})"
                        )
                    }

                    val verifiedBatch = withContext(Dispatchers.IO) {
                        coroutineScope {
                            batch.map { candidate ->
                                async {
                                    val ping = V2RayOutboundClient.verifyRealInternetConnectivity(
                                        config = candidate,
                                        vpnService = null,
                                        timeoutMs = 3200
                                    )
                                    if (ping in 1..4999) candidate.copy(pingMs = ping) else null
                                }
                            }.awaitAll().filterNotNull()
                        }
                    }.sortedWith(
                        compareBy<V2RayConfig> { it.countryCode.equals("TR", ignoreCase = true) }
                            .thenBy { it.pingMs }
                    )

                    testedSoFar = nextTestedCount
                    ensureActive()
                    if (scanSessionId.get() != sessionId) return@launch

                    if (verifiedBatch.isNotEmpty()) {
                        val bestInBatch = verifiedBatch.first()
                        val bestCountry = bestInBatch.countryNameFa.substringBefore("•").trim()
                        verifiedBest = bestInBatch
                        _uiState.update {
                            it.copy(
                                progressPercent = 100,
                                testedCount = testedSoFar,
                                maxTestCount = totalToTest,
                                scanDetailText = "پیدا شد (${bestInBatch.pingMs}ms) • ${bestInBatch.flagEmoji} $bestCountry"
                            )
                        }
                        break
                    }
                }

                if (verifiedBest == null) {
                    logAnalyticsEvent("meh_scan_failed_auto_disconnect") {
                        putLong("tested_count", totalToTest.toLong())
                        putLong("discovered_count", configs.size.toLong())
                    }
                    VpnStateBus.resetDisconnected()
                    _uiState.update {
                        it.copy(
                            stage = ConnectionStage.DISCONNECTED,
                            selectedServer = null,
                            progressPercent = 0,
                            testedCount = totalToTest,
                            maxTestCount = totalToTest,
                            discoveredCount = configs.size,
                            scanDetailText = "عدم اتصال • توقف پس از $totalToTest تست"
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

    private suspend fun buildPrioritizedTestQueue(
        githubConfigs: List<V2RayConfig>,
        maxTests: Int
    ): List<V2RayConfig> = withContext(Dispatchers.IO) {
        val queue = mutableListOf<V2RayConfig>()

        fun addUnique(cfg: V2RayConfig) {
            if (queue.size < maxTests &&
                !V2RayOutboundClient.isNodeBlacklisted(cfg) &&
                queue.none { it.address == cfg.address && it.port == cfg.port && it.protocol == cfg.protocol }
            ) {
                queue.add(cfg)
            }
        }

        // 1. Last working cached server (skipping TR nodes so MCI never gets stuck on a cached Turkey node)
        val cachedUri = prefs.getString(KEY_LAST_BEST_URI, null)
        val cachedSource = prefs.getString(KEY_LAST_BEST_SOURCE, "SoliSpirit/v2ray-configs") ?: "GitHub"
        if (!cachedUri.isNullOrBlank()) {
            val parsedCached = V2RayParser.parseSingleUri(cachedUri, cachedSource)
            if (parsedCached != null && !parsedCached.countryCode.equals("TR", ignoreCase = true)) {
                addUnique(parsedCached)
            }
        }

        // 2. Top TCP-reachable GitHub V2Ray servers (prioritizing DE / NL / FI / GB / FR)
        if (githubConfigs.isNotEmpty()) {
            val tcpRanked = aggregator.rankTopTcpCandidates(
                configs = githubConfigs,
                maxCandidates = maxTests,
                timeoutMs = 1100
            )
            for (cfg in tcpRanked) {
                if (queue.size >= maxTests) break
                addUnique(cfg)
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
        logAnalyticsEvent("meh_vpn_disconnected")
        VpnStateBus.resetDisconnected()
        _uiState.update {
            it.copy(
                stage = ConnectionStage.DISCONNECTED,
                selectedServer = null,
                progressPercent = 0,
                testedCount = 0,
                scanDetailText = ""
            )
        }
    }

    private fun logAnalyticsEvent(
        eventName: String,
        paramsBuilder: (Bundle.() -> Unit)? = null
    ) {
        runCatching {
            val appContext = getApplication<Application>()
            ensureFirebaseInitialized()
            val bundle = Bundle().apply {
                paramsBuilder?.invoke(this)
            }
            FirebaseAnalytics.getInstance(appContext).logEvent(eventName, bundle)
        }
    }

    companion object {
        const val MAX_TOTAL_TESTS = 15
        private const val KEY_LAST_BEST_URI = "last_best_uri"
        private const val KEY_LAST_BEST_SOURCE = "last_best_source"
    }
}
