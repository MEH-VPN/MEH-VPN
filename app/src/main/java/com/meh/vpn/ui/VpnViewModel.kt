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
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class VpnUiState(
    val stage: ConnectionStage = ConnectionStage.DISCONNECTED,
    val selectedServer: V2RayConfig? = null
)

class VpnViewModel(application: Application) : AndroidViewModel(application) {

    private val prefs = application.getSharedPreferences("meh_fast_prefs", Context.MODE_PRIVATE)
    private val aggregator = GitHubSubscriptionAggregator()
    private val _uiState = MutableStateFlow(VpnUiState())
    val uiState: StateFlow<VpnUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null

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
                _uiState.update { current ->
                    val resolvedStage = when {
                        runtime.stage == ConnectionStage.CONNECTED -> ConnectionStage.CONNECTED
                        runtime.stage == ConnectionStage.AETHER_FALLBACK -> ConnectionStage.AETHER_FALLBACK
                        runtime.stage == ConnectionStage.SERVERLESS_FALLBACK -> ConnectionStage.SERVERLESS_FALLBACK
                        runtime.stage == ConnectionStage.SNI_SPOOF_FALLBACK -> ConnectionStage.SNI_SPOOF_FALLBACK
                        runtime.stage == ConnectionStage.CONNECTING -> ConnectionStage.CONNECTING
                        current.stage == ConnectionStage.FETCHING_SUBSCRIPTIONS ||
                            current.stage == ConnectionStage.TESTING_SERVERS ||
                            current.stage == ConnectionStage.AETHER_FALLBACK ||
                            current.stage == ConnectionStage.SERVERLESS_FALLBACK ||
                            current.stage == ConnectionStage.SNI_SPOOF_FALLBACK -> current.stage
                        else -> ConnectionStage.DISCONNECTED
                    }
                    current.copy(
                        stage = resolvedStage,
                        selectedServer = runtime.activeConfig ?: current.selectedServer
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
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
            logAnalyticsEvent("meh_connect_clicked")

            // =========================================================================
            // Method 1: دریافت کانفیگ و تست کانفیگ از گیت‌هاب (GitHub V2Ray Configs)
            // =========================================================================
            _uiState.update { it.copy(stage = ConnectionStage.FETCHING_SUBSCRIPTIONS) }
            val configs = aggregator.fetchAllGitHubConfigs()
            delay(200)

            var selectedConfig: V2RayConfig? = null
            if (configs.isNotEmpty()) {
                _uiState.update { it.copy(stage = ConnectionStage.TESTING_SERVERS) }
                val (bestServer, _) = aggregator.findFastestServer(configs)
                selectedConfig = bestServer
            }

            if (selectedConfig == null) {
                val cachedUri = prefs.getString(KEY_LAST_BEST_URI, null)
                val cachedSource = prefs.getString(KEY_LAST_BEST_SOURCE, "SoliSpirit/v2ray-configs") ?: "GitHub"
                if (!cachedUri.isNullOrBlank()) {
                    val parsedCached = V2RayParser.parseSingleUri(cachedUri, cachedSource)
                    if (parsedCached != null &&
                        (parsedCached.protocol == V2RayProtocol.VLESS || parsedCached.protocol == V2RayProtocol.TROJAN)
                    ) {
                        val ping = withContext(Dispatchers.IO) {
                            V2RayOutboundClient.verifyRealInternetConnectivity(parsedCached, null, 2000)
                        }
                        if (ping in 1..4999) {
                            selectedConfig = parsedCached.copy(pingMs = ping)
                        }
                    }
                }
            }

            // =========================================================================
            // Method 2: CluvexStudio/Aether (در صورت وصل نشدن روش اول)
            // =========================================================================
            if (selectedConfig == null) {
                logAnalyticsEvent("meh_aether_fallback_started")
                _uiState.update { it.copy(stage = ConnectionStage.AETHER_FALLBACK) }
                delay(200)
                selectedConfig = AetherGatewayEngine.discoverAndValidateGatewayOrNull()
            }

            // =========================================================================
            // Method 3: patterniha/Serverless-for-Iran (در صورت وصل نشدن روش دوم)
            // =========================================================================
            if (selectedConfig == null) {
                logAnalyticsEvent("meh_serverless_fallback_started")
                _uiState.update { it.copy(stage = ConnectionStage.SERVERLESS_FALLBACK) }
                delay(200)
                selectedConfig = PatternihaBypassEngine.discoverAndValidateServerlessOrNull()
            }

            // =========================================================================
            // Method 4: patterniha/SNI-Spoofing (در صورت وصل نشدن روش سوم)
            // =========================================================================
            val resolvedBest: V2RayConfig = selectedConfig ?: run {
                logAnalyticsEvent("meh_sni_spoof_fallback_started")
                _uiState.update { it.copy(stage = ConnectionStage.SNI_SPOOF_FALLBACK) }
                delay(200)
                PatternihaBypassEngine.discoverAndValidateSniSpoofing()
            }

            cacheBestServer(resolvedBest)
            val countryOnly = resolvedBest.countryNameFa.substringBefore("•").trim()
            logAnalyticsEvent("meh_server_selected") {
                putString("country", countryOnly)
                putString("protocol", resolvedBest.protocol.name)
                putString("source_repo", resolvedBest.sourceRepo)
                putLong("ping_ms", resolvedBest.pingMs.toLong())
            }
            runCatching {
                val app = getApplication<Application>()
                ensureFirebaseInitialized()
                if (FirebaseAuth.getInstance().currentUser != null) {
                    val databaseId = app.getString(R.string.firestore_database_id)
                    val db = FirebaseFirestore.getInstance(databaseId)
                    MehFirebaseRepository(db).saveConnectionLog(
                        countryNameFa = countryOnly,
                        flagEmoji = resolvedBest.flagEmoji,
                        rawUri = resolvedBest.rawUri,
                        sourceRepo = resolvedBest.sourceRepo,
                        pingMs = resolvedBest.pingMs.toLong()
                    )
                }
            }

            // Final Stage: در حال اتصال -> متصل
            _uiState.update {
                it.copy(
                    stage = ConnectionStage.CONNECTING,
                    selectedServer = resolvedBest
                )
            }
            onReadyToStartService(resolvedBest)
        }
    }

    private fun cacheBestServer(config: V2RayConfig) {
        prefs.edit()
            .putString(KEY_LAST_BEST_URI, config.rawUri)
            .putString(KEY_LAST_BEST_SOURCE, config.sourceRepo)
            .apply()
    }

    fun cancelScanAndReset() {
        scanJob?.cancel()
        logAnalyticsEvent("meh_vpn_disconnected")
        VpnStateBus.resetDisconnected()
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

    private companion object {
        const val KEY_LAST_BEST_URI = "last_best_uri"
        const val KEY_LAST_BEST_SOURCE = "last_best_source"
    }
}
