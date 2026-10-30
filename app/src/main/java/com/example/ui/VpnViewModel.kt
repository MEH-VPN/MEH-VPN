package com.example.ui

import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.R
import com.example.data.GitHubSubscriptionAggregator
import com.example.data.MehFirebaseRepository
import com.example.data.V2RayParser
import com.example.model.ConnectionStage
import com.example.model.V2RayConfig
import com.example.vpn.VpnStateBus
import com.google.firebase.FirebaseApp
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.auth.FirebaseAuth
import com.google.firebase.firestore.FirebaseFirestore
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

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
                        runtime.stage == ConnectionStage.CONNECTING -> ConnectionStage.CONNECTING
                        current.stage == ConnectionStage.FETCHING_SUBSCRIPTIONS ||
                            current.stage == ConnectionStage.TESTING_SERVERS -> current.stage
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

            // Stage 1: دریافت کانفیگ (Fetching configs from GitHub)
            _uiState.update { it.copy(stage = ConnectionStage.FETCHING_SUBSCRIPTIONS) }
            val configs = aggregator.fetchAllGitHubConfigs()
            delay(250)

            // Stage 2: تست کانفیگ (Testing configs to pick the fastest server)
            _uiState.update { it.copy(stage = ConnectionStage.TESTING_SERVERS) }
            val (bestServer, _) = aggregator.findFastestServer(configs)
            delay(250)

            val resolvedBest = bestServer ?: run {
                val cachedUri = prefs.getString(KEY_LAST_BEST_URI, null)
                val cachedSource = prefs.getString(KEY_LAST_BEST_SOURCE, "SoliSpirit/v2ray-configs") ?: "GitHub"
                if (!cachedUri.isNullOrBlank()) {
                    V2RayParser.parseSingleUri(cachedUri, cachedSource)
                } else {
                    null
                }
            }

            if (resolvedBest != null) {
                cacheBestServer(resolvedBest)
                val countryOnly = resolvedBest.countryNameFa.substringBefore("•").trim()
                logAnalyticsEvent("meh_server_selected") {
                    putString("country", countryOnly)
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
                // Stage 3: در حال اتصال (Connecting to best server)
                _uiState.update {
                    it.copy(
                        stage = ConnectionStage.CONNECTING,
                        selectedServer = resolvedBest
                    )
                }
                onReadyToStartService(resolvedBest)
            } else {
                logAnalyticsEvent("meh_connect_failed")
                _uiState.update { it.copy(stage = ConnectionStage.DISCONNECTED) }
            }
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
