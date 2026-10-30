package com.example.ui

import android.content.SharedPreferences
import android.os.Bundle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.GitHubSubscriptionAggregator
import com.example.data.MehFirebaseRepository
import com.example.data.V2RayParser
import com.example.model.ConnectionStage
import com.example.model.V2RayConfig
import com.example.vpn.VpnStateBus
import com.google.firebase.Firebase
import com.google.firebase.analytics.FirebaseAnalytics
import com.google.firebase.analytics.analytics
import com.google.firebase.auth.auth
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

class VpnViewModel(
    private val repository: MehFirebaseRepository,
    private val prefs: SharedPreferences,
    private val analytics: FirebaseAnalytics = Firebase.analytics
) : ViewModel() {

    private val aggregator = GitHubSubscriptionAggregator()
    private val _uiState = MutableStateFlow(VpnUiState())
    val uiState: StateFlow<VpnUiState> = _uiState.asStateFlow()

    private var scanJob: Job? = null

    init {
        logAnalyticsEvent("meh_app_opened")
        observeVpnRuntimeBus()
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
                if (Firebase.auth.currentUser != null) {
                    viewModelScope.launch {
                        repository.saveConnectionLog(
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
            val bundle = Bundle()
            block?.invoke(bundle)
            analytics.logEvent(name, bundle)
        }
    }

    private companion object {
        const val KEY_LAST_BEST_URI = "last_best_uri"
        const val KEY_LAST_BEST_SOURCE = "last_best_source"
    }
}
