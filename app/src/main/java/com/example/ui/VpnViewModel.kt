package com.example.ui

import android.app.Application
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.GitHubSubscriptionAggregator
import com.example.data.V2RayParser
import com.example.model.ConnectionStage
import com.example.model.V2RayConfig
import com.example.vpn.MehVpnService
import com.example.vpn.VpnStateBus
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

    companion object {
        private const val KEY_LAST_BEST_URI = "last_best_uri"
        private const val KEY_LAST_BEST_SOURCE = "last_best_source"
    }

    init {
        observeVpnRuntimeBus()
    }

    private fun observeVpnRuntimeBus() {
        viewModelScope.launch {
            VpnStateBus.runtimeStats.collect { runtime ->
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
            }
        }
    }

    fun findBestServerAndConnect(onReadyToStartService: (V2RayConfig) -> Unit) {
        scanJob?.cancel()
        scanJob = viewModelScope.launch {
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
                if (!cachedUri.isNullOrBlank()) V2RayParser.parseSingleUri(cachedUri, cachedSource) else null
            }

            if (resolvedBest != null) {
                cacheBestServer(resolvedBest)
                // Stage 3: در حال اتصال (Connecting to best server)
                _uiState.update {
                    it.copy(
                        stage = ConnectionStage.CONNECTING,
                        selectedServer = resolvedBest
                    )
                }
                onReadyToStartService(resolvedBest)
            } else {
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

    fun startVpnTunnelService(config: V2RayConfig) {
        val app = getApplication<Application>()
        val intent = Intent(app, MehVpnService::class.java).apply {
            action = MehVpnService.ACTION_CONNECT
            putExtra(MehVpnService.EXTRA_CONFIG_URI, config.rawUri)
            putExtra(MehVpnService.EXTRA_SOURCE_REPO, config.sourceRepo)
            putExtra(MehVpnService.EXTRA_INITIAL_PING, config.pingMs)
        }
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                app.startForegroundService(intent)
            } else {
                app.startService(intent)
            }
        }
    }

    fun disconnectVpnTunnel() {
        scanJob?.cancel()
        val app = getApplication<Application>()
        val intent = Intent(app, MehVpnService::class.java).apply {
            action = MehVpnService.ACTION_DISCONNECT
        }
        runCatching { app.startService(intent) }
        VpnStateBus.resetDisconnected()
    }
}
