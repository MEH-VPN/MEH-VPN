package com.example.ui

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.SoliSpiritRepository
import com.example.model.V2RayConfig
import com.example.telemetry.MehTelemetry
import com.example.vpn.MehVpnService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch

enum class MehPhase {
  DISCONNECTED,
  FETCHING_CONFIGS,
  TESTING_SPEED,
  CONNECTING,
  CONNECTED,
  ERROR,
}

data class MehUiState(
  val phase: MehPhase = MehPhase.DISCONNECTED,
  val liveLogLine: String = "",
  val selectedConfig: V2RayConfig? = null,
) {
  val isBusy: Boolean
    get() =
      phase == MehPhase.FETCHING_CONFIGS ||
        phase == MehPhase.TESTING_SPEED ||
        phase == MehPhase.CONNECTING

  val isActiveOrBusy: Boolean
    get() = isBusy || phase == MehPhase.CONNECTED
}

class MehViewModel(
  private val repository: SoliSpiritRepository = SoliSpiritRepository(),
) : ViewModel() {

  companion object {
    const val LOG_FETCHING = "دریافت لیست سرور ها"
    const val LOG_TESTING = "تست سرور ها"
    const val LOG_CONNECTED = "متصل"
  }

  private val _uiState = MutableStateFlow(MehUiState())
  val uiState: StateFlow<MehUiState> = _uiState.asStateFlow()

  private var workflowJob: Job? = null
  private var pendingConfigForPermission: V2RayConfig? = null

  init {
    viewModelScope.launch {
      MehVpnService.tunnelSession.collect { session ->
        if (session.isRunning) {
          _uiState.update { current ->
            current.copy(
              phase = MehPhase.CONNECTED,
              liveLogLine = LOG_CONNECTED,
            )
          }
        } else if (session.errorMessage != null) {
          MehTelemetry.logError(
            stage = "vpn_tunnel_session",
            errorMessage = session.errorMessage,
          )
          _uiState.update { current ->
            current.copy(
              phase = MehPhase.ERROR,
              liveLogLine = "",
            )
          }
        } else if (_uiState.value.phase == MehPhase.CONNECTED) {
          _uiState.update { current ->
            current.copy(
              phase = MehPhase.DISCONNECTED,
              liveLogLine = "",
              selectedConfig = null,
            )
          }
        }
      }
    }
  }

  fun onPowerButtonClicked(
    context: Context,
    onRequestVpnPermission: (Intent) -> Unit,
  ) {
    val currentPhase = _uiState.value.phase
    if (currentPhase == MehPhase.CONNECTED || _uiState.value.isBusy) {
      disconnectOrCancel(context)
    } else {
      startAutoConnectPipeline(context, onRequestVpnPermission)
    }
  }

  private fun startAutoConnectPipeline(
    context: Context,
    onRequestVpnPermission: (Intent) -> Unit,
  ) {
    workflowJob?.cancel()
    workflowJob =
      viewModelScope.launch {
        try {
          MehTelemetry.logConnectAttempt()

          // Stage 1: دریافت لیست سرور ها
          _uiState.update {
            it.copy(
              phase = MehPhase.FETCHING_CONFIGS,
              liveLogLine = LOG_FETCHING,
              selectedConfig = null,
            )
          }

          val configs = repository.fetchConfigsFromSoliSpirit { _ -> }

          if (configs.isEmpty()) {
            MehTelemetry.logError(
              stage = "fetch_configs",
              errorMessage = "Empty config list returned from SoliSpirit/v2ray-configs",
            )
            _uiState.update {
              it.copy(
                phase = MehPhase.ERROR,
                liveLogLine = "",
              )
            }
            return@launch
          }

          MehTelemetry.logConfigsFetched(configs.size)

          // Stage 2: تست سرور ها
          _uiState.update {
            it.copy(
              phase = MehPhase.TESTING_SPEED,
              liveLogLine = LOG_TESTING,
            )
          }
          delay(200L)

          val fastestConfig = repository.testAndSelectFastest(configs) { _ -> }

          if (fastestConfig == null) {
            MehTelemetry.logError(
              stage = "speed_test",
              errorMessage = "No responsive V2Ray server found among ${configs.size} configs",
            )
            _uiState.update {
              it.copy(
                phase = MehPhase.ERROR,
                liveLogLine = "",
              )
            }
            return@launch
          }

          val prepareIntent =
            try {
              android.net.VpnService.prepare(context)
            } catch (e: Exception) {
              MehTelemetry.logError(
                stage = "vpn_prepare",
                errorMessage = e.localizedMessage ?: "VpnService.prepare failed",
                throwable = e,
              )
              null
            }

          if (prepareIntent != null) {
            pendingConfigForPermission = fastestConfig
            onRequestVpnPermission(prepareIntent)
          } else {
            launchVpnService(context, fastestConfig)
          }
        } catch (ce: CancellationException) {
          throw ce
        } catch (e: Exception) {
          MehTelemetry.logError(
            stage = "connect_pipeline",
            errorMessage = e.localizedMessage ?: "Unexpected pipeline error",
            throwable = e,
          )
          _uiState.update {
            it.copy(
              phase = MehPhase.ERROR,
              liveLogLine = "",
            )
          }
        }
      }
  }

  fun onVpnPermissionResult(context: Context, granted: Boolean) {
    val config = pendingConfigForPermission
    pendingConfigForPermission = null

    if (granted && config != null) {
      launchVpnService(context, config)
    } else {
      MehTelemetry.logError(
        stage = "vpn_permission",
        errorMessage = "User declined Android VPN permission dialog",
      )
      _uiState.update {
        it.copy(
          phase = MehPhase.DISCONNECTED,
          liveLogLine = "",
        )
      }
    }
  }

  private fun launchVpnService(context: Context, config: V2RayConfig) {
    val intent =
      Intent(context, MehVpnService::class.java).apply {
        action = MehVpnService.ACTION_CONNECT
        putExtra(MehVpnService.EXTRA_RAW_URI, config.rawUri)
        putExtra(MehVpnService.EXTRA_SERVER_NAME, config.cleanTitle)
        putExtra(MehVpnService.EXTRA_SERVER_ADDRESS, config.address)
        putExtra(MehVpnService.EXTRA_SERVER_PORT, config.port)
        putExtra(MehVpnService.EXTRA_PROTOCOL_LABEL, config.protocol.label)
        putExtra(MehVpnService.EXTRA_INITIAL_PING, config.latencyMs)
        putExtra(MehVpnService.EXTRA_CORE_JSON, config.toV2RayCoreJson())
      }

    // Stage 3: متصل
    try {
      ContextCompat.startForegroundService(context, intent)
    } catch (e: Exception) {
      MehTelemetry.logError(
        stage = "start_foreground_service",
        errorMessage = e.localizedMessage ?: "Failed to start MehVpnService",
        throwable = e,
      )
    }

    MehTelemetry.logServerConnected(
      protocol = config.protocol.label,
      serverName = config.cleanTitle,
      latencyMs = config.latencyMs,
    )

    _uiState.update {
      it.copy(
        phase = MehPhase.CONNECTED,
        selectedConfig = config,
        liveLogLine = LOG_CONNECTED,
      )
    }
  }

  private fun disconnectOrCancel(context: Context) {
    workflowJob?.cancel()
    workflowJob = null
    pendingConfigForPermission = null

    try {
      val stopIntent =
        Intent(context, MehVpnService::class.java).apply {
          action = MehVpnService.ACTION_DISCONNECT
        }
      context.startService(stopIntent)
    } catch (_: Exception) {}

    MehTelemetry.logDisconnected()

    _uiState.update {
      it.copy(
        phase = MehPhase.DISCONNECTED,
        selectedConfig = null,
        liveLogLine = "",
      )
    }
  }
}
