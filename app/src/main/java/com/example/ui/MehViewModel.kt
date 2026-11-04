package com.example.ui

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.MehConnectionMethod
import com.example.data.SoliSpiritRepository
import com.example.model.V2RayConfig
import com.example.telemetry.MehTelemetry
import com.example.vpn.MehVpnService
import java.util.ArrayList
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
  val activeMethod: MehConnectionMethod? = null,
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
    const val LOG_CONNECTING = "در حال اتصال"
    const val LOG_CONNECTED = "متصل"
  }

  private val _uiState = MutableStateFlow(MehUiState())
  val uiState: StateFlow<MehUiState> = _uiState.asStateFlow()

  private var workflowJob: Job? = null
  private var pendingCandidatesForPermission: List<V2RayConfig> = emptyList()

  init {
    viewModelScope.launch {
      MehVpnService.tunnelSession.collect { session ->
        if (session.isRunning) {
          if (_uiState.value.phase != MehPhase.CONNECTED) {
            val cfg = _uiState.value.selectedConfig
            MehTelemetry.logServerConnected(
              protocol =
                "${MehConnectionMethod.V2RAY_SOLISPIRIT.badgeLabel}:${session.protocolLabel}",
              serverName = cfg?.cleanTitle ?: session.serverName,
              latencyMs = session.currentPingMs,
            )
          }
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
              activeMethod = null,
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
      startV2RayConnectionPipeline(context, onRequestVpnPermission)
    }
  }

  /**
   * Primary V2Ray connection pipeline using the latest V2Ray core:
   * 1. Fetches configs from `SoliSpirit/v2ray-configs`.
   * 2. Benchmarks and selects the fastest verified candidates.
   * 3. Starts the VPN tunnel service.
   */
  private fun startV2RayConnectionPipeline(
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
              activeMethod = MehConnectionMethod.V2RAY_SOLISPIRIT,
            )
          }

          val configs = repository.fetchConfigsFromSoliSpirit { _ -> }
          if (configs.isEmpty()) {
            MehTelemetry.logError(
              stage = "fetch_configs",
              errorMessage = "No V2Ray configs fetched",
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
          delay(150L)

          val verifiedCandidates =
            repository.testAndSelectFastestCandidates(
              configs = configs,
              maxCount = 6,
            ) { _ -> }

          if (verifiedCandidates.isEmpty()) {
            MehTelemetry.logError(
              stage = "verify_candidates",
              errorMessage = "No responsive V2Ray candidate passed verification",
            )
            _uiState.update {
              it.copy(
                phase = MehPhase.ERROR,
                liveLogLine = "",
              )
            }
            return@launch
          }

          prepareAndStartVpn(
            context = context,
            candidates = verifiedCandidates,
            onRequestVpnPermission = onRequestVpnPermission,
          )
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

  private fun prepareAndStartVpn(
    context: Context,
    candidates: List<V2RayConfig>,
    onRequestVpnPermission: (Intent) -> Unit,
  ) {
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
      pendingCandidatesForPermission = candidates
      onRequestVpnPermission(prepareIntent)
    } else {
      launchVpnService(context, candidates)
    }
  }

  fun onVpnPermissionResult(context: Context, granted: Boolean) {
    val candidates = pendingCandidatesForPermission
    pendingCandidatesForPermission = emptyList()

    if (granted && candidates.isNotEmpty()) {
      launchVpnService(context, candidates)
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

  private fun launchVpnService(
    context: Context,
    candidates: List<V2RayConfig>,
  ) {
    val config = candidates.first()
    val intent =
      Intent(context, MehVpnService::class.java).apply {
        action = MehVpnService.ACTION_CONNECT
        putExtra(MehVpnService.EXTRA_RAW_URI, config.rawUri)
        putExtra(MehVpnService.EXTRA_RESOLVED_IP, config.resolvedIp)
        putExtra(MehVpnService.EXTRA_FRAGMENT_PROFILE, config.fragmentProfile)
        putExtra(MehVpnService.EXTRA_CIPHER_SUITES, config.cipherSuites)
        putStringArrayListExtra(
          MehVpnService.EXTRA_CANDIDATE_URIS,
          ArrayList(candidates.map { it.rawUri }),
        )
        putStringArrayListExtra(
          MehVpnService.EXTRA_CANDIDATE_IPS,
          ArrayList(candidates.map { it.resolvedIp }),
        )
        putStringArrayListExtra(
          MehVpnService.EXTRA_CANDIDATE_PROFILES,
          ArrayList(candidates.map { it.fragmentProfile }),
        )
        putStringArrayListExtra(
          MehVpnService.EXTRA_CANDIDATE_CIPHERS,
          ArrayList(candidates.map { it.cipherSuites }),
        )
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

    // Do not report "connected" yet: the service publishes `isRunning = true` through
    // `MehVpnService.tunnelSession` only after the TUN and tun2socks are really up, and the
    // collector in `init` then flips the phase to CONNECTED (or ERROR if startup failed).
    _uiState.update {
      it.copy(
        phase = MehPhase.CONNECTING,
        selectedConfig = config,
        activeMethod = MehConnectionMethod.V2RAY_SOLISPIRIT,
        liveLogLine = LOG_CONNECTING,
      )
    }
  }

  private fun disconnectOrCancel(context: Context) {
    workflowJob?.cancel()
    workflowJob = null
    pendingCandidatesForPermission = emptyList()

    try {
      val stopIntent =
        Intent(context, MehVpnService::class.java).apply {
          action = MehVpnService.ACTION_DISCONNECT
        }
      context.startService(stopIntent)
    } catch (_: Exception) {}

    MehTelemetry.logDisconnected()

    _uiState.update { current ->
      current.copy(
        phase = MehPhase.DISCONNECTED,
        selectedConfig = null,
        activeMethod = null,
        liveLogLine = "",
      )
    }
  }
}
