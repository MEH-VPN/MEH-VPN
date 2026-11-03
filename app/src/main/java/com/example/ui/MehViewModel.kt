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

enum class MethodRunStatus {
  IDLE,
  TESTING,
  CONNECTED,
  FAILED,
}

data class MethodItemState(
  val method: MehConnectionMethod,
  val status: MethodRunStatus = MethodRunStatus.IDLE,
  val statusTextFa: String = "تست",
  val latencyMs: Long? = null,
)

data class MehUiState(
  val phase: MehPhase = MehPhase.DISCONNECTED,
  val liveLogLine: String = "",
  val selectedConfig: V2RayConfig? = null,
  val activeMethod: MehConnectionMethod? = null,
  val isMethodSheetOpen: Boolean = false,
  val methodStates: Map<MehConnectionMethod, MethodItemState> =
    MehConnectionMethod.entries.associateWith { MethodItemState(method = it) },
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
  private var pendingCandidatesForPermission: List<V2RayConfig> = emptyList()
  private var pendingMethodForPermission: MehConnectionMethod? = null

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
              activeMethod = null,
            )
          }
        }
      }
    }
  }

  fun openMethodSheet() {
    _uiState.update { it.copy(isMethodSheetOpen = true) }
  }

  fun closeMethodSheet() {
    _uiState.update { it.copy(isMethodSheetOpen = false) }
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

  /**
   * Automatic sequential connection pipeline:
   * 1. First tries standard V2Ray (`SoliSpirit/v2ray-configs`).
   * 2. If V2Ray fails, automatically falls back through `WhiteDNS`, `CluvexStudio/Aether`,
   *    `GFW-knocker`, and `patterniha` methods in order.
   */
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
              activeMethod = MehConnectionMethod.V2RAY_SOLISPIRIT,
            )
          }

          val orderedMethods = MehConnectionMethod.entries
          var winningCandidates: List<V2RayConfig> = emptyList()
          var winningMethod: MehConnectionMethod = MehConnectionMethod.V2RAY_SOLISPIRIT

          for ((index, method) in orderedMethods.withIndex()) {
            updateMethodState(
              method = method,
              status = MethodRunStatus.TESTING,
              statusTextFa = "در حال تست",
              latencyMs = null,
            )

            if (index == 0) {
              // Primary V2Ray method preserves exact LOG_FETCHING -> LOG_TESTING logs
              val configs = repository.fetchConfigsFromSoliSpirit { _ -> }
              if (configs.isNotEmpty()) {
                MehTelemetry.logConfigsFetched(configs.size)
                _uiState.update {
                  it.copy(
                    phase = MehPhase.TESTING_SPEED,
                    liveLogLine = LOG_TESTING,
                  )
                }
                delay(150L)
                val verified =
                  repository.testAndSelectFastestCandidates(
                    configs = configs,
                    maxCount = 6,
                  ) { _ -> }
                if (verified.isNotEmpty()) {
                  winningCandidates = verified
                  winningMethod = method
                  val ping = verified.first().latencyMs
                  updateMethodState(
                    method = method,
                    status = MethodRunStatus.CONNECTED,
                    statusTextFa = "متصل (${ping}ms)",
                    latencyMs = ping,
                  )
                  break
                }
              }
              updateMethodState(
                method = method,
                status = MethodRunStatus.FAILED,
                statusTextFa = "ناموفق",
                latencyMs = null,
              )
            } else {
              // Sequential fallback through remaining methods
              _uiState.update {
                it.copy(
                  phase = MehPhase.TESTING_SPEED,
                  activeMethod = method,
                  liveLogLine = "تست ${method.titleFa}",
                )
              }
              val candidates =
                repository.executeMethodAndSelectCandidates(
                  method = method,
                  maxCount = 6,
                  onLogUpdate = { log ->
                    _uiState.update { state -> state.copy(liveLogLine = log) }
                  },
                )
              if (candidates.isNotEmpty()) {
                winningCandidates = candidates
                winningMethod = method
                val ping = candidates.first().latencyMs
                updateMethodState(
                  method = method,
                  status = MethodRunStatus.CONNECTED,
                  statusTextFa = "متصل (${ping}ms)",
                  latencyMs = ping,
                )
                break
              } else {
                updateMethodState(
                  method = method,
                  status = MethodRunStatus.FAILED,
                  statusTextFa = "ناموفق",
                  latencyMs = null,
                )
              }
            }
          }

          if (winningCandidates.isEmpty()) {
            MehTelemetry.logError(
              stage = "auto_fallback_pipeline",
              errorMessage = "All connection methods failed to find a responsive candidate",
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
            method = winningMethod,
            candidates = winningCandidates,
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

  /**
   * Called when the user clicks on a specific method inside the methods sheet
   * to test and connect with that individual method.
   */
  fun testAndConnectSingleMethod(
    context: Context,
    method: MehConnectionMethod,
    onRequestVpnPermission: (Intent) -> Unit,
  ) {
    workflowJob?.cancel()
    workflowJob =
      viewModelScope.launch {
        try {
          MehTelemetry.logConnectAttempt()

          // Reset any previously connected method badge to IDLE while testing the chosen method
          _uiState.update { current ->
            val updatedMap = current.methodStates.toMutableMap()
            updatedMap.forEach { (k, v) ->
              if (k != method && v.status == MethodRunStatus.CONNECTED) {
                updatedMap[k] = v.copy(status = MethodRunStatus.IDLE, statusTextFa = "تست")
              }
            }
            updatedMap[method] =
              MethodItemState(
                method = method,
                status = MethodRunStatus.TESTING,
                statusTextFa = "در حال تست",
                latencyMs = null,
              )
            current.copy(
              phase = MehPhase.FETCHING_CONFIGS,
              activeMethod = method,
              liveLogLine =
                if (method == MehConnectionMethod.V2RAY_SOLISPIRIT) {
                  LOG_FETCHING
                } else {
                  "تست ${method.titleFa}"
                },
              methodStates = updatedMap,
            )
          }

          val candidates =
            repository.executeMethodAndSelectCandidates(
              method = method,
              maxCount = 6,
              onLogUpdate = { logMsg ->
                _uiState.update { state ->
                  state.copy(
                    phase = MehPhase.TESTING_SPEED,
                    liveLogLine = logMsg,
                  )
                }
              },
            )

          if (candidates.isEmpty()) {
            updateMethodState(
              method = method,
              status = MethodRunStatus.FAILED,
              statusTextFa = "ناموفق",
              latencyMs = null,
            )
            _uiState.update {
              it.copy(
                phase = MehPhase.ERROR,
                liveLogLine = "",
              )
            }
            return@launch
          }

          val bestPing = candidates.first().latencyMs
          updateMethodState(
            method = method,
            status = MethodRunStatus.CONNECTED,
            statusTextFa = "متصل (${bestPing}ms)",
            latencyMs = bestPing,
          )

          prepareAndStartVpn(
            context = context,
            method = method,
            candidates = candidates,
            onRequestVpnPermission = onRequestVpnPermission,
          )
        } catch (ce: CancellationException) {
          throw ce
        } catch (e: Exception) {
          updateMethodState(
            method = method,
            status = MethodRunStatus.FAILED,
            statusTextFa = "ناموفق",
            latencyMs = null,
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

  private fun updateMethodState(
    method: MehConnectionMethod,
    status: MethodRunStatus,
    statusTextFa: String,
    latencyMs: Long?,
  ) {
    _uiState.update { current ->
      val updated = current.methodStates.toMutableMap()
      updated[method] =
        MethodItemState(
          method = method,
          status = status,
          statusTextFa = statusTextFa,
          latencyMs = latencyMs,
        )
      current.copy(methodStates = updated)
    }
  }

  private fun prepareAndStartVpn(
    context: Context,
    method: MehConnectionMethod,
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
      pendingMethodForPermission = method
      onRequestVpnPermission(prepareIntent)
    } else {
      launchVpnService(context, method, candidates)
    }
  }

  fun onVpnPermissionResult(context: Context, granted: Boolean) {
    val candidates = pendingCandidatesForPermission
    val method = pendingMethodForPermission ?: MehConnectionMethod.V2RAY_SOLISPIRIT
    pendingCandidatesForPermission = emptyList()
    pendingMethodForPermission = null

    if (granted && candidates.isNotEmpty()) {
      launchVpnService(context, method, candidates)
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
    method: MehConnectionMethod,
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

    MehTelemetry.logServerConnected(
      protocol = "${method.badgeLabel}:${config.protocol.label}",
      serverName = config.cleanTitle,
      latencyMs = config.latencyMs,
    )

    updateMethodState(
      method = method,
      status = MethodRunStatus.CONNECTED,
      statusTextFa = "متصل (${config.latencyMs}ms)",
      latencyMs = config.latencyMs,
    )

    _uiState.update {
      it.copy(
        phase = MehPhase.CONNECTED,
        selectedConfig = config,
        activeMethod = method,
        liveLogLine = LOG_CONNECTED,
      )
    }
  }

  private fun disconnectOrCancel(context: Context) {
    workflowJob?.cancel()
    workflowJob = null
    pendingCandidatesForPermission = emptyList()
    pendingMethodForPermission = null

    try {
      val stopIntent =
        Intent(context, MehVpnService::class.java).apply {
          action = MehVpnService.ACTION_DISCONNECT
        }
      context.startService(stopIntent)
    } catch (_: Exception) {}

    MehTelemetry.logDisconnected()

    _uiState.update { current ->
      val resetMethods =
        current.methodStates.mapValues { (m, state) ->
          if (state.status == MethodRunStatus.CONNECTED || state.status == MethodRunStatus.TESTING) {
            MethodItemState(method = m)
          } else {
            state
          }
        }
      current.copy(
        phase = MehPhase.DISCONNECTED,
        selectedConfig = null,
        activeMethod = null,
        liveLogLine = "",
        methodStates = resetMethods,
      )
    }
  }
}
