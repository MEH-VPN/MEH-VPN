package com.example.ui

import android.content.Context
import android.content.Intent
import androidx.core.content.ContextCompat
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.example.data.AppUpdateInfo
import com.example.data.DeadServerStore
import com.example.data.MehConnectionMethod
import com.example.data.UpdateChecker
import com.example.data.SoliSpiritRepository
import com.example.model.V2RayConfig
import com.example.model.V2RayConfigParser
import com.example.telemetry.MehTelemetry
import com.example.vpn.MehVpnService
import com.example.vpn.V2RayOutboundClient
import java.util.ArrayList
import java.util.concurrent.atomic.AtomicLong
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject

enum class MehPhase {
  DISCONNECTED,
  FETCHING_CONFIGS,
  TESTING_SPEED,
  CONNECTING,
  CONNECTED,
  ERROR,
}

enum class HackerLogLevel {
  SYSTEM,
  SOURCE,
  SCAN,
  SUCCESS,
  ERROR,
}

data class HackerLogEntry(
  val id: Long,
  val timestamp: String = "",
  val tag: String = "",
  val message: String,
  val level: HackerLogLevel = HackerLogLevel.SYSTEM,
)

data class MehUiState(
  val phase: MehPhase = MehPhase.DISCONNECTED,
  val liveLogLine: String = "",
  val terminalLogs: List<HackerLogEntry> = emptyList(),
  val selectedConfig: V2RayConfig? = null,
  val lastConnectedConfig: V2RayConfig? = null,
  val activeMethod: MehConnectionMethod? = null,
  val updateInfo: AppUpdateInfo? = null,
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
  private val updateChecker: UpdateChecker = UpdateChecker(),
) : ViewModel() {

  companion object {
    const val LOG_FETCHING = "دریافت لیست سرور ها"
    const val LOG_TESTING = "تست سرور ها"
    const val LOG_CONNECTING = "در حال اتصال"
    const val LOG_CONNECTED = "متصل"
    private const val MAX_LOG_LINES = 5

    private const val PREFS_LAST_SERVER = "meh_last_server_prefs"
    private const val KEY_SAVED_CANDIDATES_JSON = "saved_candidates_json"
  }

  private val _uiState = MutableStateFlow(MehUiState())
  val uiState: StateFlow<MehUiState> = _uiState.asStateFlow()

  private var workflowJob: Job? = null
  private var pendingCandidatesForPermission: List<V2RayConfig> = emptyList()
  private var cachedLastCandidates: List<V2RayConfig> = emptyList()

  /** Candidates of the attempt in flight; persisted as "last server" only once actually connected. */
  private var pendingSave: Pair<Context, List<V2RayConfig>>? = null
  private val logIdGenerator = AtomicLong(1L)

  init {
    checkForUpdates()

    viewModelScope.launch {
      MehVpnService.tunnelSession.collect { session ->
        if (session.isRunning) {
          val wasAlreadyConnected = _uiState.value.phase == MehPhase.CONNECTED
          if (!wasAlreadyConnected) {
            if (_uiState.value.updateInfo == null) {
              checkForUpdates()
            }
            pendingSave?.let { (ctx, list) -> saveLastConnectedCandidates(ctx, list) }
            pendingSave = null
            val cfg = _uiState.value.selectedConfig
            val srvName = cfg?.cleanTitle ?: session.serverName
            MehTelemetry.logServerConnected(
              protocol =
                "${MehConnectionMethod.V2RAY_SOLISPIRIT.badgeLabel}:${session.protocolLabel}",
              serverName = srvName,
              latencyMs = session.currentPingMs,
            )
            appendLogLine(
              message = "متصل به ${session.protocolLabel} (پینگ ${session.currentPingMs}ms)",
              level = HackerLogLevel.SUCCESS,
            )
          }
          _uiState.update { current ->
            current.copy(
              phase = MehPhase.CONNECTED,
              liveLogLine = LOG_CONNECTED,
              lastConnectedConfig = current.selectedConfig ?: current.lastConnectedConfig,
            )
          }
        } else if (session.errorMessage != null) {
          MehTelemetry.logError(
            stage = "vpn_tunnel_session",
            errorMessage = session.errorMessage,
          )
          appendLogLine(
            message = session.errorMessage,
            level = HackerLogLevel.ERROR,
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
              terminalLogs = emptyList(),
              selectedConfig = null,
              activeMethod = null,
            )
          }
        }
      }
    }
  }

  /**
   * Loads the last connected server configuration from `SharedPreferences` so the user can
   * optionally reconnect to it with one tap.
   */
  fun checkForUpdates() {
    viewModelScope.launch {
      runCatching {
        val update = updateChecker.check()
        if (update != null) {
          _uiState.update { it.copy(updateInfo = update) }
        }
      }
    }
  }

  fun dismissUpdate() {
    _uiState.update { it.copy(updateInfo = null) }
  }

  fun loadSavedLastServer(context: Context) {
    try {
      val prefs = context.applicationContext.getSharedPreferences(PREFS_LAST_SERVER, Context.MODE_PRIVATE)
      val rawJson = prefs.getString(KEY_SAVED_CANDIDATES_JSON, null)
      if (rawJson.isNullOrBlank()) return
      val arr = JSONArray(rawJson)
      val restored = mutableListOf<V2RayConfig>()
      for (i in 0 until arr.length()) {
        val obj = arr.optJSONObject(i) ?: continue
        val uri = obj.optString("rawUri", "")
        val parsed = V2RayConfigParser.parseSingleUri(uri) ?: continue
        val ip = obj.optString("resolvedIp", "")
        val profile = obj.optString("fragmentProfile", parsed.fragmentProfile)
        val ciphers = obj.optString("cipherSuites", parsed.cipherSuites)
        val latency = obj.optLong("latencyMs", parsed.latencyMs)
        restored.add(
          parsed.copy(
            resolvedIp = ip,
            fragmentProfile = profile.ifBlank { parsed.fragmentProfile },
            cipherSuites = ciphers.ifBlank { parsed.cipherSuites },
            latencyMs = latency,
          )
        )
      }
      if (restored.isNotEmpty()) {
        cachedLastCandidates = restored.filter { it.endpointKey !in DeadServerStore.deadKeys(context) }
        _uiState.update { current ->
          current.copy(lastConnectedConfig = restored.first())
        }
      }
    } catch (_: Throwable) {}
  }

  private fun saveLastConnectedCandidates(context: Context, candidates: List<V2RayConfig>) {
    if (candidates.isEmpty()) return
    // Accumulate working servers across sessions (up to 20) instead of keeping only
    // the latest pool, so the next connect tries proven servers first.
    val deadKeys = DeadServerStore.deadKeys(context)
    val merged =
      (candidates + cachedLastCandidates)
        .filter { it.endpointKey !in deadKeys }
        .distinctBy { it.endpointKey }
        .take(20)
    cachedLastCandidates = merged
    _uiState.update { current ->
      current.copy(lastConnectedConfig = merged.first())
    }
    try {
      val arr = JSONArray()
      for (cfg in merged) {
        val obj =
          JSONObject().apply {
            put("rawUri", cfg.rawUri)
            put("resolvedIp", cfg.resolvedIp)
            put("fragmentProfile", cfg.fragmentProfile)
            put("cipherSuites", cfg.cipherSuites)
            put("latencyMs", cfg.latencyMs)
          }
        arr.put(obj)
      }
      context.applicationContext
        .getSharedPreferences(PREFS_LAST_SERVER, Context.MODE_PRIVATE)
        .edit()
        .putString(KEY_SAVED_CANDIDATES_JSON, arr.toString())
        .apply()
    } catch (_: Throwable) {}
  }

  /**
   * Appends a line-by-line sub-log below the main stage status (`liveLogLine`),
   * without overwriting the main status text (`دریافت لیست سرور ها`, `تست سرور ها`, `در حال اتصال`, `متصل`).
   */
  private fun appendLogLine(
    message: String,
    level: HackerLogLevel = HackerLogLevel.SYSTEM,
  ) {
    val cleanMsg = message.trim()
    if (cleanMsg.isEmpty()) return
    if (cleanMsg == LOG_FETCHING ||
      cleanMsg == LOG_TESTING ||
      cleanMsg == LOG_CONNECTING ||
      cleanMsg == LOG_CONNECTED
    ) {
      return
    }

    val entry =
      HackerLogEntry(
        id = logIdGenerator.getAndIncrement(),
        message = cleanMsg,
        level = level,
      )
    _uiState.update { current ->
      if (current.terminalLogs.lastOrNull()?.message == cleanMsg) {
        current
      } else {
        val updatedList = (current.terminalLogs + entry).takeLast(MAX_LOG_LINES)
        current.copy(
          terminalLogs = updatedList,
        )
      }
    }
  }

  /**
   * Default action when the central power button is clicked:
   * - If connected or busy -> disconnects / cancels.
   * - If disconnected or error -> ALWAYS starts the default full V2Ray discovery & test pipeline.
   */
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
   * Optional action when the user explicitly chooses to reconnect using the last connected server
   * instead of running the full discovery pipeline.
   */
  fun onConnectWithLastServerClicked(
    context: Context,
    onRequestVpnPermission: (Intent) -> Unit,
  ) {
    if (_uiState.value.isActiveOrBusy) return
    val lastPrimary = _uiState.value.lastConnectedConfig ?: cachedLastCandidates.firstOrNull() ?: return
    val candidatesToUse =
      (if (cachedLastCandidates.isNotEmpty()) cachedLastCandidates else listOf(lastPrimary))
        .filter { it.endpointKey !in DeadServerStore.deadKeys(context) }

    workflowJob?.cancel()
    workflowJob =
      viewModelScope.launch {
        try {
          val deadKeys = DeadServerStore.deadKeys(context)
          MehTelemetry.logConnectAttempt()

          _uiState.update {
            it.copy(
              phase = MehPhase.CONNECTING,
              liveLogLine = LOG_CONNECTING,
              terminalLogs = emptyList(),
              selectedConfig = lastPrimary,
              activeMethod = MehConnectionMethod.V2RAY_SOLISPIRIT,
            )
          }

          appendLogLine(
            message = "اتصال با آخرین سرور (${lastPrimary.protocol.label}) ...",
            level = HackerLogLevel.SYSTEM,
          )

          val resolvedCandidates =
            withContext(Dispatchers.IO) {
              candidatesToUse.map { cfg ->
                if (cfg.resolvedIp.isNotBlank()) {
                  cfg
                } else {
                  val ip = V2RayOutboundClient.resolveEndpointIpv4(cfg.address).orEmpty()
                  cfg.copy(resolvedIp = ip)
                }
              }
            }

          prepareAndStartVpn(
            context = context,
            candidates = resolvedCandidates,
            onRequestVpnPermission = onRequestVpnPermission,
          )
        } catch (ce: CancellationException) {
          throw ce
        } catch (e: Exception) {
          MehTelemetry.logError(
            stage = "connect_last_server",
            errorMessage = e.localizedMessage ?: "Failed to connect with last server",
            throwable = e,
          )
          _uiState.update {
            it.copy(
              phase = MehPhase.ERROR,
              liveLogLine = "",
              terminalLogs = emptyList(),
            )
          }
        }
      }
  }

  /**
   * Primary V2Ray connection pipeline using the latest V2Ray core. Each tier is searched
   * with a pipelined fetch+test: sources are fetched in batches of 4 and each batch is
   * probed the moment it arrives (64 parallel probes, 1500 ms first-pass timeout), so the
   * first passing server connects within seconds instead of after the whole tier downloads.
   * 1. Tier 1: `rzashakeri/v2ray-configs`.
   * 2. Tier 2: Only if Tier 1 yields no working server, the mhcfpTopic subscription.
   * 3. Tier 3: Only if Tier 2 also yields nothing, the remaining subscriptions.
   * 4. Starts the VPN tunnel service with the first passing server (plus up to 4 backups
   *    in the failover pool); the background refinement keeps testing the remaining pool
   *    and upgrades later if a clearly better node appears.
   */
  private fun startV2RayConnectionPipeline(
    context: Context,
    onRequestVpnPermission: (Intent) -> Unit,
  ) {
    workflowJob?.cancel()
    workflowJob =
      viewModelScope.launch {
        try {
          val deadKeys = DeadServerStore.deadKeys(context)
          MehTelemetry.logConnectAttempt()

          // Step 1 (Priority #1): دریافت لیست سرور ها از rzashakeri/v2ray-configs
          _uiState.update {
            it.copy(
              phase = MehPhase.FETCHING_CONFIGS,
              liveLogLine = LOG_FETCHING,
              terminalLogs = emptyList(),
              selectedConfig = null,
              activeMethod = MehConnectionMethod.V2RAY_SOLISPIRIT,
            )
          }

          var verifiedCandidates: List<V2RayConfig> = emptyList()

          _uiState.update {
            it.copy(
              phase = MehPhase.TESTING_SPEED,
              liveLogLine = LOG_TESTING,
            )
          }
          delay(120L)

          verifiedCandidates =
            repository.findFirstPassingFromSources(
              sources = SoliSpiritRepository.PRIMARY_RZASHAKERI_SOURCES,
              prioritizedSavedNodes = cachedLastCandidates.filter { it.endpointKey !in deadKeys },
            excludedEndpointKeys = deadKeys,
              poolSize = 5,
            ) { logLine ->
              appendLogLine(
                message = logLine,
                level = HackerLogLevel.SCAN,
              )
            }

                    // Step 2 (Tier 2): mhcfp — only if Priority #1 yielded no working server
          if (verifiedCandidates.isEmpty()) {
            _uiState.update {
              it.copy(
                phase = MehPhase.TESTING_SPEED,
                liveLogLine = LOG_TESTING,
              )
            }
            delay(120L)

            verifiedCandidates =
              repository.findFirstPassingFromSources(
                sources = SoliSpiritRepository.MHCFP_SOURCES,
                prioritizedSavedNodes = cachedLastCandidates.filter { it.endpointKey !in deadKeys },
            excludedEndpointKeys = deadKeys,
                poolSize = 5,
              ) { logLine ->
                appendLogLine(
                  message = logLine,
                  level = HackerLogLevel.SCAN,
                )
              }
          }

          // Step 3 (Tier 3): فقط در صورتی که سرورهای اولویت اول و دوم وصل نشدند سراغ بقیه ساب‌ها برو
          if (verifiedCandidates.isEmpty()) {
            appendLogLine(
              message = "عدم اتصال سرورهای اولویت اول؛ بررسی مخازن پشتیبان ...",
              level = HackerLogLevel.SOURCE,
            )

            _uiState.update {
              it.copy(
                phase = MehPhase.TESTING_SPEED,
                liveLogLine = LOG_TESTING,
              )
            }
            delay(120L)

            verifiedCandidates =
              repository.findFirstPassingFromSources(
                sources = SoliSpiritRepository.FALLBACK_SOURCES,
                prioritizedSavedNodes = cachedLastCandidates.filter { it.endpointKey !in deadKeys },
            excludedEndpointKeys = deadKeys,
                poolSize = 5,
              ) { logLine ->
                appendLogLine(
                  message = logLine,
                  level = HackerLogLevel.SCAN,
                )
              }
          }

          if (verifiedCandidates.isEmpty()) {
            MehTelemetry.logError(
              stage = "verify_candidates",
              errorMessage = "No responsive V2Ray candidate passed verification",
            )
            _uiState.update {
              it.copy(
                phase = MehPhase.ERROR,
                liveLogLine = "",
                terminalLogs = emptyList(),
              )
            }
            return@launch
          }

          prepareAndStartVpn(
            context = context,
            candidates = (verifiedCandidates + cachedLastCandidates.filter { it.endpointKey !in DeadServerStore.deadKeys(context) }).distinctBy { it.endpointKey },
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
              terminalLogs = emptyList(),
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
          terminalLogs = emptyList(),
        )
      }
    }
  }

  private fun launchVpnService(
    context: Context,
    candidates: List<V2RayConfig>,
  ) {
    val config = candidates.first()
    pendingSave = context.applicationContext to candidates

    appendLogLine(
      message = "راه‌اندازی تونل ارتباطی (${config.protocol.label}) ...",
      level = HackerLogLevel.SYSTEM,
    )

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

    try {
      ContextCompat.startForegroundService(context, intent)
    } catch (e: Exception) {
      MehTelemetry.logError(
        stage = "start_foreground_service",
        errorMessage = e.localizedMessage ?: "Failed to start MehVpnService",
        throwable = e,
      )
    }

    _uiState.update {
      it.copy(
        phase = MehPhase.CONNECTING,
        selectedConfig = config,
        lastConnectedConfig = config,
        activeMethod = MehConnectionMethod.V2RAY_SOLISPIRIT,
        liveLogLine = LOG_CONNECTING,
      )
    }
  }

  /**
   * Manual "next server": asks the running service to switch to the next healthy
   * node. Only while connected; the old node is NOT marked dead (user's choice).
   */
  fun switchToNextServer(context: Context) {
    if (_uiState.value.phase != MehPhase.CONNECTED) return
    val intent =
      Intent(context, MehVpnService::class.java).apply {
        action = MehVpnService.ACTION_SWITCH_SERVER
      }
    context.startService(intent)
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
        terminalLogs = emptyList(),
      )
    }
  }
}
