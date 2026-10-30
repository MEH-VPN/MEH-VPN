package com.example.vpn

import com.example.model.ConnectionStage
import com.example.model.V2RayConfig
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

data class TunnelRuntimeStats(
    val stage: ConnectionStage = ConnectionStage.DISCONNECTED,
    val activeConfig: V2RayConfig? = null,
    val tunInterfaceEstablished: Boolean = false
)

object VpnStateBus {
    private val _runtimeStats = MutableStateFlow(TunnelRuntimeStats())
    val runtimeStats: StateFlow<TunnelRuntimeStats> = _runtimeStats.asStateFlow()

    fun updateStage(stage: ConnectionStage, config: V2RayConfig? = _runtimeStats.value.activeConfig) {
        _runtimeStats.update {
            it.copy(
                stage = stage,
                activeConfig = config
            )
        }
    }

    fun updateConnected(config: V2RayConfig, tunEstablished: Boolean) {
        _runtimeStats.update {
            it.copy(
                stage = ConnectionStage.CONNECTED,
                activeConfig = config,
                tunInterfaceEstablished = tunEstablished
            )
        }
    }

    fun resetDisconnected() {
        _runtimeStats.value = TunnelRuntimeStats(stage = ConnectionStage.DISCONNECTED)
    }
}
