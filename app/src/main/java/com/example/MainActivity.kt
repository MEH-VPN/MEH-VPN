package com.example

import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.model.ConnectionStage
import com.example.model.V2RayConfig
import com.example.ui.MehScreen
import com.example.ui.VpnViewModel
import com.example.ui.theme.MyApplicationTheme

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                val vpnViewModel: VpnViewModel = viewModel()
                val uiState by vpnViewModel.uiState.collectAsStateWithLifecycle()
                val context = LocalContext.current

                val vpnPermissionLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.StartActivityForResult()
                ) { _ ->
                    val target = uiState.selectedServer
                    if (target != null) {
                        vpnViewModel.startVpnTunnelService(target)
                    }
                }

                val requestVpnAndStart: (V2RayConfig) -> Unit = { config ->
                    val prepareIntent = runCatching { VpnService.prepare(context) }.getOrNull()
                    if (prepareIntent != null) {
                        vpnPermissionLauncher.launch(prepareIntent)
                    } else {
                        vpnViewModel.startVpnTunnelService(config)
                    }
                }

                MehScreen(
                    uiState = uiState,
                    onOneTapConnectToggle = {
                        when (uiState.stage) {
                            ConnectionStage.CONNECTED,
                            ConnectionStage.CONNECTING,
                            ConnectionStage.FETCHING_SUBSCRIPTIONS,
                            ConnectionStage.TESTING_SERVERS -> {
                                vpnViewModel.disconnectVpnTunnel()
                            }
                            ConnectionStage.DISCONNECTED -> {
                                vpnViewModel.findBestServerAndConnect(
                                    onReadyToStartService = requestVpnAndStart
                                )
                            }
                        }
                    }
                )
            }
        }
    }
}
