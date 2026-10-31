package com.example

import android.content.Intent
import android.net.VpnService
import android.os.Build
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
import com.example.vpn.MehVpnService
import com.google.firebase.FirebaseApp

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        runCatching {
            if (FirebaseApp.getApps(this).isEmpty()) {
                FirebaseApp.initializeApp(this)
            }
        }
        enableEdgeToEdge()
        setContent {
            MyApplicationTheme {
                val context = LocalContext.current
                val vpnViewModel: VpnViewModel = viewModel()
                val uiState by vpnViewModel.uiState.collectAsStateWithLifecycle()

                val startVpnService: (V2RayConfig) -> Unit = { config ->
                    val appContext = context.applicationContext
                    val intent = Intent(appContext, MehVpnService::class.java).apply {
                        action = MehVpnService.ACTION_CONNECT
                        putExtra(MehVpnService.EXTRA_CONFIG_URI, config.rawUri)
                        putExtra(MehVpnService.EXTRA_SOURCE_REPO, config.sourceRepo)
                        putExtra(MehVpnService.EXTRA_INITIAL_PING, config.pingMs)
                    }
                    runCatching {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                            appContext.startForegroundService(intent)
                        } else {
                            appContext.startService(intent)
                        }
                    }
                }

                val stopVpnService: () -> Unit = {
                    vpnViewModel.cancelScanAndReset()
                    val appContext = context.applicationContext
                    val intent = Intent(appContext, MehVpnService::class.java).apply {
                        action = MehVpnService.ACTION_DISCONNECT
                    }
                    runCatching { appContext.startService(intent) }
                }

                val vpnPermissionLauncher = rememberLauncherForActivityResult(
                    contract = ActivityResultContracts.StartActivityForResult()
                ) { _ ->
                    val target = uiState.selectedServer
                    if (target != null) {
                        startVpnService(target)
                    }
                }

                val requestVpnAndStart: (V2RayConfig) -> Unit = { config ->
                    val prepareIntent = runCatching { VpnService.prepare(context) }.getOrNull()
                    if (prepareIntent != null) {
                        vpnPermissionLauncher.launch(prepareIntent)
                    } else {
                        startVpnService(config)
                    }
                }

                MehScreen(
                    uiState = uiState,
                    onOneTapConnectToggle = {
                        when (uiState.stage) {
                            ConnectionStage.CONNECTED,
                            ConnectionStage.CONNECTING,
                            ConnectionStage.FETCHING_SUBSCRIPTIONS,
                            ConnectionStage.TESTING_SERVERS,
                            ConnectionStage.AETHER_FALLBACK,
                            ConnectionStage.SERVERLESS_FALLBACK,
                            ConnectionStage.SNI_SPOOF_FALLBACK -> {
                                stopVpnService()
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
