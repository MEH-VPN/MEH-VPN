package com.example

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import com.example.ui.MehPhase
import com.example.ui.MehUiState
import com.example.ui.MehViewModel
import com.example.ui.theme.MyApplicationTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [34])
class ExampleRobolectricTest {

  @get:Rule val composeTestRule = createComposeRule()

  @Test
  fun minimalScreen_displaysOnlyPowerButtonAndLiveLogLine() {
    var clicked = false
    composeTestRule.setContent {
      MyApplicationTheme {
        MehMinimalScreen(
          uiState =
            MehUiState(
              phase = MehPhase.FETCHING_CONFIGS,
              liveLogLine = MehViewModel.LOG_FETCHING,
            ),
          onPowerToggle = { clicked = true },
        )
      }
    }

    composeTestRule.onNodeWithTag("vpn_toggle_button").assertIsDisplayed()
    composeTestRule.onNodeWithTag("live_status_log").assertIsDisplayed()
    composeTestRule.onNodeWithTag("vpn_toggle_button").performClick()
    assertTrue(clicked)
  }

  @Test
  fun firebaseTelemetry_initializesAndTracksActiveUsersAndFlushesErrors() {
    val context = androidx.test.core.app.ApplicationProvider.getApplicationContext<android.content.Context>()

    // 1. Verify Google Services plugin generated valid Firebase project resources
    val googleAppIdRes = context.resources.getIdentifier("google_app_id", "string", context.packageName)
    val projectIdRes = context.resources.getIdentifier("project_id", "string", context.packageName)
    assertTrue("google_app_id resource must exist", googleAppIdRes != 0)
    assertTrue("project_id resource must exist", projectIdRes != 0)
    org.junit.Assert.assertEquals(
      "1:468881393461:android:595ee77141fb8a77606e7c",
      context.getString(googleAppIdRes),
    )
    org.junit.Assert.assertEquals(
      "gen-lang-client-0005537360",
      context.getString(projectIdRes),
    )

    // 2. Verify MehTelemetry initialization & active user tracking
    com.example.telemetry.MehTelemetry.initialize(context)
    com.example.telemetry.MehTelemetry.logAppOpen("MehMinimalScreen")

    val diagAfterOpen = com.example.telemetry.MehTelemetry.getDiagnostics()
    assertTrue("Firebase should be initialized", diagAfterOpen.isFirebaseInitialized)
    assertTrue("Client user ID must be generated and persisted", diagAfterOpen.clientUserId.startsWith("meh_"))
    assertTrue("Active session count must increment", diagAfterOpen.activeSessionsCount >= 1)
    assertTrue(
      "Should record app_open and user_active_session events",
      diagAfterOpen.recentEvents.any { it.name == "app_open" } &&
        diagAfterOpen.recentEvents.any { it.name == "user_active_session" },
    )

    // 3. Log a pre-connection error and a simulated crash error while disconnected; verify persistence & flush on connect
    com.example.telemetry.MehTelemetry.logConnectAttempt()
    com.example.telemetry.MehTelemetry.logError(
      stage = "fetch_configs",
      errorMessage = "Simulated network timeout before VPN connect",
    )
    com.example.telemetry.MehTelemetry.logError(
      stage = "uncaught_crash",
      errorMessage = "IllegalStateException: Simulated crash",
      persistSynchronously = true,
    )

    val diagBeforeConnect = com.example.telemetry.MehTelemetry.getDiagnostics()
    assertTrue("Total errors logged must be >= 2", diagBeforeConnect.totalErrorsLogged >= 2)
    assertTrue("Pre-connection errors must be buffered for flush", diagBeforeConnect.pendingBufferedErrorsCount >= 2)

    // 4. Simulate VPN connection -> should flush buffered errors and record vpn_connected + heartbeat
    com.example.telemetry.MehTelemetry.logServerConnected(
      protocol = "V2Ray:VLESS",
      serverName = "Germany-Fast",
      latencyMs = 115L,
    )
    com.example.telemetry.MehTelemetry.logActiveSessionHeartbeat(
      serverName = "Germany-Fast",
      protocol = "VLESS",
      latencyMs = 110L,
      uptimeSeconds = 60L,
    )

    val diagAfterConnect = com.example.telemetry.MehTelemetry.getDiagnostics()
    org.junit.Assert.assertEquals("connected", diagAfterConnect.lastVpnStatus)
    org.junit.Assert.assertEquals("Buffered errors should be flushed upon VPN connection", 0, diagAfterConnect.pendingBufferedErrorsCount)
    assertTrue(
      "Should emit app_error_flushed and app_crash_recovered when flushed",
      diagAfterConnect.recentEvents.any { it.name == "app_error_flushed" } &&
        diagAfterConnect.recentEvents.any { it.name == "app_crash_recovered" } &&
        diagAfterConnect.recentEvents.any { it.name == "vpn_active_heartbeat" },
    )
  }
}
