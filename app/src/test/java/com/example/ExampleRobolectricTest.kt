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
}
