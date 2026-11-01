package com.example

import android.app.Activity
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.togetherWith
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.telemetry.MehTelemetry
import com.example.ui.MehPhase
import com.example.ui.MehUiState
import com.example.ui.MehViewModel
import com.example.ui.theme.AmberPulse
import com.example.ui.theme.CrimsonAlert
import com.example.ui.theme.CyberCyan
import com.example.ui.theme.MyApplicationTheme
import com.example.ui.theme.NeonEmerald
import com.example.ui.theme.NeonEmeraldGlow
import com.example.ui.theme.ObsidianBackground
import com.example.ui.theme.ObsidianElevated
import com.example.ui.theme.ObsidianSurface
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.example.ui.theme.VazirmatnFontFamily

class MainActivity : ComponentActivity() {
  override fun onCreate(savedInstanceState: Bundle?) {
    super.onCreate(savedInstanceState)
    MehTelemetry.initialize(this)
    enableEdgeToEdge()
    setContent {
      MyApplicationTheme {
        val mehViewModel: MehViewModel = viewModel()
        val uiState by mehViewModel.uiState.collectAsStateWithLifecycle()
        val context = LocalContext.current

        val vpnPermissionLauncher =
          rememberLauncherForActivityResult(
            contract = ActivityResultContracts.StartActivityForResult()
          ) { result ->
            mehViewModel.onVpnPermissionResult(
              context = context,
              granted = result.resultCode == Activity.RESULT_OK,
            )
          }

        MehMinimalScreen(
          uiState = uiState,
          onPowerToggle = {
            mehViewModel.onPowerButtonClicked(
              context = context,
              onRequestVpnPermission = { prepareIntent ->
                vpnPermissionLauncher.launch(prepareIntent)
              },
            )
          },
        )
      }
    }
  }
}

@Composable
fun MehMinimalScreen(
  uiState: MehUiState,
  onPowerToggle: () -> Unit,
  modifier: Modifier = Modifier,
) {
  val accentColor by
    animateColorAsState(
      targetValue =
        when (uiState.phase) {
          MehPhase.CONNECTED -> NeonEmerald
          MehPhase.FETCHING_CONFIGS -> CyberCyan
          MehPhase.TESTING_SPEED -> AmberPulse
          MehPhase.CONNECTING -> NeonEmeraldGlow
          MehPhase.ERROR -> CrimsonAlert
          MehPhase.DISCONNECTED -> TextMuted
        },
      animationSpec = tween(durationMillis = 450),
      label = "accentColor",
    )

  Scaffold(
    modifier = modifier.fillMaxSize(),
    containerColor = ObsidianBackground,
    contentWindowInsets = WindowInsets.safeDrawing,
  ) { innerPadding ->
    Box(
      modifier =
        Modifier.fillMaxSize()
          .background(
            Brush.radialGradient(
              colors =
                listOf(
                  accentColor.copy(alpha = if (uiState.phase == MehPhase.CONNECTED) 0.14f else 0.06f),
                  ObsidianBackground,
                ),
            )
          )
          .padding(innerPadding)
          .windowInsetsPadding(WindowInsets.safeDrawing),
      contentAlignment = Alignment.Center,
    ) {
      // Center column: strictly the circular power button and the single live status log line below it
      Column(
        modifier =
          Modifier.fillMaxWidth()
            .widthIn(max = 460.dp)
            .padding(horizontal = 24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
      ) {
        CircularPowerButton(
          phase = uiState.phase,
          accentColor = accentColor,
          onClick = onPowerToggle,
        )

        Spacer(modifier = Modifier.height(44.dp))

        SingleLineLiveLog(
          logText = uiState.liveLogLine,
          phase = uiState.phase,
          accentColor = accentColor,
        )
      }
    }
  }
}

@Composable
private fun CircularPowerButton(
  phase: MehPhase,
  accentColor: Color,
  onClick: () -> Unit,
) {
  val haptic = LocalHapticFeedback.current
  val interactionSource = remember { MutableInteractionSource() }
  val isPressed by interactionSource.collectIsPressedAsState()

  val pressScale by
    animateFloatAsState(
      targetValue = if (isPressed) 0.93f else 1f,
      animationSpec =
        spring(
          dampingRatio = Spring.DampingRatioMediumBouncy,
          stiffness = Spring.StiffnessLow,
        ),
      label = "pressScale",
    )

  val infiniteTransition = rememberInfiniteTransition(label = "orbitalTransition")
  val sweepRotation by
    infiniteTransition.animateFloat(
      initialValue = 0f,
      targetValue = 360f,
      animationSpec =
        infiniteRepeatable(
          animation = tween(durationMillis = 1500, easing = LinearEasing),
          repeatMode = RepeatMode.Restart,
        ),
      label = "sweepRotation",
    )

  val breathingPulse by
    infiniteTransition.animateFloat(
      initialValue = 0.88f,
      targetValue = 1.08f,
      animationSpec =
        infiniteRepeatable(
          animation = tween(durationMillis = 1800, easing = FastOutSlowInEasing),
          repeatMode = RepeatMode.Reverse,
        ),
      label = "breathingPulse",
    )

  val isBusy =
    phase == MehPhase.FETCHING_CONFIGS ||
      phase == MehPhase.TESTING_SPEED ||
      phase == MehPhase.CONNECTING
  val isConnected = phase == MehPhase.CONNECTED

  val connectDesc = stringResource(R.string.vpn_button_connect_desc)
  val disconnectDesc = stringResource(R.string.vpn_button_disconnect_desc)
  val a11yDescription = if (isConnected || isBusy) disconnectDesc else connectDesc

  Box(
    modifier = Modifier.size(230.dp),
    contentAlignment = Alignment.Center,
  ) {
    // Ambient concentric aura and live orbital progress ring
    Canvas(modifier = Modifier.fillMaxSize()) {
      val centerRadius = size.minDimension / 2f

      // Outer subtle halo
      drawCircle(
        color =
          accentColor.copy(
            alpha =
              when {
                isConnected -> 0.16f * breathingPulse
                isBusy -> 0.14f
                else -> 0.05f
              }
          ),
        radius = centerRadius * (if (isConnected || isBusy) breathingPulse else 0.92f),
      )

      // Mid ring track
      drawCircle(
        color = accentColor.copy(alpha = if (isConnected) 0.35f else 0.15f),
        radius = centerRadius * 0.82f,
        style = Stroke(width = 2.dp.toPx()),
      )

      // Live rotating orbital arc while fetching configs, testing speed, or connecting
      if (isBusy) {
        drawArc(
          color = accentColor,
          startAngle = sweepRotation,
          sweepAngle = 105f,
          useCenter = false,
          style = Stroke(width = 4.dp.toPx(), cap = StrokeCap.Round),
          topLeft =
            androidx.compose.ui.geometry.Offset(
              x = size.width * 0.09f,
              y = size.height * 0.09f,
            ),
          size =
            androidx.compose.ui.geometry.Size(
              width = size.width * 0.82f,
              height = size.height * 0.82f,
            ),
        )
      }
    }

    // Core interactive circular button
    Box(
      modifier =
        Modifier.size(164.dp)
          .scale(pressScale)
          .clip(CircleShape)
          .background(
            Brush.linearGradient(
              colors =
                if (isConnected) {
                  listOf(
                    NeonEmerald.copy(alpha = 0.24f),
                    ObsidianSurface,
                  )
                } else {
                  listOf(
                    ObsidianElevated,
                    ObsidianSurface,
                  )
                }
            )
          )
          .border(
            width = if (isConnected) 2.5.dp else 1.5.dp,
            color =
              when {
                isConnected -> NeonEmerald
                isBusy -> accentColor.copy(alpha = 0.85f)
                phase == MehPhase.ERROR -> CrimsonAlert.copy(alpha = 0.7f)
                else -> TextMuted.copy(alpha = 0.4f)
              },
            shape = CircleShape,
          )
          .semantics {
            role = Role.Button
            contentDescription = a11yDescription
          }
          .clickable(
            interactionSource = interactionSource,
            indication = androidx.compose.material3.ripple(bounded = true, color = accentColor),
            onClick = {
              haptic.performHapticFeedback(HapticFeedbackType.LongPress)
              onClick()
            },
          )
          .testTag("vpn_toggle_button"),
      contentAlignment = Alignment.Center,
    ) {
      Icon(
        imageVector = Icons.Rounded.PowerSettingsNew,
        contentDescription = null,
        tint =
          when {
            isConnected -> NeonEmeraldGlow
            isBusy -> accentColor
            phase == MehPhase.ERROR -> CrimsonAlert
            else -> TextPrimary.copy(alpha = 0.82f)
          },
        modifier = Modifier.size(64.dp),
      )
    }
  }
}

@Composable
private fun SingleLineLiveLog(
  logText: String,
  phase: MehPhase,
  accentColor: Color,
) {
  val infiniteTransition = rememberInfiniteTransition(label = "logDotPulse")
  val dotAlpha by
    infiniteTransition.animateFloat(
      initialValue = 0.35f,
      targetValue = 1f,
      animationSpec =
        infiniteRepeatable(
          animation = tween(durationMillis = 700, easing = FastOutSlowInEasing),
          repeatMode = RepeatMode.Reverse,
        ),
      label = "dotAlpha",
    )

  CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
    Row(
      modifier =
        Modifier.fillMaxWidth()
          .height(28.dp)
          .padding(horizontal = 8.dp)
          .testTag("live_status_log_container"),
      verticalAlignment = Alignment.CenterVertically,
      horizontalArrangement = Arrangement.Center,
    ) {
      if (logText.isNotEmpty()) {
        Box(
          modifier =
            Modifier.size(8.dp)
              .clip(CircleShape)
              .background(color = accentColor.copy(alpha = dotAlpha))
        )

        Spacer(modifier = Modifier.width(10.dp))
      }

      AnimatedContent(
        targetState = logText,
        transitionSpec = {
          fadeIn(animationSpec = tween(180)) togetherWith fadeOut(animationSpec = tween(140))
        },
        label = "liveLogAnimatedText",
      ) { currentLog ->
        Text(
          text = currentLog,
          style = MaterialTheme.typography.bodyLarge,
          fontFamily = VazirmatnFontFamily,
          color =
            when (phase) {
              MehPhase.CONNECTED -> NeonEmeraldGlow
              MehPhase.ERROR -> CrimsonAlert
              MehPhase.DISCONNECTED -> TextSecondary
              else -> TextPrimary
            },
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
          textAlign = TextAlign.Center,
          modifier = Modifier.testTag("live_status_log"),
        )
      }
    }
  }
}
