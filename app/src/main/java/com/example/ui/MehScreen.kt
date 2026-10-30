package com.example.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material3.Icon
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.model.ConnectionStage
import com.example.ui.theme.AmberScan
import com.example.ui.theme.CyberEmerald
import com.example.ui.theme.ObsidianBg
import com.example.ui.theme.ObsidianBorder
import com.example.ui.theme.ObsidianSurfaceElevated
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.example.ui.theme.VazirmatnFontFamily

@Composable
fun MehScreen(
    uiState: VpnUiState,
    onOneTapConnectToggle: () -> Unit
) {
    val isConnected = uiState.stage == ConnectionStage.CONNECTED
    val isBusy = uiState.stage == ConnectionStage.FETCHING_SUBSCRIPTIONS ||
        uiState.stage == ConnectionStage.TESTING_SERVERS ||
        uiState.stage == ConnectionStage.CONNECTING

    val ringColor = when {
        isConnected -> CyberEmerald
        isBusy -> AmberScan
        else -> ObsidianBorder
    }

    val iconTint = when {
        isConnected -> CyberEmerald
        isBusy -> AmberScan
        else -> TextMuted
    }

    val stageText = when (uiState.stage) {
        ConnectionStage.DISCONNECTED -> "خاموش"
        ConnectionStage.FETCHING_SUBSCRIPTIONS -> "دریافت کانفیگ..."
        ConnectionStage.TESTING_SERVERS -> "تست کانفیگ..."
        ConnectionStage.CONNECTING -> "در حال اتصال..."
        ConnectionStage.CONNECTED -> "متصل"
    }

    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
        Scaffold(
            modifier = Modifier.fillMaxSize(),
            containerColor = ObsidianBg,
            contentWindowInsets = WindowInsets.safeDrawing
        ) { innerPadding ->
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(innerPadding)
                    .windowInsetsPadding(WindowInsets.safeDrawing),
                contentAlignment = Alignment.Center
            ) {
                val interactionSource = remember { MutableInteractionSource() }

                // Single Central Circle with Power On/Off Icon and Stage Text Inside
                Box(
                    modifier = Modifier
                        .size(210.dp)
                        .clip(CircleShape)
                        .background(
                            if (isConnected) CyberEmerald.copy(alpha = 0.12f)
                            else ObsidianSurfaceElevated
                        )
                        .border(
                            width = if (isConnected) 3.dp else 2.dp,
                            color = ringColor,
                            shape = CircleShape
                        )
                        .clickable(
                            interactionSource = interactionSource,
                            indication = ripple(bounded = true, color = ringColor),
                            onClick = onOneTapConnectToggle
                        )
                        .padding(16.dp)
                        .testTag("one_tap_connect_button"),
                    contentAlignment = Alignment.Center
                ) {
                    Column(
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.Center
                    ) {
                        Icon(
                            painter = painterResource(id = R.drawable.ic_power),
                            contentDescription = stageText,
                            tint = iconTint,
                            modifier = Modifier.size(64.dp)
                        )

                        Spacer(modifier = Modifier.height(14.dp))

                        Text(
                            text = stageText,
                            fontFamily = VazirmatnFontFamily,
                            fontWeight = FontWeight.Bold,
                            fontSize = 17.sp,
                            color = when {
                                isConnected -> CyberEmerald
                                isBusy -> AmberScan
                                else -> TextSecondary
                            },
                            textAlign = TextAlign.Center,
                            modifier = Modifier.testTag("connection_status_title")
                        )

                        if (isConnected && uiState.selectedServer != null) {
                            Spacer(modifier = Modifier.height(4.dp))
                            Text(
                                text = "${uiState.selectedServer.flagEmoji} ${uiState.selectedServer.countryNameFa}",
                                fontFamily = VazirmatnFontFamily,
                                fontWeight = FontWeight.Medium,
                                fontSize = 13.sp,
                                color = TextPrimary,
                                textAlign = TextAlign.Center,
                                maxLines = 1
                            )
                        }
                    }
                }
            }
        }
    }
}
