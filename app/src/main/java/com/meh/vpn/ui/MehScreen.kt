package com.meh.vpn.ui

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
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.layout.windowInsetsPadding
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
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
import com.meh.vpn.R
import com.meh.vpn.model.ConnectionStage
import com.meh.vpn.ui.theme.AmberScan
import com.meh.vpn.ui.theme.CyberEmerald
import com.meh.vpn.ui.theme.ObsidianBg
import com.meh.vpn.ui.theme.ObsidianBorder
import com.meh.vpn.ui.theme.ObsidianSurfaceElevated
import com.meh.vpn.ui.theme.TextMuted
import com.meh.vpn.ui.theme.TextPrimary
import com.meh.vpn.ui.theme.TextSecondary
import com.meh.vpn.ui.theme.VazirmatnFontFamily

@Composable
fun MehScreen(
    uiState: VpnUiState,
    onOneTapConnectToggle: () -> Unit
) {
    val isConnected = uiState.stage == ConnectionStage.CONNECTED
    val isBusy = uiState.stage == ConnectionStage.FETCHING_SUBSCRIPTIONS ||
        uiState.stage == ConnectionStage.TESTING_SERVERS ||
        uiState.stage == ConnectionStage.AETHER_FALLBACK ||
        uiState.stage == ConnectionStage.SERVERLESS_FALLBACK ||
        uiState.stage == ConnectionStage.SNI_SPOOF_FALLBACK ||
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

    val baseStageText = when (uiState.stage) {
        ConnectionStage.DISCONNECTED -> "خاموش"
        ConnectionStage.FETCHING_SUBSCRIPTIONS -> "دریافت کانفیگ..."
        ConnectionStage.TESTING_SERVERS -> "تست کانفیگ..."
        ConnectionStage.AETHER_FALLBACK -> "اتصال Aether..."
        ConnectionStage.SERVERLESS_FALLBACK -> "اتصال Serverless..."
        ConnectionStage.SNI_SPOOF_FALLBACK -> "اتصال SNI Spoof..."
        ConnectionStage.CONNECTING -> "در حال اتصال..."
        ConnectionStage.CONNECTED -> "متصل"
    }

    val stageText = if (isBusy && uiState.progressPercent > 0) {
        "$baseStageText (${uiState.progressPercent}٪)"
    } else {
        baseStageText
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
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.Center,
                    modifier = Modifier.padding(horizontal = 24.dp)
                ) {
                    val interactionSource = remember { MutableInteractionSource() }

                    // Central Circle with ONLY the Power On/Off Icon Inside
                    Box(
                        modifier = Modifier
                            .size(200.dp)
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
                        Icon(
                            painter = painterResource(id = R.drawable.ic_power),
                            contentDescription = stageText,
                            tint = iconTint,
                            modifier = Modifier.size(72.dp)
                        )
                    }

                    // Outside the circle: show all connection statuses below the circle
                    Spacer(modifier = Modifier.height(24.dp))

                    Text(
                        text = stageText,
                        fontFamily = VazirmatnFontFamily,
                        fontWeight = FontWeight.Bold,
                        fontSize = 18.sp,
                        color = when {
                            isConnected -> CyberEmerald
                            isBusy -> AmberScan
                            else -> TextSecondary
                        },
                        textAlign = TextAlign.Center,
                        modifier = Modifier.testTag("connection_status_title")
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    // Progress bar & detail text outside the circle during fetching/testing,
                    // or Flag Emoji + Country Name when connected
                    Box(
                        modifier = Modifier.height(56.dp),
                        contentAlignment = Alignment.TopCenter
                    ) {
                        when {
                            isConnected && uiState.selectedServer != null -> {
                                val countryOnly = uiState.selectedServer.countryNameFa
                                    .substringBefore("•")
                                    .trim()
                                Text(
                                    text = "${uiState.selectedServer.flagEmoji} $countryOnly",
                                    fontFamily = VazirmatnFontFamily,
                                    fontWeight = FontWeight.Bold,
                                    fontSize = 18.sp,
                                    color = TextPrimary,
                                    textAlign = TextAlign.Center,
                                    modifier = Modifier.testTag("connected_country_label")
                                )
                            }
                            isBusy -> {
                                Column(
                                    horizontalAlignment = Alignment.CenterHorizontally
                                ) {
                                    // Sleek progress bar outside the circle
                                    val fraction = (uiState.progressPercent.coerceIn(0, 100)) / 100f
                                    Box(
                                        modifier = Modifier
                                            .width(180.dp)
                                            .height(6.dp)
                                            .clip(RoundedCornerShape(3.dp))
                                            .background(ObsidianSurfaceElevated)
                                            .testTag("scan_progress_bar")
                                    ) {
                                        Box(
                                            modifier = Modifier
                                                .fillMaxWidth(fraction)
                                                .height(6.dp)
                                                .clip(RoundedCornerShape(3.dp))
                                                .background(AmberScan)
                                        )
                                    }

                                    if (uiState.scanDetailText.isNotEmpty()) {
                                        Spacer(modifier = Modifier.height(8.dp))
                                        Text(
                                            text = uiState.scanDetailText,
                                            fontFamily = VazirmatnFontFamily,
                                            fontWeight = FontWeight.Medium,
                                            fontSize = 13.sp,
                                            color = TextSecondary,
                                            textAlign = TextAlign.Center,
                                            modifier = Modifier.testTag("scan_progress_detail")
                                        )
                                    }
                                }
                            }
                            uiState.scanDetailText.isNotEmpty() -> {
                                Text(
                                    text = uiState.scanDetailText,
                                    fontFamily = VazirmatnFontFamily,
                                    fontWeight = FontWeight.Medium,
                                    fontSize = 13.sp,
                                    color = TextMuted,
                                    textAlign = TextAlign.Center,
                                    modifier = Modifier.testTag("scan_progress_detail")
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}
