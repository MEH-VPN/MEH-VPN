package com.example.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.hapticfeedback.HapticFeedbackType
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalHapticFeedback
import androidx.compose.ui.platform.LocalLayoutDirection
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.LayoutDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.ui.theme.AmberPulse
import com.example.ui.theme.CrimsonAlert
import com.example.ui.theme.CyberCyan
import com.example.ui.theme.NeonEmerald
import com.example.ui.theme.NeonEmeraldGlow
import com.example.ui.theme.ObsidianBackground
import com.example.ui.theme.ObsidianElevated
import com.example.ui.theme.ObsidianSurface
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.example.ui.theme.VazirmatnFontFamily
import com.example.vpn.DeviceCalibrationSnapshot
import com.example.vpn.FullLogCategory
import com.example.vpn.FullLogEntry
import com.example.vpn.MehFullLogger
import com.example.vpn.TunnelModePreference
import com.example.vpn.TunnelProfile
import kotlinx.coroutines.delay

/**
 * Compact top action row giving 1-tap access to:
 * 1. Device optimization & tunnel profile calibration (shows the active calibrated profile).
 * 2. Comprehensive unfiltered raw diagnostic log viewer (shows live log entry count).
 */
@Composable
fun TopCalibrationAndLogsBar(
  effectiveProfile: TunnelProfile,
  selectedMode: TunnelModePreference,
  logCount: Int,
  onOpenCalibration: () -> Unit,
  onOpenFullLogs: () -> Unit,
  modifier: Modifier = Modifier,
) {
  val haptic = LocalHapticFeedback.current
  val optimizeLabel = stringResource(R.string.device_optimize_button)
  val logsLabel = stringResource(R.string.full_logs_button)

  CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
    Row(
      modifier = modifier.fillMaxWidth(),
      horizontalArrangement = Arrangement.SpaceBetween,
      verticalAlignment = Alignment.CenterVertically,
    ) {
      // Device Optimization / Tunnel Profile Pill
      Row(
        modifier =
          Modifier.defaultMinSize(minHeight = 48.dp)
            .clip(RoundedCornerShape(24.dp))
            .background(ObsidianSurface.copy(alpha = 0.86f))
            .border(
              width = 1.dp,
              color = CyberCyan.copy(alpha = 0.30f),
              shape = RoundedCornerShape(24.dp),
            )
            .semantics {
              role = Role.Button
              contentDescription = "$optimizeLabel: ${effectiveProfile.shortBadgeFa}"
            }
            .clickable {
              haptic.performHapticFeedback(HapticFeedbackType.LongPress)
              onOpenCalibration()
            }
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag("open_calibration_button"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
      ) {
        Icon(
          painter = painterResource(R.drawable.ic_tune_rounded),
          contentDescription = null,
          tint = CyberCyan,
          modifier = Modifier.size(16.dp),
        )
        Text(
          text =
            if (selectedMode == TunnelModePreference.AUTO) {
              effectiveProfile.shortBadgeFa
            } else {
              "${effectiveProfile.shortBadgeFa} • دستی"
            },
          style = MaterialTheme.typography.labelMedium,
          fontFamily = VazirmatnFontFamily,
          fontSize = 11.sp,
          fontWeight = FontWeight.Medium,
          color = TextPrimary,
          maxLines = 1,
          overflow = TextOverflow.Ellipsis,
        )
      }

      // Full Diagnostic Logs Pill
      Row(
        modifier =
          Modifier.defaultMinSize(minHeight = 48.dp)
            .clip(RoundedCornerShape(24.dp))
            .background(ObsidianSurface.copy(alpha = 0.86f))
            .border(
              width = 1.dp,
              color = TextMuted.copy(alpha = 0.34f),
              shape = RoundedCornerShape(24.dp),
            )
            .semantics {
              role = Role.Button
              contentDescription = logsLabel
            }
            .clickable {
              haptic.performHapticFeedback(HapticFeedbackType.LongPress)
              onOpenFullLogs()
            }
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag("open_full_logs_button"),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(6.dp),
      ) {
        Icon(
          painter = painterResource(R.drawable.ic_terminal_rounded),
          contentDescription = null,
          tint = NeonEmeraldGlow,
          modifier = Modifier.size(16.dp),
        )
        Text(
          text = if (logCount > 0) "$logsLabel ($logCount)" else logsLabel,
          style = MaterialTheme.typography.labelMedium,
          fontFamily = VazirmatnFontFamily,
          fontSize = 11.sp,
          fontWeight = FontWeight.Medium,
          color = TextSecondary,
          maxLines = 1,
        )
      }
    }
  }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DeviceOptimizationSheet(
  snapshot: DeviceCalibrationSnapshot?,
  selectedMode: TunnelModePreference,
  effectiveProfile: TunnelProfile,
  onSelectMode: (TunnelModePreference) -> Unit,
  onRecalibrate: () -> Unit,
  onOpenFullLogs: () -> Unit,
  onDismiss: () -> Unit,
) {
  val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
  val haptic = LocalHapticFeedback.current

  ModalBottomSheet(
    onDismissRequest = onDismiss,
    sheetState = sheetState,
    containerColor = ObsidianElevated,
    contentColor = TextPrimary,
    scrimColor = Color.Black.copy(alpha = 0.70f),
    shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
  ) {
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
      Column(
        modifier =
          Modifier.fillMaxWidth()
            .verticalScroll(rememberScrollState())
            .navigationBarsPadding()
            .padding(horizontal = 20.dp)
            .padding(top = 4.dp, bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
      ) {
        Text(
          text = stringResource(R.string.calibration_sheet_title),
          style = MaterialTheme.typography.titleMedium,
          fontFamily = VazirmatnFontFamily,
          fontWeight = FontWeight.Bold,
          color = TextPrimary,
        )
        Text(
          text = stringResource(R.string.calibration_sheet_subtitle),
          style = MaterialTheme.typography.bodySmall,
          fontFamily = VazirmatnFontFamily,
          color = TextSecondary,
        )

        // Device & Network Diagnostic Summary Card
        if (snapshot != null) {
          Column(
            modifier =
              Modifier.fillMaxWidth()
                .clip(RoundedCornerShape(16.dp))
                .background(ObsidianSurface)
                .border(1.dp, CyberCyan.copy(alpha = 0.25f), RoundedCornerShape(16.dp))
                .padding(14.dp),
            verticalArrangement = Arrangement.spacedBy(6.dp),
          ) {
            DiagInfoRow("دستگاه", "${snapshot.deviceModel} • اندروید ${snapshot.androidRelease} (API ${snapshot.sdkInt})")
            DiagInfoRow("شبکه فعلی", "${snapshot.transportLabel}${if (snapshot.hasCgnat100Interface) " • رنج CGNAT 100.64" else ""}")
            DiagInfoRow(
              "Private DNS",
              "${snapshot.privateDnsModeRaw}${snapshot.privateDnsHostname?.let { " ($it)" } ?: ""}",
            )
            DiagInfoRow("پروفایل فعال", effectiveProfile.titleFa, valueColor = NeonEmeraldGlow)
            Text(
              text = snapshot.recommendationReasonFa,
              style = MaterialTheme.typography.labelSmall,
              fontFamily = VazirmatnFontFamily,
              fontSize = 11.sp,
              lineHeight = 16.sp,
              color = TextSecondary,
            )
          }
        }

        // Recalibrate Button
        Row(
          modifier =
            Modifier.fillMaxWidth()
              .defaultMinSize(minHeight = 48.dp)
              .clip(RoundedCornerShape(14.dp))
              .background(CyberCyan.copy(alpha = 0.14f))
              .border(1.dp, CyberCyan.copy(alpha = 0.45f), RoundedCornerShape(14.dp))
              .clickable {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onRecalibrate()
              }
              .padding(horizontal = 16.dp, vertical = 10.dp)
              .testTag("recalibrate_device_button"),
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.Center,
        ) {
          Icon(
            painter = painterResource(R.drawable.ic_tune_rounded),
            contentDescription = null,
            tint = CyberCyan,
            modifier = Modifier.size(18.dp),
          )
          Spacer(modifier = Modifier.width(8.dp))
          Text(
            text = stringResource(R.string.calibration_recalibrate_btn),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = VazirmatnFontFamily,
            fontWeight = FontWeight.SemiBold,
            color = CyberCyan,
          )
        }

        // Tunnel Profile Selector Cards
        TunnelModeOptionCard(
          title = TunnelModePreference.AUTO.titleFa,
          subtitle = "پیشنهاد هوشمند بر اساس اندروید و شبکه (${snapshot?.recommendedProfile?.shortBadgeFa ?: effectiveProfile.shortBadgeFa})",
          isSelected = selectedMode == TunnelModePreference.AUTO,
          testTagName = "mode_option_auto",
          onClick = { onSelectMode(TunnelModePreference.AUTO) },
        )

        TunnelProfile.entries.forEach { profile ->
          val modePref = TunnelModePreference.fromId(profile.id)
          TunnelModeOptionCard(
            title = profile.titleFa,
            subtitle = profile.descriptionFa,
            isSelected = selectedMode == modePref,
            testTagName = "mode_option_${profile.id}",
            onClick = { onSelectMode(modePref) },
          )
        }

        // Direct Shortcut to Full Logs
        Row(
          modifier =
            Modifier.fillMaxWidth()
              .defaultMinSize(minHeight = 48.dp)
              .clip(RoundedCornerShape(14.dp))
              .background(ObsidianSurface)
              .border(1.dp, TextMuted.copy(alpha = 0.35f), RoundedCornerShape(14.dp))
              .clickable {
                haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                onOpenFullLogs()
              }
              .padding(horizontal = 16.dp, vertical = 10.dp)
              .testTag("calibration_open_logs_button"),
          verticalAlignment = Alignment.CenterVertically,
          horizontalArrangement = Arrangement.Center,
        ) {
          Icon(
            painter = painterResource(R.drawable.ic_terminal_rounded),
            contentDescription = null,
            tint = NeonEmeraldGlow,
            modifier = Modifier.size(18.dp),
          )
          Spacer(modifier = Modifier.width(8.dp))
          Text(
            text = stringResource(R.string.calibration_view_logs_btn),
            style = MaterialTheme.typography.bodySmall,
            fontFamily = VazirmatnFontFamily,
            fontWeight = FontWeight.Medium,
            color = TextPrimary,
          )
        }
      }
    }
  }
}

@Composable
private fun DiagInfoRow(
  label: String,
  value: String,
  valueColor: Color = TextPrimary,
) {
  Row(
    modifier = Modifier.fillMaxWidth(),
    horizontalArrangement = Arrangement.SpaceBetween,
    verticalAlignment = Alignment.Top,
  ) {
    Text(
      text = label,
      style = MaterialTheme.typography.labelSmall,
      fontFamily = VazirmatnFontFamily,
      color = TextMuted,
    )
    Spacer(modifier = Modifier.width(12.dp))
    Text(
      text = value,
      style = MaterialTheme.typography.labelSmall,
      fontFamily = VazirmatnFontFamily,
      fontWeight = FontWeight.Medium,
      color = valueColor,
      maxLines = 2,
      overflow = TextOverflow.Ellipsis,
    )
  }
}

@Composable
private fun TunnelModeOptionCard(
  title: String,
  subtitle: String,
  isSelected: Boolean,
  testTagName: String,
  onClick: () -> Unit,
) {
  val haptic = LocalHapticFeedback.current
  val borderColor = if (isSelected) NeonEmerald else TextMuted.copy(alpha = 0.25f)
  val bgColor = if (isSelected) NeonEmerald.copy(alpha = 0.10f) else ObsidianSurface

  Row(
    modifier =
      Modifier.fillMaxWidth()
        .defaultMinSize(minHeight = 56.dp)
        .clip(RoundedCornerShape(14.dp))
        .background(bgColor)
        .border(if (isSelected) 1.5.dp else 1.dp, borderColor, RoundedCornerShape(14.dp))
        .clickable {
          haptic.performHapticFeedback(HapticFeedbackType.LongPress)
          onClick()
        }
        .padding(horizontal = 14.dp, vertical = 10.dp)
        .testTag(testTagName),
    verticalAlignment = Alignment.CenterVertically,
    horizontalArrangement = Arrangement.spacedBy(10.dp),
  ) {
    Box(
      modifier =
        Modifier.size(16.dp)
          .clip(CircleShape)
          .border(1.5.dp, if (isSelected) NeonEmerald else TextMuted, CircleShape)
          .padding(3.dp),
      contentAlignment = Alignment.Center,
    ) {
      if (isSelected) {
        Box(
          modifier =
            Modifier.size(8.dp)
              .clip(CircleShape)
              .background(NeonEmerald)
        )
      }
    }
    Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
      Text(
        text = title,
        style = MaterialTheme.typography.bodySmall,
        fontFamily = VazirmatnFontFamily,
        fontWeight = FontWeight.SemiBold,
        color = if (isSelected) NeonEmeraldGlow else TextPrimary,
      )
      Text(
        text = subtitle,
        style = MaterialTheme.typography.labelSmall,
        fontFamily = VazirmatnFontFamily,
        fontSize = 11.sp,
        lineHeight = 15.sp,
        color = TextSecondary,
      )
    }
  }
}

private enum class FullLogFilter(val labelFa: String) {
  ALL("همه"),
  TUN_DNS("تونل / DNS"),
  XRAY_PROBE("Xray / تست"),
  ERRORS("خطاها"),
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FullDiagnosticLogSheet(
  entries: List<FullLogEntry>,
  onRefreshSnapshot: () -> Unit,
  onClearLogs: () -> Unit,
  onDismiss: () -> Unit,
) {
  val context = LocalContext.current
  val haptic = LocalHapticFeedback.current
  val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
  var selectedFilter by remember { mutableStateOf(FullLogFilter.ALL) }
  var copiedRecently by remember { mutableStateOf(false) }

  LaunchedEffect(copiedRecently) {
    if (copiedRecently) {
      delay(2000L)
      copiedRecently = false
    }
  }

  val filteredEntries =
    remember(entries, selectedFilter) {
      when (selectedFilter) {
        FullLogFilter.ALL -> entries
        FullLogFilter.TUN_DNS ->
          entries.filter {
            it.category == FullLogCategory.TUNNEL ||
              it.category == FullLogCategory.DNS ||
              it.category == FullLogCategory.CALIBRATION ||
              it.category == FullLogCategory.NETWORK
          }
        FullLogFilter.XRAY_PROBE ->
          entries.filter {
            it.category == FullLogCategory.XRAY ||
              it.category == FullLogCategory.PROBE ||
              it.category == FullLogCategory.SERVER
          }
        FullLogFilter.ERRORS -> entries.filter { it.isError }
      }
    }

  val listState = rememberLazyListState()
  LaunchedEffect(filteredEntries.size) {
    if (filteredEntries.isNotEmpty()) {
      listState.scrollToItem(filteredEntries.lastIndex)
    }
  }

  ModalBottomSheet(
    onDismissRequest = onDismiss,
    sheetState = sheetState,
    containerColor = ObsidianElevated,
    contentColor = TextPrimary,
    scrimColor = Color.Black.copy(alpha = 0.72f),
    shape = RoundedCornerShape(topStart = 24.dp, topEnd = 24.dp),
  ) {
    CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Rtl) {
      Column(
        modifier =
          Modifier.fillMaxWidth()
            .fillMaxHeight(0.88f)
            .navigationBarsPadding()
            .padding(horizontal = 16.dp)
            .padding(bottom = 16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
      ) {
        // Title + Count
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.SpaceBetween,
          verticalAlignment = Alignment.CenterVertically,
        ) {
          Text(
            text = stringResource(R.string.full_logs_sheet_title),
            style = MaterialTheme.typography.titleSmall,
            fontFamily = VazirmatnFontFamily,
            fontWeight = FontWeight.Bold,
            color = TextPrimary,
          )
          Text(
            text = "${filteredEntries.size} خط",
            style = MaterialTheme.typography.labelSmall,
            fontFamily = VazirmatnFontFamily,
            color = CyberCyan,
          )
        }

        // Action Buttons Row (Copy All, Snapshot Refresh, Clear)
        Row(
          modifier = Modifier.fillMaxWidth(),
          horizontalArrangement = Arrangement.spacedBy(8.dp),
          verticalAlignment = Alignment.CenterVertically,
        ) {
          // Copy Complete Report Button
          Row(
            modifier =
              Modifier.weight(1.4f)
                .defaultMinSize(minHeight = 48.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(
                  if (copiedRecently) NeonEmerald.copy(alpha = 0.22f) else CyberCyan.copy(alpha = 0.16f)
                )
                .border(
                  1.dp,
                  if (copiedRecently) NeonEmerald else CyberCyan.copy(alpha = 0.50f),
                  RoundedCornerShape(12.dp),
                )
                .clickable {
                  haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                  val report = MehFullLogger.exportFullDiagnosticReport(context)
                  val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                  cm?.setPrimaryClip(ClipData.newPlainText("MEH Full Diagnostic Log", report))
                  copiedRecently = true
                }
                .padding(horizontal = 10.dp, vertical = 8.dp)
                .testTag("copy_full_logs_button"),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.Center,
          ) {
            Icon(
              painter = painterResource(R.drawable.ic_copy_rounded),
              contentDescription = null,
              tint = if (copiedRecently) NeonEmeraldGlow else CyberCyan,
              modifier = Modifier.size(16.dp),
            )
            Spacer(modifier = Modifier.width(6.dp))
            Text(
              text =
                if (copiedRecently) {
                  stringResource(R.string.full_logs_copied)
                } else {
                  stringResource(R.string.full_logs_copy_all)
                },
              style = MaterialTheme.typography.labelMedium,
              fontFamily = VazirmatnFontFamily,
              fontWeight = FontWeight.Bold,
              color = if (copiedRecently) NeonEmeraldGlow else CyberCyan,
              maxLines = 1,
            )
          }

          // Snapshot Refresh Button
          Box(
            modifier =
              Modifier.weight(1f)
                .defaultMinSize(minHeight = 48.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(ObsidianSurface)
                .border(1.dp, TextMuted.copy(alpha = 0.35f), RoundedCornerShape(12.dp))
                .clickable {
                  haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                  onRefreshSnapshot()
                }
                .padding(horizontal = 8.dp)
                .testTag("refresh_full_logs_button"),
            contentAlignment = Alignment.Center,
          ) {
            Text(
              text = stringResource(R.string.full_logs_refresh),
              style = MaterialTheme.typography.labelMedium,
              fontFamily = VazirmatnFontFamily,
              color = TextPrimary,
              maxLines = 1,
            )
          }

          // Clear Button
          Box(
            modifier =
              Modifier.defaultMinSize(minWidth = 68.dp, minHeight = 48.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(ObsidianSurface)
                .border(1.dp, CrimsonAlert.copy(alpha = 0.40f), RoundedCornerShape(12.dp))
                .clickable {
                  haptic.performHapticFeedback(HapticFeedbackType.LongPress)
                  onClearLogs()
                }
                .padding(horizontal = 10.dp)
                .testTag("clear_full_logs_button"),
            contentAlignment = Alignment.Center,
          ) {
            Text(
              text = stringResource(R.string.full_logs_clear),
              style = MaterialTheme.typography.labelMedium,
              fontFamily = VazirmatnFontFamily,
              color = CrimsonAlert,
              maxLines = 1,
            )
          }
        }

        // Category Filter Chips
        Row(
          modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
          horizontalArrangement = Arrangement.spacedBy(8.dp),
        ) {
          FullLogFilter.entries.forEach { filter ->
            val active = selectedFilter == filter
            Box(
              modifier =
                Modifier.defaultMinSize(minHeight = 36.dp)
                  .clip(RoundedCornerShape(18.dp))
                  .background(if (active) NeonEmerald.copy(alpha = 0.16f) else ObsidianSurface)
                  .border(
                    1.dp,
                    if (active) NeonEmerald else TextMuted.copy(alpha = 0.25f),
                    RoundedCornerShape(18.dp),
                  )
                  .clickable { selectedFilter = filter }
                  .padding(horizontal = 12.dp, vertical = 6.dp),
              contentAlignment = Alignment.Center,
            ) {
              Text(
                text = filter.labelFa,
                style = MaterialTheme.typography.labelSmall,
                fontFamily = VazirmatnFontFamily,
                color = if (active) NeonEmeraldGlow else TextSecondary,
              )
            }
          }
        }

        // Raw Chronological Log Terminal Container (LTR monospace for exact technical readability)
        Box(
          modifier =
            Modifier.fillMaxWidth()
              .weight(1f)
              .clip(RoundedCornerShape(14.dp))
              .background(ObsidianBackground)
              .border(1.dp, TextMuted.copy(alpha = 0.22f), RoundedCornerShape(14.dp))
              .padding(10.dp)
              .testTag("full_logs_terminal_list"),
        ) {
          if (filteredEntries.isEmpty()) {
            Text(
              text = stringResource(R.string.full_logs_empty),
              style = MaterialTheme.typography.bodySmall,
              fontFamily = VazirmatnFontFamily,
              color = TextMuted,
              modifier = Modifier.align(Alignment.Center),
            )
          } else {
            CompositionLocalProvider(LocalLayoutDirection provides LayoutDirection.Ltr) {
              LazyColumn(
                state = listState,
                verticalArrangement = Arrangement.spacedBy(5.dp),
              ) {
                items(items = filteredEntries, key = { it.id }) { entry ->
                  val badgeColor =
                    when {
                      entry.isError -> CrimsonAlert
                      entry.category == FullLogCategory.CALIBRATION -> CyberCyan
                      entry.category == FullLogCategory.DNS -> AmberPulse
                      entry.category == FullLogCategory.TUNNEL -> NeonEmeraldGlow
                      entry.category == FullLogCategory.XRAY -> Color(0xFF93C5FD)
                      entry.category == FullLogCategory.PROBE -> Color(0xFF86EFAC)
                      else -> TextSecondary
                    }
                  Text(
                    text = "[${entry.timeFormatted}][${entry.category.tag}] ${entry.message}",
                    fontFamily = FontFamily.Monospace,
                    fontSize = 11.sp,
                    lineHeight = 15.sp,
                    color = badgeColor,
                  )
                }
              }
            }
          }
        }
      }
    }
  }
}
