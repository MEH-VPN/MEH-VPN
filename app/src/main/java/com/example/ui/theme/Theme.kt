package com.example.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable

private val MehDarkColorScheme =
  darkColorScheme(
    primary = NeonEmerald,
    onPrimary = ObsidianBackground,
    secondary = CyberCyan,
    onSecondary = ObsidianBackground,
    tertiary = AmberPulse,
    background = ObsidianBackground,
    onBackground = TextPrimary,
    surface = ObsidianSurface,
    onSurface = TextPrimary,
    surfaceVariant = ObsidianElevated,
    onSurfaceVariant = TextSecondary,
    error = CrimsonAlert,
  )

@Composable
fun MyApplicationTheme(
  content: @Composable () -> Unit,
) {
  MaterialTheme(
    colorScheme = MehDarkColorScheme,
    typography = Typography,
    content = content,
  )
}
