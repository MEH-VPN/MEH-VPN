package com.meh.vpn.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val MehDarkColorScheme = darkColorScheme(
    primary = CyberEmerald,
    onPrimary = ObsidianBg,
    primaryContainer = ObsidianSurfaceElevated,
    onPrimaryContainer = CyberEmerald,
    secondary = ElectricCobalt,
    onSecondary = ObsidianBg,
    secondaryContainer = ObsidianSurfaceElevated,
    onSecondaryContainer = ElectricCobalt,
    tertiary = AmberScan,
    background = ObsidianBg,
    onBackground = TextPrimary,
    surface = ObsidianSurface,
    onSurface = TextPrimary,
    surfaceVariant = ObsidianSurfaceElevated,
    onSurfaceVariant = TextSecondary,
    outline = ObsidianBorder,
    error = CoralAlert,
    onError = Color.White
)

@Composable
fun MyApplicationTheme(
    content: @Composable () -> Unit
) {
    MaterialTheme(
        colorScheme = MehDarkColorScheme,
        typography = Typography,
        content = content
    )
}
