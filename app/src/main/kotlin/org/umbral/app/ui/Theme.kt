package org.umbral.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

private val DarkColors = darkColorScheme(
    primary = Color(0xFF8AB4F8),
    secondary = Color(0xFFB9C9E8),
    tertiary = Color(0xFFEFB8C8),
    background = Color(0xFF111318),
    surface = Color(0xFF111318),
    surfaceVariant = Color(0xFF1C1E24),
    error = Color(0xFFF2B8B5)
)

private val LightColors = lightColorScheme(
    primary = Color(0xFF2F5DA8),
    secondary = Color(0xFF565E71),
    tertiary = Color(0xFF7C5361),
    background = Color(0xFFFAF9FD),
    surface = Color(0xFFFAF9FD),
    surfaceVariant = Color(0xFFE1E2EC),
    error = Color(0xFFBA1A1A)
)

@Composable
fun UmbralTheme(content: @Composable () -> Unit) {
    val dark = isSystemInDarkTheme()
    MaterialTheme(
        colorScheme = if (dark) DarkColors else LightColors,
        content = content
    )
}
