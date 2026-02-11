package com.vpn.client.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// Light Theme Colors
private val LightPrimary = Color(0xFF0D6EFD)
private val LightOnPrimary = Color(0xFFFFFFFF)
private val LightPrimaryContainer = Color(0xFFD8E2FF)
private val LightOnPrimaryContainer = Color(0xFF001A42)

private val LightSecondary = Color(0xFF565F71)
private val LightOnSecondary = Color(0xFFFFFFFF)
private val LightSecondaryContainer = Color(0xFFDAE2F9)
private val LightOnSecondaryContainer = Color(0xFF131C2B)

private val LightTertiary = Color(0xFF705575)
private val LightOnTertiary = Color(0xFFFFFFFF)
private val LightTertiaryContainer = Color(0xFFFAD8FD)
private val LightOnTertiaryContainer = Color(0xFF28132F)

private val LightError = Color(0xFFBA1A1A)
private val LightOnError = Color(0xFFFFFFFF)
private val LightErrorContainer = Color(0xFFFFDAD6)
private val LightOnErrorContainer = Color(0xFF410002)

private val LightBackground = Color(0xFFFEFBFF)
private val LightOnBackground = Color(0xFF1B1B1F)
private val LightSurface = Color(0xFFFEFBFF)
private val LightOnSurface = Color(0xFF1B1B1F)
private val LightSurfaceVariant = Color(0xFFE1E2EC)
private val LightOnSurfaceVariant = Color(0xFF44474F)
private val LightOutline = Color(0xFF74777F)

// Dark Theme Colors
private val DarkPrimary = Color(0xFFAEC6FF)
private val DarkOnPrimary = Color(0xFF002E6A)
private val DarkPrimaryContainer = Color(0xFF004494)
private val DarkOnPrimaryContainer = Color(0xFFD8E2FF)

private val DarkSecondary = Color(0xFFBEC6DC)
private val DarkOnSecondary = Color(0xFF283041)
private val DarkSecondaryContainer = Color(0xFF3E4758)
private val DarkOnSecondaryContainer = Color(0xFFDAE2F9)

private val DarkTertiary = Color(0xFFDDBCE0)
private val DarkOnTertiary = Color(0xFF3F2844)
private val DarkTertiaryContainer = Color(0xFF573E5C)
private val DarkOnTertiaryContainer = Color(0xFFFAD8FD)

private val DarkError = Color(0xFFFFB4AB)
private val DarkOnError = Color(0xFF690005)
private val DarkErrorContainer = Color(0xFF93000A)
private val DarkOnErrorContainer = Color(0xFFFFDAD6)

private val DarkBackground = Color(0xFF1B1B1F)
private val DarkOnBackground = Color(0xFFE4E2E6)
private val DarkSurface = Color(0xFF1B1B1F)
private val DarkOnSurface = Color(0xFFE4E2E6)
private val DarkSurfaceVariant = Color(0xFF44474F)
private val DarkOnSurfaceVariant = Color(0xFFC4C6D0)
private val DarkOutline = Color(0xFF8E9099)

private val LightColorScheme = lightColorScheme(
    primary = LightPrimary,
    onPrimary = LightOnPrimary,
    primaryContainer = LightPrimaryContainer,
    onPrimaryContainer = LightOnPrimaryContainer,
    secondary = LightSecondary,
    onSecondary = LightOnSecondary,
    secondaryContainer = LightSecondaryContainer,
    onSecondaryContainer = LightOnSecondaryContainer,
    tertiary = LightTertiary,
    onTertiary = LightOnTertiary,
    tertiaryContainer = LightTertiaryContainer,
    onTertiaryContainer = LightOnTertiaryContainer,
    error = LightError,
    onError = LightOnError,
    errorContainer = LightErrorContainer,
    onErrorContainer = LightOnErrorContainer,
    background = LightBackground,
    onBackground = LightOnBackground,
    surface = LightSurface,
    onSurface = LightOnSurface,
    surfaceVariant = LightSurfaceVariant,
    onSurfaceVariant = LightOnSurfaceVariant,
    outline = LightOutline
)

private val DarkColorScheme = darkColorScheme(
    primary = DarkPrimary,
    onPrimary = DarkOnPrimary,
    primaryContainer = DarkPrimaryContainer,
    onPrimaryContainer = DarkOnPrimaryContainer,
    secondary = DarkSecondary,
    onSecondary = DarkOnSecondary,
    secondaryContainer = DarkSecondaryContainer,
    onSecondaryContainer = DarkOnSecondaryContainer,
    tertiary = DarkTertiary,
    onTertiary = DarkOnTertiary,
    tertiaryContainer = DarkTertiaryContainer,
    onTertiaryContainer = DarkOnTertiaryContainer,
    error = DarkError,
    onError = DarkOnError,
    errorContainer = DarkErrorContainer,
    onErrorContainer = DarkOnErrorContainer,
    background = DarkBackground,
    onBackground = DarkOnBackground,
    surface = DarkSurface,
    onSurface = DarkOnSurface,
    surfaceVariant = DarkSurfaceVariant,
    onSurfaceVariant = DarkOnSurfaceVariant,
    outline = DarkOutline
)

@Composable
fun VpnClientTheme(
    darkTheme: Boolean = isSystemInDarkTheme(),
    dynamicColor: Boolean = true,
    content: @Composable () -> Unit
) {
    val colorScheme = when {
        dynamicColor && Build.VERSION.SDK_INT >= Build.VERSION_CODES.S -> {
            val context = LocalContext.current
            if (darkTheme) dynamicDarkColorScheme(context) else dynamicLightColorScheme(context)
        }
        darkTheme -> DarkColorScheme
        else -> LightColorScheme
    }

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = colorScheme.surface.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = !darkTheme
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = Typography,
        content = content
    )
}

// Typography
private val Typography = Typography()
