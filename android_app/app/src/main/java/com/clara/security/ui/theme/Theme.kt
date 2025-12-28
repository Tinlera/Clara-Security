package com.clara.security.ui.theme

import android.app.Activity
import android.os.Build
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.toArgb
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║                    CLARA Security - Cyberpunk Theme                       ║
// ║                        Matrix / Hacker Aesthetic                          ║
// ╚══════════════════════════════════════════════════════════════════════════╝

// === NEON COLORS ===
val NeonGreen = Color(0xFF00FF41)           // Matrix yeşili
val NeonGreenDark = Color(0xFF00CC33)       // Daha koyu yeşil
val NeonGreenLight = Color(0xFF39FF14)      // Parlak yeşil
val NeonCyan = Color(0xFF00FFFF)            // Cyan/Turkuaz
val NeonPurple = Color(0xFFBF00FF)          // Neon mor
val NeonBlue = Color(0xFF00D4FF)            // Elektrik mavisi
val NeonPink = Color(0xFFFF00FF)            // Magenta

// === DARK BACKGROUNDS ===
val MatrixBlack = Color(0xFF000000)         // Saf siyah
val MatrixDarkGreen = Color(0xFF001100)     // Çok koyu yeşil
val MatrixGray = Color(0xFF0D0D0D)          // Kart arkaplanı
val MatrixGrayLight = Color(0xFF1A1A1A)     // Hafif açık
val MatrixGrayMedium = Color(0xFF262626)    // Orta gri

// === STATUS COLORS ===
val CyberSuccess = Color(0xFF00FF41)        // Yeşil = Güvenli
val CyberWarning = Color(0xFFFFB800)        // Altın sarısı = Uyarı
val CyberDanger = Color(0xFFFF0040)         // Neon kırmızı = Tehlike
val CyberInfo = Color(0xFF00D4FF)           // Cyan = Bilgi

// === LEGACY COMPATIBILITY (eski kodlar için) ===
val CLARAPrimary = NeonGreen
val CLARASecondary = NeonCyan
val CLARATertiary = NeonPurple
val CLARAError = CyberDanger
val CLARASuccess = CyberSuccess
val CLARAWarning = CyberWarning

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║                              DARK THEME                                   ║
// ║                    (Ana tema - Matrix aesthetic)                          ║
// ╚══════════════════════════════════════════════════════════════════════════╝
private val CyberpunkDarkColorScheme = darkColorScheme(
    // Ana renkler
    primary = NeonGreen,
    onPrimary = MatrixBlack,
    primaryContainer = NeonGreen.copy(alpha = 0.15f),
    onPrimaryContainer = NeonGreen,
    
    // İkincil renkler
    secondary = NeonCyan,
    onSecondary = MatrixBlack,
    secondaryContainer = NeonCyan.copy(alpha = 0.15f),
    onSecondaryContainer = NeonCyan,
    
    // Üçüncül renkler
    tertiary = NeonPurple,
    onTertiary = Color.White,
    tertiaryContainer = NeonPurple.copy(alpha = 0.15f),
    onTertiaryContainer = NeonPurple,
    
    // Hata renkleri
    error = CyberDanger,
    onError = Color.White,
    errorContainer = CyberDanger.copy(alpha = 0.15f),
    onErrorContainer = CyberDanger,
    
    // Arkaplan
    background = MatrixBlack,
    onBackground = NeonGreen.copy(alpha = 0.9f),
    
    // Yüzeyler
    surface = MatrixGray,
    onSurface = Color(0xFFE0E0E0),
    surfaceVariant = MatrixGrayLight,
    onSurfaceVariant = Color(0xFFB0B0B0),
    
    // Kontur
    outline = NeonGreen.copy(alpha = 0.3f),
    outlineVariant = NeonGreen.copy(alpha = 0.15f),
    
    // Ters renkler
    inverseSurface = NeonGreen,
    inverseOnSurface = MatrixBlack,
    inversePrimary = MatrixDarkGreen,
    
    // Diğer
    scrim = MatrixBlack.copy(alpha = 0.8f),
    surfaceTint = NeonGreen
)

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║                             LIGHT THEME                                   ║
// ║                    (Alternatif - hala cyberpunk)                          ║
// ╚══════════════════════════════════════════════════════════════════════════╝
private val CyberpunkLightColorScheme = lightColorScheme(
    primary = NeonGreenDark,
    onPrimary = Color.White,
    primaryContainer = NeonGreen.copy(alpha = 0.2f),
    onPrimaryContainer = NeonGreenDark,
    
    secondary = Color(0xFF00B8B8),
    onSecondary = Color.White,
    secondaryContainer = NeonCyan.copy(alpha = 0.2f),
    onSecondaryContainer = Color(0xFF006666),
    
    tertiary = Color(0xFF9900CC),
    onTertiary = Color.White,
    tertiaryContainer = NeonPurple.copy(alpha = 0.2f),
    onTertiaryContainer = Color(0xFF660088),
    
    error = Color(0xFFCC0033),
    onError = Color.White,
    errorContainer = CyberDanger.copy(alpha = 0.2f),
    onErrorContainer = Color(0xFF990026),
    
    background = Color(0xFFF5FFF5),          // Çok hafif yeşilimsi beyaz
    onBackground = Color(0xFF001100),
    
    surface = Color.White,
    onSurface = Color(0xFF001100),
    surfaceVariant = Color(0xFFE8F5E8),
    onSurfaceVariant = Color(0xFF003300),
    
    outline = NeonGreenDark.copy(alpha = 0.5f),
    outlineVariant = NeonGreenDark.copy(alpha = 0.2f),
    
    inverseSurface = MatrixBlack,
    inverseOnSurface = NeonGreen,
    inversePrimary = NeonGreen,
    
    scrim = MatrixBlack.copy(alpha = 0.5f),
    surfaceTint = NeonGreenDark
)

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║                              THEME COMPOSABLE                             ║
// ╚══════════════════════════════════════════════════════════════════════════╝
@Composable
fun CLARASecurityTheme(
    darkTheme: Boolean = true,              // Default olarak dark theme
    dynamicColor: Boolean = false,          // Dynamic color KAPALI (kendi temamız için)
    content: @Composable () -> Unit
) {
    // Her zaman cyberpunk teması kullan
    val colorScheme = if (darkTheme) CyberpunkDarkColorScheme else CyberpunkLightColorScheme
    
    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = MatrixBlack.toArgb()
            window.navigationBarColor = MatrixBlack.toArgb()
            WindowCompat.getInsetsController(window, view).isAppearanceLightStatusBars = false
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = CyberpunkTypography,
        content = content
    )
}

// ╔══════════════════════════════════════════════════════════════════════════╗
// ║                           UTILITY EXTENSIONS                              ║
// ╚══════════════════════════════════════════════════════════════════════════╝

/**
 * Güven puanına göre renk döndür
 */
fun getScoreColor(score: Int): Color = when {
    score >= 80 -> CyberSuccess
    score >= 50 -> NeonCyan
    score >= 20 -> CyberWarning
    else -> CyberDanger
}

/**
 * Neon glow efekti için alpha değeri
 */
fun glowAlpha(intensity: Float = 0.3f): Float = intensity
