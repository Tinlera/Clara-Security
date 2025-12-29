package com.clara.security.security

import android.content.Context
import android.content.SharedPreferences
import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Security Preferences
 * 
 * Tüm güvenlik ayarları burada yönetilir.
 * DEFAULT: TÜM ÖZELLİKLER AÇIK
 */
object SecurityPreferences {
    private const val TAG = "SecurityPreferences"
    private const val PREFS_NAME = "clara_security_prefs"
    
    private var prefs: SharedPreferences? = null
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SETTINGS KEYS
    // ═══════════════════════════════════════════════════════════════════════════
    
    private const val KEY_ANTI_THEFT_ENABLED = "anti_theft_enabled"
    private const val KEY_OVERLAY_LOCK_ENABLED = "overlay_lock_enabled"
    private const val KEY_AI_AUTO_ACTION_ENABLED = "ai_auto_action_enabled"
    private const val KEY_VOICE_PRINT_ENABLED = "voice_print_enabled"
    private const val KEY_SMS_SCAN_ENABLED = "sms_scan_enabled"
    private const val KEY_TRACKER_BLOCK_ENABLED = "tracker_block_enabled"
    private const val KEY_SHAKE_SENSITIVITY = "shake_sensitivity"
    private const val KEY_FIRST_RUN = "first_run"
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STATE FLOWS
    // ═══════════════════════════════════════════════════════════════════════════
    
    private val _antiTheftEnabled = MutableStateFlow(true)
    val antiTheftEnabled: StateFlow<Boolean> = _antiTheftEnabled.asStateFlow()
    
    private val _overlayLockEnabled = MutableStateFlow(true)
    val overlayLockEnabled: StateFlow<Boolean> = _overlayLockEnabled.asStateFlow()
    
    private val _aiAutoActionEnabled = MutableStateFlow(true)
    val aiAutoActionEnabled: StateFlow<Boolean> = _aiAutoActionEnabled.asStateFlow()
    
    private val _voicePrintEnabled = MutableStateFlow(true)
    val voicePrintEnabled: StateFlow<Boolean> = _voicePrintEnabled.asStateFlow()
    
    private val _smsScanEnabled = MutableStateFlow(true)
    val smsScanEnabled: StateFlow<Boolean> = _smsScanEnabled.asStateFlow()
    
    private val _trackerBlockEnabled = MutableStateFlow(true)
    val trackerBlockEnabled: StateFlow<Boolean> = _trackerBlockEnabled.asStateFlow()
    
    /**
     * Initialize
     */
    fun initialize(context: Context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        
        // İlk çalıştırma kontrolü
        val isFirstRun = prefs?.getBoolean(KEY_FIRST_RUN, true) ?: true
        
        if (isFirstRun) {
            // İlk çalıştırmada tüm ayarları varsayılan (AÇIK) olarak kaydet
            setDefaults()
            prefs?.edit()?.putBoolean(KEY_FIRST_RUN, false)?.apply()
            Log.d(TAG, "First run - all settings set to DEFAULT (ON)")
        } else {
            // Kayıtlı ayarları yükle
            loadSettings()
        }
    }
    
    /**
     * Varsayılan ayarları uygula (TÜM ÖZELLİKLER AÇIK)
     */
    private fun setDefaults() {
        prefs?.edit()?.apply {
            putBoolean(KEY_ANTI_THEFT_ENABLED, true)
            putBoolean(KEY_OVERLAY_LOCK_ENABLED, true)
            putBoolean(KEY_AI_AUTO_ACTION_ENABLED, true)
            putBoolean(KEY_VOICE_PRINT_ENABLED, true)
            putBoolean(KEY_SMS_SCAN_ENABLED, true)
            putBoolean(KEY_TRACKER_BLOCK_ENABLED, true)
            putFloat(KEY_SHAKE_SENSITIVITY, 25f)
            apply()
        }
        
        _antiTheftEnabled.value = true
        _overlayLockEnabled.value = true
        _aiAutoActionEnabled.value = true
        _voicePrintEnabled.value = true
        _smsScanEnabled.value = true
        _trackerBlockEnabled.value = true
    }
    
    /**
     * Kayıtlı ayarları yükle
     */
    private fun loadSettings() {
        prefs?.let { p ->
            _antiTheftEnabled.value = p.getBoolean(KEY_ANTI_THEFT_ENABLED, true)
            _overlayLockEnabled.value = p.getBoolean(KEY_OVERLAY_LOCK_ENABLED, true)
            _aiAutoActionEnabled.value = p.getBoolean(KEY_AI_AUTO_ACTION_ENABLED, true)
            _voicePrintEnabled.value = p.getBoolean(KEY_VOICE_PRINT_ENABLED, true)
            _smsScanEnabled.value = p.getBoolean(KEY_SMS_SCAN_ENABLED, true)
            _trackerBlockEnabled.value = p.getBoolean(KEY_TRACKER_BLOCK_ENABLED, true)
        }
        
        Log.d(TAG, "Settings loaded - AntiTheft: ${_antiTheftEnabled.value}, Overlay: ${_overlayLockEnabled.value}")
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SETTERS
    // ═══════════════════════════════════════════════════════════════════════════
    
    fun setAntiTheftEnabled(enabled: Boolean) {
        _antiTheftEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_ANTI_THEFT_ENABLED, enabled)?.apply()
        
        if (enabled) {
            AntiTheftManager.startProtection()
        } else {
            AntiTheftManager.stopProtection()
        }
    }
    
    fun setOverlayLockEnabled(enabled: Boolean) {
        _overlayLockEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_OVERLAY_LOCK_ENABLED, enabled)?.apply()
    }
    
    fun setAiAutoActionEnabled(enabled: Boolean) {
        _aiAutoActionEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_AI_AUTO_ACTION_ENABLED, enabled)?.apply()
    }
    
    fun setVoicePrintEnabled(enabled: Boolean) {
        _voicePrintEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_VOICE_PRINT_ENABLED, enabled)?.apply()
    }
    
    fun setSmsScanEnabled(enabled: Boolean) {
        _smsScanEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_SMS_SCAN_ENABLED, enabled)?.apply()
    }
    
    fun setTrackerBlockEnabled(enabled: Boolean) {
        _trackerBlockEnabled.value = enabled
        prefs?.edit()?.putBoolean(KEY_TRACKER_BLOCK_ENABLED, enabled)?.apply()
    }
    
    fun setShakeSensitivity(sensitivity: Float) {
        prefs?.edit()?.putFloat(KEY_SHAKE_SENSITIVITY, sensitivity)?.apply()
        AntiTheftManager.setSensitivity(sensitivity)
    }
    
    fun getShakeSensitivity(): Float {
        return prefs?.getFloat(KEY_SHAKE_SENSITIVITY, 25f) ?: 25f
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // QUICK ACCESS
    // ═══════════════════════════════════════════════════════════════════════════
    
    fun isAntiTheftEnabled() = _antiTheftEnabled.value
    fun isOverlayLockEnabled() = _overlayLockEnabled.value
    fun isAiAutoActionEnabled() = _aiAutoActionEnabled.value
    fun isVoicePrintEnabled() = _voicePrintEnabled.value
    fun isSmsScanEnabled() = _smsScanEnabled.value
    fun isTrackerBlockEnabled() = _trackerBlockEnabled.value
}
