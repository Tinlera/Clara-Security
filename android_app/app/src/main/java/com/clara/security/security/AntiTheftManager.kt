package com.clara.security.security

import android.accessibilityservice.AccessibilityService
import android.content.Context
import android.content.Intent
import android.hardware.Sensor
import android.hardware.SensorEvent
import android.hardware.SensorEventListener
import android.hardware.SensorManager
import android.os.Handler
import android.os.Looper
import android.util.Log
import com.clara.security.ai.ClaraAI
import com.clara.security.data.RootExecutor
import com.clara.security.data.ThreatDatabase
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlin.math.sqrt

/**
 * Anti-Theft Manager
 * 
 * Yetkisiz erişim tespiti ve koruma:
 * - Telefon çekilme tespiti (ivme sensörü)
 * - Ani hareket algılama
 * - Yanlış PIN/parmak izi tespiti
 * - AI ile otomatik aksiyon
 */
object AntiTheftManager : SensorEventListener {
    private const val TAG = "AntiTheftManager"
    
    private var sensorManager: SensorManager? = null
    private var accelerometer: Sensor? = null
    private var context: Context? = null
    
    // Ayarlar
    private var isEnabled = true
    private var sensitivityThreshold = 25f  // m/s² - ani hareket eşiği
    private var lastShakeTime = 0L
    private val shakeCooldown = 2000L  // 2 saniye cooldown
    
    // Durum
    private val _isLocked = MutableStateFlow(false)
    val isLocked: StateFlow<Boolean> = _isLocked.asStateFlow()
    
    private val _lastThreat = MutableStateFlow<ThreatEvent?>(null)
    val lastThreat: StateFlow<ThreatEvent?> = _lastThreat.asStateFlow()
    
    // Son ivme değerleri
    private var lastX = 0f
    private var lastY = 0f
    private var lastZ = 0f
    private var lastUpdate = 0L
    
    /**
     * Manager'ı başlat
     */
    fun initialize(ctx: Context) {
        context = ctx.applicationContext
        sensorManager = ctx.getSystemService(Context.SENSOR_SERVICE) as SensorManager
        accelerometer = sensorManager?.getDefaultSensor(Sensor.TYPE_ACCELEROMETER)
        
        Log.d(TAG, "AntiTheftManager initialized")
    }
    
    /**
     * Korumayı aktif et
     */
    fun startProtection() {
        if (!isEnabled) return
        
        accelerometer?.let { sensor ->
            sensorManager?.registerListener(
                this,
                sensor,
                SensorManager.SENSOR_DELAY_NORMAL
            )
            Log.d(TAG, "Protection started - monitoring accelerometer")
        }
    }
    
    /**
     * Korumayı durdur
     */
    fun stopProtection() {
        sensorManager?.unregisterListener(this)
        Log.d(TAG, "Protection stopped")
    }
    
    /**
     * Telefonu kilitle
     */
    fun lockDevice(reason: String) {
        if (_isLocked.value) return
        
        _isLocked.value = true
        Log.w(TAG, "DEVICE LOCKED: $reason")
        
        // Overlay kilit ekranını göster
        context?.let { ctx ->
            val intent = Intent(ctx, OverlayLockService::class.java).apply {
                action = OverlayLockService.ACTION_LOCK
                putExtra("reason", reason)
            }
            ctx.startService(intent)
        }
        
        // Tehdit olarak kaydet
        CoroutineScope(Dispatchers.IO).launch {
            context?.let { ctx ->
                ThreatDatabase.saveThreat(
                    context = ctx,
                    type = "UNAUTHORIZED_ACCESS",
                    source = "AntiTheft",
                    description = reason,
                    severity = 8
                )
            }
        }
    }
    
    /**
     * Telefonu aç (doğrulama sonrası)
     */
    fun unlockDevice() {
        _isLocked.value = false
        Log.d(TAG, "Device unlocked")
        
        context?.let { ctx ->
            val intent = Intent(ctx, OverlayLockService::class.java).apply {
                action = OverlayLockService.ACTION_UNLOCK
            }
            ctx.startService(intent)
        }
    }
    
    /**
     * Tehdit algılandığında bildirim göster
     */
    fun showThreatNotification(threat: ThreatEvent) {
        _lastThreat.value = threat
        
        context?.let { ctx ->
            val intent = Intent(ctx, OverlayLockService::class.java).apply {
                action = OverlayLockService.ACTION_SHOW_THREAT
                putExtra("threat_type", threat.type)
                putExtra("threat_description", threat.description)
                putExtra("action_taken", threat.actionTaken)
            }
            ctx.startService(intent)
        }
    }
    
    /**
     * AI ile tehdit analizi ve otomatik aksiyon
     */
    suspend fun analyzeAndAct(threat: ThreatEvent): String {
        Log.d(TAG, "Analyzing threat with AI: ${threat.type}")
        
        // AI'a sor
        val prompt = """
Güvenlik tehdidi algılandı:
- Tür: ${threat.type}
- Açıklama: ${threat.description}
- Kaynak: ${threat.source}

Ne aksiyonu almalıyım? Kısa ve net yanıt ver:
- KİLİTLE: Cihazı kilitle
- ALARM: Sesli alarm çal
- BİLDİR: Sadece bildirim göster
- YOK: Aksiyon gereksiz
"""
        
        val aiResponse = ClaraAI.askSecurityQuestion(prompt)
        
        // AI yanıtını parse et ve aksiyon al
        val action = when {
            aiResponse.contains("KİLİTLE", ignoreCase = true) -> {
                lockDevice("AI: ${threat.description}")
                "Cihaz kilitlendi"
            }
            aiResponse.contains("ALARM", ignoreCase = true) -> {
                triggerAlarm()
                "Alarm tetiklendi"
            }
            aiResponse.contains("BİLDİR", ignoreCase = true) -> {
                showThreatNotification(threat.copy(actionTaken = "Bildirildi"))
                "Bildirim gösterildi"
            }
            else -> {
                Log.d(TAG, "AI decided no action needed")
                "Aksiyon gereksiz"
            }
        }
        
        return action
    }
    
    /**
     * Sesli alarm tetikle
     */
    private fun triggerAlarm() {
        // TODO: MediaPlayer ile yüksek sesli alarm
        Log.w(TAG, "ALARM TRIGGERED!")
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SENSOR LISTENER
    // ═══════════════════════════════════════════════════════════════════════════
    
    override fun onSensorChanged(event: SensorEvent?) {
        if (event?.sensor?.type != Sensor.TYPE_ACCELEROMETER) return
        
        val currentTime = System.currentTimeMillis()
        
        if ((currentTime - lastUpdate) > 100) { // 100ms aralıkla kontrol
            val timeDiff = currentTime - lastUpdate
            lastUpdate = currentTime
            
            val x = event.values[0]
            val y = event.values[1]
            val z = event.values[2]
            
            // İvme değişimi hesapla
            val deltaX = x - lastX
            val deltaY = y - lastY
            val deltaZ = z - lastZ
            
            val acceleration = sqrt(deltaX * deltaX + deltaY * deltaY + deltaZ * deltaZ) / timeDiff * 10000
            
            lastX = x
            lastY = y
            lastZ = z
            
            // Ani hareket algılama
            if (acceleration > sensitivityThreshold) {
                if (currentTime - lastShakeTime > shakeCooldown) {
                    lastShakeTime = currentTime
                    onSuddenMovement(acceleration)
                }
            }
        }
    }
    
    override fun onAccuracyChanged(sensor: Sensor?, accuracy: Int) {
        // Gerekli değil
    }
    
    /**
     * Ani hareket algılandığında
     */
    private fun onSuddenMovement(acceleration: Float) {
        Log.w(TAG, "Sudden movement detected! Acceleration: $acceleration")
        
        val threat = ThreatEvent(
            type = "SUDDEN_MOVEMENT",
            description = "Telefon ani hareket algıladı (${acceleration.toInt()} m/s²)",
            source = "Accelerometer",
            severity = 6,
            actionTaken = ""
        )
        
        // AI'a sor ve aksiyon al
        CoroutineScope(Dispatchers.IO).launch {
            val action = analyzeAndAct(threat)
            showThreatNotification(threat.copy(actionTaken = action))
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // DATA CLASS
    // ═══════════════════════════════════════════════════════════════════════════
    
    data class ThreatEvent(
        val type: String,
        val description: String,
        val source: String,
        val severity: Int,
        val actionTaken: String,
        val timestamp: Long = System.currentTimeMillis()
    )
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SETTINGS
    // ═══════════════════════════════════════════════════════════════════════════
    
    fun setEnabled(enabled: Boolean) {
        isEnabled = enabled
        if (enabled) startProtection() else stopProtection()
    }
    
    fun setSensitivity(threshold: Float) {
        sensitivityThreshold = threshold
    }
}
