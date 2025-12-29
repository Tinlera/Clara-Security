package com.clara.security.security

import android.annotation.SuppressLint
import android.app.Service
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.graphics.PixelFormat
import android.graphics.Typeface
import android.hardware.biometrics.BiometricPrompt
import android.os.Build
import android.os.CancellationSignal
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.speech.RecognitionListener
import android.speech.RecognizerIntent
import android.speech.SpeechRecognizer
import android.util.Log
import android.view.Gravity
import android.view.MotionEvent
import android.view.View
import android.view.WindowManager
import android.widget.FrameLayout
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.biometric.BiometricManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Overlay Kilit Servisi
 * 
 * "PROTECTED BY CLARA - KERNEL LEVEL ENFORCEMENT" ekranı
 * Açma yöntemleri:
 * 1. Parmak izi + Yüz tanıma (sıralı)
 * 2. "Clara unlock" ses komutu
 */
class OverlayLockService : Service() {
    
    companion object {
        private const val TAG = "OverlayLockService"
        const val ACTION_LOCK = "com.clara.security.LOCK"
        const val ACTION_UNLOCK = "com.clara.security.UNLOCK"
        const val ACTION_SHOW_THREAT = "com.clara.security.SHOW_THREAT"
        
        // Voice unlock phrase
        const val UNLOCK_PHRASE = "clara unlock"
        const val UNLOCK_PHRASE_TR = "klara kilidi aç"
    }
    
    private var windowManager: WindowManager? = null
    private var lockView: View? = null
    private var threatView: View? = null
    
    private var speechRecognizer: SpeechRecognizer? = null
    private var isListening = false
    
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor: Executor = Executors.newSingleThreadExecutor()
    
    // Doğrulama durumu
    private var fingerprintVerified = false
    private var faceVerified = false
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    override fun onCreate() {
        super.onCreate()
        windowManager = getSystemService(Context.WINDOW_SERVICE) as WindowManager
        initSpeechRecognizer()
        Log.d(TAG, "OverlayLockService created")
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_LOCK -> {
                val reason = intent.getStringExtra("reason") ?: "Yetkisiz erişim"
                showLockScreen(reason)
            }
            ACTION_UNLOCK -> {
                hideLockScreen()
            }
            ACTION_SHOW_THREAT -> {
                val type = intent.getStringExtra("threat_type") ?: ""
                val desc = intent.getStringExtra("threat_description") ?: ""
                val action = intent.getStringExtra("action_taken") ?: ""
                showThreatOverlay(type, desc, action)
            }
        }
        return START_STICKY
    }
    
    override fun onDestroy() {
        super.onDestroy()
        hideLockScreen()
        hideThreatOverlay()
        speechRecognizer?.destroy()
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // LOCK SCREEN
    // ═══════════════════════════════════════════════════════════════════════════
    
    @SuppressLint("ClickableViewAccessibility")
    private fun showLockScreen(reason: String) {
        if (lockView != null) return
        
        Log.d(TAG, "Showing lock screen: $reason")
        
        // Ana container
        val container = FrameLayout(this).apply {
            setBackgroundColor(Color.parseColor("#0A0A0A"))
        }
        
        // İçerik layout
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        
        // Üst dekoratif çizgiler (cyberpunk tarzı)
        val topLines = View(this).apply {
            setBackgroundColor(Color.parseColor("#00D4FF"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                4
            ).apply {
                bottomMargin = 32
            }
        }
        content.addView(topLines)
        
        // Ana başlık - PROTECTED
        val protectedText = TextView(this).apply {
            text = "PROTECTED"
            textSize = 42f
            setTextColor(Color.parseColor("#00D4FF"))
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            gravity = Gravity.CENTER
            setShadowLayer(15f, 0f, 0f, Color.parseColor("#00D4FF"))
        }
        content.addView(protectedText)
        
        // BY CLARA
        val byClaraText = TextView(this).apply {
            text = "BY CLARA"
            textSize = 38f
            setTextColor(Color.WHITE)
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = 8
                bottomMargin = 48
            }
        }
        content.addView(byClaraText)
        
        // Kalkan ikonu (basit şekil)
        val shieldIcon = TextView(this).apply {
            text = "🛡️"
            textSize = 72f
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = 48
            }
        }
        content.addView(shieldIcon)
        
        // Alt bilgi
        val statusText = TextView(this).apply {
            text = "SYSTEM STATUS: AI MODERATED DEFENSE"
            textSize = 12f
            setTextColor(Color.parseColor("#00D4FF"))
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
        }
        content.addView(statusText)
        
        val enforcementText = TextView(this).apply {
            text = "KERNEL LEVEL ENFORCEMENT — SECURE"
            textSize = 12f
            setTextColor(Color.parseColor("#00D4FF"))
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = 4
                bottomMargin = 48
            }
        }
        content.addView(enforcementText)
        
        // Açma talimatları
        val instructionText = TextView(this).apply {
            text = "🔐 Parmak izi ile doğrula\n🎤 veya \"Clara unlock\" de"
            textSize = 14f
            setTextColor(Color.parseColor("#808080"))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                topMargin = 32
            }
        }
        content.addView(instructionText)
        
        // Alt dekoratif çizgiler
        val bottomLines = View(this).apply {
            setBackgroundColor(Color.parseColor("#00D4FF"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                4
            ).apply {
                topMargin = 32
            }
        }
        content.addView(bottomLines)
        
        // Container'a ekle
        container.addView(content, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.CENTER
        ))
        
        // Touch listener - dokunulduğunda parmak izi iste
        container.setOnTouchListener { _, event ->
            if (event.action == MotionEvent.ACTION_DOWN) {
                requestFingerprint()
            }
            true
        }
        
        // Window parametreleri
        val params = WindowManager.LayoutParams().apply {
            type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                @Suppress("DEPRECATION")
                WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
            }
            flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                    WindowManager.LayoutParams.FLAG_LAYOUT_NO_LIMITS or
                    WindowManager.LayoutParams.FLAG_FULLSCREEN
            format = PixelFormat.TRANSLUCENT
            width = WindowManager.LayoutParams.MATCH_PARENT
            height = WindowManager.LayoutParams.MATCH_PARENT
            gravity = Gravity.TOP or Gravity.START
        }
        
        lockView = container
        windowManager?.addView(container, params)
        
        // Ses dinlemeyi başlat
        startVoiceRecognition()
        
        // Reset verification state
        fingerprintVerified = false
        faceVerified = false
    }
    
    private fun hideLockScreen() {
        lockView?.let { view ->
            try {
                windowManager?.removeView(view)
            } catch (e: Exception) {
                Log.e(TAG, "Error removing lock view", e)
            }
            lockView = null
        }
        stopVoiceRecognition()
        AntiTheftManager.unlockDevice()
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // THREAT OVERLAY
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun showThreatOverlay(type: String, description: String, actionTaken: String) {
        Log.d(TAG, "Showing threat overlay: $type")
        
        // Eğer zaten var ise kaldır
        hideThreatOverlay()
        
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#E6FF0040")) // Kırmızı transparan
            setPadding(32, 24, 32, 24)
            gravity = Gravity.CENTER_VERTICAL
        }
        
        // Başlık
        val titleText = TextView(this).apply {
            text = "⚠️ TEHDİT ALGILANDI"
            textSize = 16f
            setTextColor(Color.WHITE)
            typeface = Typeface.DEFAULT_BOLD
        }
        container.addView(titleText)
        
        // Açıklama
        val descText = TextView(this).apply {
            text = description
            textSize = 14f
            setTextColor(Color.WHITE)
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 8 }
        }
        container.addView(descText)
        
        // Aksiyon
        val actionText = TextView(this).apply {
            text = "✓ Alınan aksiyon: $actionTaken"
            textSize = 13f
            setTextColor(Color.parseColor("#00FF41"))
            typeface = Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 8 }
        }
        container.addView(actionText)
        
        // Window params - üstte overlay
        val params = WindowManager.LayoutParams().apply {
            type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
            } else {
                @Suppress("DEPRECATION")
                WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
            }
            flags = WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL
            format = PixelFormat.TRANSLUCENT
            width = WindowManager.LayoutParams.MATCH_PARENT
            height = WindowManager.LayoutParams.WRAP_CONTENT
            gravity = Gravity.TOP
            y = 100 // Status bar altında
        }
        
        threatView = container
        windowManager?.addView(container, params)
        
        // 5 saniye sonra otomatik kapat
        mainHandler.postDelayed({
            hideThreatOverlay()
        }, 5000)
    }
    
    private fun hideThreatOverlay() {
        threatView?.let { view ->
            try {
                windowManager?.removeView(view)
            } catch (e: Exception) {
                Log.e(TAG, "Error removing threat view", e)
            }
            threatView = null
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // BIOMETRIC AUTHENTICATION
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun requestFingerprint() {
        Log.d(TAG, "Requesting fingerprint...")
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val biometricPrompt = BiometricPrompt.Builder(this)
                .setTitle("CLARA Güvenlik")
                .setSubtitle("Parmak izi ile doğrula")
                .setDescription("Cihazın kilidini açmak için parmak izinizi kullanın")
                .setNegativeButton("İptal", executor) { _, _ ->
                    Log.d(TAG, "Fingerprint cancelled")
                }
                .build()
            
            val cancellationSignal = CancellationSignal()
            
            biometricPrompt.authenticate(
                cancellationSignal,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                        Log.d(TAG, "Fingerprint SUCCESS")
                        fingerprintVerified = true
                        
                        // Şimdi yüz tanıma iste
                        mainHandler.post {
                            requestFaceRecognition()
                        }
                    }
                    
                    override fun onAuthenticationFailed() {
                        Log.w(TAG, "Fingerprint FAILED")
                        // Yanlış parmak izi - fotoğraf çek
                        captureIntruderPhoto()
                    }
                    
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        Log.e(TAG, "Fingerprint error: $errString")
                    }
                }
            )
        }
    }
    
    private fun requestFaceRecognition() {
        Log.d(TAG, "Requesting face recognition...")
        
        // Android'in yüz tanıma özelliği BiometricPrompt ile gelir
        // Cihaz destekliyorsa yüz tanıma da olur
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val biometricPrompt = BiometricPrompt.Builder(this)
                .setTitle("CLARA Güvenlik")
                .setSubtitle("Yüz ile doğrula")
                .setDescription("Kilidi açmak için yüzünüzü taratın")
                .setNegativeButton("İptal", executor) { _, _ ->
                    Log.d(TAG, "Face recognition cancelled")
                }
                .build()
            
            val cancellationSignal = CancellationSignal()
            
            biometricPrompt.authenticate(
                cancellationSignal,
                executor,
                object : BiometricPrompt.AuthenticationCallback() {
                    override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult?) {
                        Log.d(TAG, "Face recognition SUCCESS - UNLOCKING")
                        faceVerified = true
                        
                        // Her iki doğrulama da tamam - kilidi aç
                        if (fingerprintVerified && faceVerified) {
                            mainHandler.post {
                                hideLockScreen()
                            }
                        }
                    }
                    
                    override fun onAuthenticationFailed() {
                        Log.w(TAG, "Face recognition FAILED")
                        captureIntruderPhoto()
                    }
                    
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        Log.e(TAG, "Face recognition error: $errString")
                        // Yüz tanıma desteklenmiyorsa sadece parmak izi ile aç
                        if (fingerprintVerified) {
                            mainHandler.post {
                                hideLockScreen()
                            }
                        }
                    }
                }
            )
        }
    }
    
    private fun captureIntruderPhoto() {
        Log.w(TAG, "Capturing intruder photo...")
        // TODO: Ön kamera ile fotoğraf çek ve kaydet
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // VOICE RECOGNITION
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun initSpeechRecognizer() {
        if (SpeechRecognizer.isRecognitionAvailable(this)) {
            speechRecognizer = SpeechRecognizer.createSpeechRecognizer(this)
            speechRecognizer?.setRecognitionListener(VoiceListener())
            Log.d(TAG, "Speech recognizer initialized")
        } else {
            Log.w(TAG, "Speech recognition not available")
        }
    }
    
    private fun startVoiceRecognition() {
        if (isListening || speechRecognizer == null) return
        
        val intent = Intent(RecognizerIntent.ACTION_RECOGNIZE_SPEECH).apply {
            putExtra(RecognizerIntent.EXTRA_LANGUAGE_MODEL, RecognizerIntent.LANGUAGE_MODEL_FREE_FORM)
            putExtra(RecognizerIntent.EXTRA_LANGUAGE, "tr-TR")
            putExtra(RecognizerIntent.EXTRA_MAX_RESULTS, 5)
            putExtra(RecognizerIntent.EXTRA_PARTIAL_RESULTS, true)
        }
        
        try {
            speechRecognizer?.startListening(intent)
            isListening = true
            Log.d(TAG, "Voice recognition started")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start voice recognition", e)
        }
    }
    
    private fun stopVoiceRecognition() {
        speechRecognizer?.stopListening()
        isListening = false
    }
    
    private inner class VoiceListener : RecognitionListener {
        override fun onResults(results: android.os.Bundle?) {
            val matches = results?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
            matches?.forEach { phrase ->
                Log.d(TAG, "Voice: $phrase")
                
                if (phrase.lowercase().contains(UNLOCK_PHRASE) ||
                    phrase.lowercase().contains(UNLOCK_PHRASE_TR) ||
                    phrase.lowercase().contains("clara") && phrase.lowercase().contains("unlock")) {
                    
                    Log.d(TAG, "VOICE UNLOCK DETECTED!")
                    
                    // Ses doğrulaması yap (TODO: Voice print comparison)
                    // Şimdilik direkt aç
                    mainHandler.post {
                        hideLockScreen()
                    }
                    return
                }
            }
            
            // Sonuç yoksa tekrar dinle
            mainHandler.postDelayed({
                if (lockView != null) {
                    startVoiceRecognition()
                }
            }, 500)
        }
        
        override fun onPartialResults(partialResults: android.os.Bundle?) {
            val matches = partialResults?.getStringArrayList(SpeechRecognizer.RESULTS_RECOGNITION)
            matches?.forEach { phrase ->
                if (phrase.lowercase().contains("clara")) {
                    Log.d(TAG, "Partial match: $phrase")
                }
            }
        }
        
        override fun onReadyForSpeech(params: android.os.Bundle?) {}
        override fun onBeginningOfSpeech() {}
        override fun onRmsChanged(rmsdB: Float) {}
        override fun onBufferReceived(buffer: ByteArray?) {}
        override fun onEndOfSpeech() {
            isListening = false
        }
        override fun onError(error: Int) {
            isListening = false
            // Hata sonrası tekrar dene
            mainHandler.postDelayed({
                if (lockView != null) {
                    startVoiceRecognition()
                }
            }, 1000)
        }
        override fun onEvent(eventType: Int, params: android.os.Bundle?) {}
    }
}
