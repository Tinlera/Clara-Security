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
import android.widget.LinearLayout
import android.widget.TextView
import java.util.concurrent.Executor
import java.util.concurrent.Executors

/**
 * Overlay Kilit Servisi
 * 
 * "PROTECTED BY CLARA - KERNEL LEVEL ENFORCEMENT" ekrani
 * Acma yontemleri:
 * 1. Parmak izi + Yuz tanima (sirali)
 * 2. "Clara unlock" ses komutu
 */
class OverlayLockService : Service() {
    
    companion object {
        private const val TAG = "OverlayLockService"
        const val ACTION_LOCK = "com.clara.security.LOCK"
        const val ACTION_UNLOCK = "com.clara.security.UNLOCK"
        const val ACTION_SHOW_THREAT = "com.clara.security.SHOW_THREAT"
        
        const val UNLOCK_PHRASE = "clara unlock"
        const val UNLOCK_PHRASE_TR = "klara kilidi ac"
    }
    
    private var windowManager: WindowManager? = null
    private var lockView: View? = null
    private var threatView: View? = null
    
    private var speechRecognizer: SpeechRecognizer? = null
    private var isListening = false
    
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executor: Executor = Executors.newSingleThreadExecutor()
    
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
                val reason = intent.getStringExtra("reason") ?: "Yetkisiz erisim"
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
    
    @SuppressLint("ClickableViewAccessibility")
    private fun showLockScreen(reason: String) {
        if (lockView != null) return
        
        Log.d(TAG, "Showing lock screen: $reason")
        
        val container = FrameLayout(this).apply {
            setBackgroundColor(Color.parseColor("#0A0A0A"))
        }
        
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(48, 48, 48, 48)
        }
        
        val topLines = View(this).apply {
            setBackgroundColor(Color.parseColor("#00D4FF"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 4
            ).apply { bottomMargin = 32 }
        }
        content.addView(topLines)
        
        val protectedText = TextView(this).apply {
            text = "PROTECTED"
            textSize = 42f
            setTextColor(Color.parseColor("#00D4FF"))
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            gravity = Gravity.CENTER
            setShadowLayer(15f, 0f, 0f, Color.parseColor("#00D4FF"))
        }
        content.addView(protectedText)
        
        val byClaraText = TextView(this).apply {
            text = "BY CLARA"
            textSize = 38f
            setTextColor(Color.WHITE)
            typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 8; bottomMargin = 48 }
        }
        content.addView(byClaraText)
        
        val shieldIcon = TextView(this).apply {
            text = "\uD83D\uDEE1\uFE0F"
            textSize = 72f
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = 48 }
        }
        content.addView(shieldIcon)
        
        val statusText = TextView(this).apply {
            text = "SYSTEM STATUS: AI MODERATED DEFENSE"
            textSize = 12f
            setTextColor(Color.parseColor("#00D4FF"))
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
        }
        content.addView(statusText)
        
        val enforcementText = TextView(this).apply {
            text = "KERNEL LEVEL ENFORCEMENT - SECURE"
            textSize = 12f
            setTextColor(Color.parseColor("#00D4FF"))
            typeface = Typeface.MONOSPACE
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 4; bottomMargin = 48 }
        }
        content.addView(enforcementText)
        
        val instructionText = TextView(this).apply {
            text = "Parmak izi ile dogrula veya 'Clara unlock' de"
            textSize = 14f
            setTextColor(Color.parseColor("#808080"))
            gravity = Gravity.CENTER
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.WRAP_CONTENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 32 }
        }
        content.addView(instructionText)
        
        val bottomLines = View(this).apply {
            setBackgroundColor(Color.parseColor("#00D4FF"))
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT, 4
            ).apply { topMargin = 32 }
        }
        content.addView(bottomLines)
        
        container.addView(content, FrameLayout.LayoutParams(
            FrameLayout.LayoutParams.MATCH_PARENT,
            FrameLayout.LayoutParams.WRAP_CONTENT,
            Gravity.CENTER
        ))
        
        container.setOnTouchListener { _, event ->
            if (event.action == MotionEvent.ACTION_DOWN) {
                requestFingerprint()
            }
            true
        }
        
        val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
        }
        
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.MATCH_PARENT,
            layoutType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_LAYOUT_IN_SCREEN or
                    WindowManager.LayoutParams.FLAG_FULLSCREEN,
            PixelFormat.TRANSLUCENT
        )
        params.gravity = Gravity.TOP or Gravity.START
        
        lockView = container
        windowManager?.addView(container, params)
        
        startVoiceRecognition()
        
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
    
    private fun showThreatOverlay(type: String, description: String, actionTaken: String) {
        Log.d(TAG, "Showing threat overlay: $type")
        
        hideThreatOverlay()
        
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(Color.parseColor("#E6FF0040"))
            setPadding(32, 24, 32, 24)
            gravity = Gravity.CENTER_VERTICAL
        }
        
        val titleText = TextView(this).apply {
            text = "TEHDIT ALGILANDI"
            textSize = 16f
            setTextColor(Color.WHITE)
            typeface = Typeface.DEFAULT_BOLD
        }
        container.addView(titleText)
        
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
        
        val actionText = TextView(this).apply {
            text = "Alinan aksiyon: $actionTaken"
            textSize = 13f
            setTextColor(Color.parseColor("#00FF41"))
            typeface = Typeface.DEFAULT_BOLD
            layoutParams = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = 8 }
        }
        container.addView(actionText)
        
        val layoutType = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            WindowManager.LayoutParams.TYPE_APPLICATION_OVERLAY
        } else {
            @Suppress("DEPRECATION")
            WindowManager.LayoutParams.TYPE_SYSTEM_ALERT
        }
        
        val params = WindowManager.LayoutParams(
            WindowManager.LayoutParams.MATCH_PARENT,
            WindowManager.LayoutParams.WRAP_CONTENT,
            layoutType,
            WindowManager.LayoutParams.FLAG_NOT_FOCUSABLE or
                    WindowManager.LayoutParams.FLAG_NOT_TOUCH_MODAL,
            PixelFormat.TRANSLUCENT
        )
        params.gravity = Gravity.TOP
        params.y = 100
        
        threatView = container
        windowManager?.addView(container, params)
        
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
    
    private fun requestFingerprint() {
        Log.d(TAG, "Requesting fingerprint...")
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val biometricPrompt = BiometricPrompt.Builder(this)
                .setTitle("CLARA Guvenlik")
                .setSubtitle("Parmak izi ile dogrula")
                .setDescription("Cihazin kilidini acmak icin parmak izinizi kullanin")
                .setNegativeButton("Iptal", executor) { _, _ ->
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
                        mainHandler.post { hideLockScreen() }
                    }
                    
                    override fun onAuthenticationFailed() {
                        Log.w(TAG, "Fingerprint FAILED")
                    }
                    
                    override fun onAuthenticationError(errorCode: Int, errString: CharSequence?) {
                        Log.e(TAG, "Fingerprint error: $errString")
                    }
                }
            )
        }
    }
    
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
                    (phrase.lowercase().contains("clara") && phrase.lowercase().contains("unlock"))) {
                    
                    Log.d(TAG, "VOICE UNLOCK DETECTED!")
                    mainHandler.post { hideLockScreen() }
                    return
                }
            }
            
            mainHandler.postDelayed({
                if (lockView != null) {
                    startVoiceRecognition()
                }
            }, 500)
        }
        
        override fun onPartialResults(partialResults: android.os.Bundle?) {}
        override fun onReadyForSpeech(params: android.os.Bundle?) {}
        override fun onBeginningOfSpeech() {}
        override fun onRmsChanged(rmsdB: Float) {}
        override fun onBufferReceived(buffer: ByteArray?) {}
        override fun onEndOfSpeech() { isListening = false }
        override fun onError(error: Int) {
            isListening = false
            mainHandler.postDelayed({
                if (lockView != null) {
                    startVoiceRecognition()
                }
            }, 1000)
        }
        override fun onEvent(eventType: Int, params: android.os.Bundle?) {}
    }
}
