package com.clara.security.security

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioFormat
import android.media.AudioRecord
import android.media.MediaRecorder
import android.util.Log
import androidx.core.content.ContextCompat
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import kotlin.math.abs
import kotlin.math.sqrt

/**
 * Voice Print Authentication
 * 
 * Kullanıcının ses parmak izi ile ayarlara erişim kontrolü.
 * - Ses kaydı ve analizi
 * - Voice print karşılaştırma
 * - Ayarlara erişim yetkisi
 */
object VoicePrintAuth {
    private const val TAG = "VoicePrintAuth"
    
    private const val SAMPLE_RATE = 44100
    private const val CHANNEL_CONFIG = AudioFormat.CHANNEL_IN_MONO
    private const val AUDIO_FORMAT = AudioFormat.ENCODING_PCM_16BIT
    private const val RECORD_DURATION_MS = 3000 // 3 saniye kayıt
    
    private var context: Context? = null
    private var voicePrintFile: File? = null
    
    private val _isEnrolled = MutableStateFlow(false)
    val isEnrolled: StateFlow<Boolean> = _isEnrolled.asStateFlow()
    
    private val _isVerifying = MutableStateFlow(false)
    val isVerifying: StateFlow<Boolean> = _isVerifying.asStateFlow()
    
    // Kayıtlı ses özellikleri
    private var enrolledFeatures: VoiceFeatures? = null
    
    /**
     * Initialize
     */
    fun initialize(ctx: Context) {
        context = ctx.applicationContext
        voicePrintFile = File(ctx.filesDir, "voiceprint.dat")
        
        // Kayıtlı voice print var mı kontrol et
        if (voicePrintFile?.exists() == true) {
            loadEnrolledVoicePrint()
        }
        
        Log.d(TAG, "VoicePrintAuth initialized, enrolled: ${_isEnrolled.value}")
    }
    
    /**
     * Yeni ses parmak izi kaydet
     */
    suspend fun enrollVoicePrint(phrase: String = "Clara beni tanı"): Boolean = withContext(Dispatchers.IO) {
        Log.d(TAG, "Starting voice enrollment...")
        
        if (!hasRecordPermission()) {
            Log.e(TAG, "No record permission")
            return@withContext false
        }
        
        try {
            // Ses kaydet
            val audioData = recordAudio()
            if (audioData.isEmpty()) {
                Log.e(TAG, "Failed to record audio")
                return@withContext false
            }
            
            // Ses özelliklerini çıkar
            val features = extractVoiceFeatures(audioData)
            
            // Kaydet
            enrolledFeatures = features
            saveEnrolledVoicePrint(features)
            
            _isEnrolled.value = true
            Log.d(TAG, "Voice enrollment SUCCESS")
            
            true
        } catch (e: Exception) {
            Log.e(TAG, "Voice enrollment failed", e)
            false
        }
    }
    
    /**
     * Ses ile doğrulama yap
     */
    suspend fun verifyVoice(): VoiceVerifyResult = withContext(Dispatchers.IO) {
        if (enrolledFeatures == null) {
            return@withContext VoiceVerifyResult(false, 0f, "Kayıtlı ses bulunamadı")
        }
        
        if (!hasRecordPermission()) {
            return@withContext VoiceVerifyResult(false, 0f, "Mikrofon izni yok")
        }
        
        _isVerifying.value = true
        
        try {
            Log.d(TAG, "Starting voice verification...")
            
            // Ses kaydet
            val audioData = recordAudio()
            if (audioData.isEmpty()) {
                return@withContext VoiceVerifyResult(false, 0f, "Ses kaydı başarısız")
            }
            
            // Ses özelliklerini çıkar
            val currentFeatures = extractVoiceFeatures(audioData)
            
            // Karşılaştır
            val similarity = compareVoiceFeatures(enrolledFeatures!!, currentFeatures)
            
            Log.d(TAG, "Voice similarity: $similarity")
            
            val threshold = 0.75f // %75 benzerlik eşiği
            val isMatch = similarity >= threshold
            
            VoiceVerifyResult(
                isMatch = isMatch,
                confidence = similarity,
                message = if (isMatch) "Ses doğrulandı" else "Ses eşleşmedi"
            )
        } catch (e: Exception) {
            Log.e(TAG, "Voice verification failed", e)
            VoiceVerifyResult(false, 0f, "Doğrulama hatası: ${e.message}")
        } finally {
            _isVerifying.value = false
        }
    }
    
    /**
     * Ayarlara erişim izni ver
     */
    suspend fun requestSettingsAccess(): Boolean {
        val result = verifyVoice()
        
        if (result.isMatch) {
            Log.d(TAG, "Settings access GRANTED (confidence: ${result.confidence})")
            return true
        } else {
            Log.w(TAG, "Settings access DENIED")
            return false
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // AUDIO RECORDING
    // ═══════════════════════════════════════════════════════════════════════════
    
    private suspend fun recordAudio(): ShortArray = withContext(Dispatchers.IO) {
        val bufferSize = AudioRecord.getMinBufferSize(SAMPLE_RATE, CHANNEL_CONFIG, AUDIO_FORMAT)
        
        if (bufferSize == AudioRecord.ERROR || bufferSize == AudioRecord.ERROR_BAD_VALUE) {
            Log.e(TAG, "Invalid buffer size")
            return@withContext shortArrayOf()
        }
        
        val audioRecord = try {
            AudioRecord(
                MediaRecorder.AudioSource.MIC,
                SAMPLE_RATE,
                CHANNEL_CONFIG,
                AUDIO_FORMAT,
                bufferSize
            )
        } catch (e: SecurityException) {
            Log.e(TAG, "No permission to record", e)
            return@withContext shortArrayOf()
        }
        
        if (audioRecord.state != AudioRecord.STATE_INITIALIZED) {
            Log.e(TAG, "AudioRecord failed to initialize")
            return@withContext shortArrayOf()
        }
        
        val totalSamples = SAMPLE_RATE * RECORD_DURATION_MS / 1000
        val audioData = ShortArray(totalSamples)
        var totalRead = 0
        
        audioRecord.startRecording()
        
        while (totalRead < totalSamples) {
            val toRead = minOf(bufferSize / 2, totalSamples - totalRead)
            val read = audioRecord.read(audioData, totalRead, toRead)
            if (read > 0) {
                totalRead += read
            } else {
                break
            }
        }
        
        audioRecord.stop()
        audioRecord.release()
        
        Log.d(TAG, "Recorded $totalRead samples")
        
        audioData.copyOf(totalRead)
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FEATURE EXTRACTION
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun extractVoiceFeatures(audioData: ShortArray): VoiceFeatures {
        // Basit ses özellikleri çıkarma
        // Gerçek bir voice print için MFCC kullanılmalı
        
        // 1. RMS Energy
        var sumSquares = 0.0
        for (sample in audioData) {
            sumSquares += sample.toDouble() * sample.toDouble()
        }
        val rmsEnergy = sqrt(sumSquares / audioData.size).toFloat()
        
        // 2. Zero Crossing Rate
        var zeroCrossings = 0
        for (i in 1 until audioData.size) {
            if ((audioData[i] >= 0 && audioData[i-1] < 0) ||
                (audioData[i] < 0 && audioData[i-1] >= 0)) {
                zeroCrossings++
            }
        }
        val zcr = zeroCrossings.toFloat() / audioData.size
        
        // 3. Spectral Centroid (basitleştirilmiş)
        var weightedSum = 0.0
        var sum = 0.0
        for (i in audioData.indices) {
            val magnitude = abs(audioData[i].toDouble())
            weightedSum += i * magnitude
            sum += magnitude
        }
        val spectralCentroid = if (sum > 0) (weightedSum / sum).toFloat() else 0f
        
        // 4. Peak amplitude
        val peakAmplitude = audioData.maxOfOrNull { abs(it.toInt()) }?.toFloat() ?: 0f
        
        // 5. Average amplitude
        val avgAmplitude = audioData.map { abs(it.toInt()) }.average().toFloat()
        
        return VoiceFeatures(
            rmsEnergy = rmsEnergy,
            zeroCrossingRate = zcr,
            spectralCentroid = spectralCentroid,
            peakAmplitude = peakAmplitude,
            averageAmplitude = avgAmplitude
        )
    }
    
    private fun compareVoiceFeatures(enrolled: VoiceFeatures, current: VoiceFeatures): Float {
        // Normalize edilmiş özellik karşılaştırması
        
        val rmsDiff = 1f - minOf(1f, abs(enrolled.rmsEnergy - current.rmsEnergy) / (enrolled.rmsEnergy + 1f))
        val zcrDiff = 1f - minOf(1f, abs(enrolled.zeroCrossingRate - current.zeroCrossingRate) / 0.1f)
        val scDiff = 1f - minOf(1f, abs(enrolled.spectralCentroid - current.spectralCentroid) / (enrolled.spectralCentroid + 1f))
        val peakDiff = 1f - minOf(1f, abs(enrolled.peakAmplitude - current.peakAmplitude) / (enrolled.peakAmplitude + 1f))
        val avgDiff = 1f - minOf(1f, abs(enrolled.averageAmplitude - current.averageAmplitude) / (enrolled.averageAmplitude + 1f))
        
        // Ağırlıklı ortalama
        return (rmsDiff * 0.25f + zcrDiff * 0.15f + scDiff * 0.25f + peakDiff * 0.15f + avgDiff * 0.20f)
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PERSISTENCE
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun saveEnrolledVoicePrint(features: VoiceFeatures) {
        voicePrintFile?.let { file ->
            try {
                val data = "${features.rmsEnergy},${features.zeroCrossingRate},${features.spectralCentroid},${features.peakAmplitude},${features.averageAmplitude}"
                file.writeText(data)
                Log.d(TAG, "Voice print saved")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to save voice print", e)
            }
        }
    }
    
    private fun loadEnrolledVoicePrint() {
        voicePrintFile?.let { file ->
            try {
                if (file.exists()) {
                    val data = file.readText().split(",")
                    if (data.size >= 5) {
                        enrolledFeatures = VoiceFeatures(
                            rmsEnergy = data[0].toFloat(),
                            zeroCrossingRate = data[1].toFloat(),
                            spectralCentroid = data[2].toFloat(),
                            peakAmplitude = data[3].toFloat(),
                            averageAmplitude = data[4].toFloat()
                        )
                        _isEnrolled.value = true
                        Log.d(TAG, "Voice print loaded")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to load voice print", e)
            }
        }
    }
    
    /**
     * Voice print'i sil
     */
    fun deleteVoicePrint() {
        voicePrintFile?.delete()
        enrolledFeatures = null
        _isEnrolled.value = false
        Log.d(TAG, "Voice print deleted")
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // HELPERS
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun hasRecordPermission(): Boolean {
        return context?.let {
            ContextCompat.checkSelfPermission(it, Manifest.permission.RECORD_AUDIO) ==
                    PackageManager.PERMISSION_GRANTED
        } ?: false
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // DATA CLASSES
    // ═══════════════════════════════════════════════════════════════════════════
    
    data class VoiceFeatures(
        val rmsEnergy: Float,
        val zeroCrossingRate: Float,
        val spectralCentroid: Float,
        val peakAmplitude: Float,
        val averageAmplitude: Float
    )
    
    data class VoiceVerifyResult(
        val isMatch: Boolean,
        val confidence: Float,
        val message: String
    )
}
