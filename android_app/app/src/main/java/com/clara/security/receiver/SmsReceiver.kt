package com.clara.security.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.clara.security.ai.ClaraAI
import com.clara.security.data.ThreatDatabase
import com.clara.security.service.NotificationService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * SMS Receiver
 * 
 * Gelen SMS'leri dinler ve AI ile phishing analizi yapar.
 * Tehdit tespit edilirse bildirim gösterir.
 */
class SmsReceiver : BroadcastReceiver() {
    
    companion object {
        private const val TAG = "SmsReceiver"
    }
    
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return
        
        Log.d(TAG, "SMS received")
        
        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)
        if (messages.isNullOrEmpty()) return
        
        // Her mesajı analiz et
        messages.forEach { sms ->
            val sender = sms.displayOriginatingAddress ?: "Unknown"
            val body = sms.messageBody ?: ""
            
            if (body.isBlank()) return@forEach
            
            Log.d(TAG, "Analyzing SMS from: $sender")
            
            // Arka planda AI analizi yap
            CoroutineScope(Dispatchers.IO).launch {
                try {
                    // Önce hızlı kural tabanlı kontrol
                    val quickResult = quickPhishingCheck(body)
                    
                    if (quickResult.isDefinitelyPhishing) {
                        // Kesin phishing - hemen bildirim
                        showThreatNotification(context, sender, body, "TEHLİKELİ", quickResult.reason)
                        saveThreat(context, sender, body, "PHISHING", quickResult.reason)
                    } else if (quickResult.isSuspicious) {
                        // Şüpheli - AI ile detaylı analiz
                        val aiResult = ClaraAI.analyzeSms(body, sender)
                        
                        when (aiResult.threatLevel) {
                            ClaraAI.ThreatLevel.DANGEROUS -> {
                                showThreatNotification(context, sender, body, "TEHLİKELİ", aiResult.explanation)
                                saveThreat(context, sender, body, "PHISHING", aiResult.explanation)
                            }
                            ClaraAI.ThreatLevel.SUSPICIOUS -> {
                                showThreatNotification(context, sender, body, "ŞÜPHELİ", aiResult.explanation)
                                saveThreat(context, sender, body, "SUSPICIOUS", aiResult.explanation)
                            }
                            else -> {
                                Log.d(TAG, "SMS is safe: $sender")
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "SMS analysis failed", e)
                }
            }
        }
    }
    
    /**
     * Hızlı kural tabanlı phishing kontrolü
     */
    private fun quickPhishingCheck(message: String): QuickCheckResult {
        val lowerMessage = message.lowercase()
        
        // Kesin phishing kalıpları (Türkiye'de yaygın)
        val definitePhishingPatterns = listOf(
            // Sahte banka mesajları
            "hesabınız.*(?:bloke|askıya|donduruldu)",
            "kart.*(?:şifre|güncelle|onayla)",
            "3d.*secure.*güncelle",
            "internet.*bankacılık.*giriş",
            
            // Sahte kargo mesajları
            "kargo.*(?:tıklayın|gümrük|ödeme)",
            "paket.*bekliyor.*tıkla",
            "gümrük.*vergisi.*öde",
            
            // Acil para talepleri
            "acil.*(?:para|havale|eft)",
            "kazandınız.*tıklayın",
            "hediye.*(?:kazan|çek|link)",
            
            // Sahte devlet/vergi
            "e-devlet.*güncelle",
            "vergi.*iade.*tıkla",
            "sgk.*borç.*öde"
        )
        
        // Şüpheli URL kalıpları
        val suspiciousUrlPatterns = listOf(
            "bit\\.ly", "tinyurl", "goo\\.gl",
            "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}",  // IP adresi
            "(?<!@)[a-z0-9]+-[a-z0-9]+\\.[a-z]{2,}",      // Şüpheli domain
            "\\.(tk|ml|ga|cf|gq)(/|$)"                     // Ücretsiz TLD'ler
        )
        
        // Kesin phishing kontrolü
        for (pattern in definitePhishingPatterns) {
            if (Regex(pattern, RegexOption.IGNORE_CASE).containsMatchIn(message)) {
                return QuickCheckResult(
                    isDefinitelyPhishing = true,
                    isSuspicious = true,
                    reason = "Bilinen phishing kalıbı tespit edildi"
                )
            }
        }
        
        // URL içeriyor mu?
        val hasUrl = message.contains("http") || message.contains("www.") || 
                     Regex("[a-z0-9.-]+\\.[a-z]{2,}/\\S*", RegexOption.IGNORE_CASE).containsMatchIn(message)
        
        // Şüpheli URL kontrolü
        if (hasUrl) {
            for (pattern in suspiciousUrlPatterns) {
                if (Regex(pattern, RegexOption.IGNORE_CASE).containsMatchIn(message)) {
                    return QuickCheckResult(
                        isDefinitelyPhishing = false,
                        isSuspicious = true,
                        reason = "Şüpheli URL tespit edildi"
                    )
                }
            }
            
            // URL var ama şüpheli değil - yine de AI ile kontrol et
            return QuickCheckResult(
                isDefinitelyPhishing = false,
                isSuspicious = true,
                reason = "Link içeren mesaj"
            )
        }
        
        // Acil/tehdit içeren kelimeler
        val urgentWords = listOf(
            "acil", "hemen", "son şans", "süre doluyor",
            "hesap.*kapatılacak", "engellendi", "askıya"
        )
        
        for (word in urgentWords) {
            if (Regex(word, RegexOption.IGNORE_CASE).containsMatchIn(message)) {
                return QuickCheckResult(
                    isDefinitelyPhishing = false,
                    isSuspicious = true,
                    reason = "Aciliyet içeren mesaj"
                )
            }
        }
        
        return QuickCheckResult(
            isDefinitelyPhishing = false,
            isSuspicious = false,
            reason = ""
        )
    }
    
    private fun showThreatNotification(
        context: Context,
        sender: String,
        message: String,
        level: String,
        explanation: String
    ) {
        NotificationService.showThreatNotification(
            context = context,
            title = "⚠️ $level SMS Tespit Edildi!",
            body = "Gönderen: $sender\n$explanation",
            threatId = System.currentTimeMillis().toString()
        )
    }
    
    private suspend fun saveThreat(
        context: Context,
        sender: String,
        message: String,
        type: String,
        description: String
    ) {
        ThreatDatabase.saveThreat(
            context = context,
            type = type,
            source = sender,
            description = description,
            data = message
        )
    }
    
    data class QuickCheckResult(
        val isDefinitelyPhishing: Boolean,
        val isSuspicious: Boolean,
        val reason: String
    )
}
