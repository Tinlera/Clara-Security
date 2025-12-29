package com.clara.security.ai

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.OutputStreamWriter
import java.net.HttpURLConnection
import java.net.URL

/**
 * CLARA AI Engine
 * 
 * Hugging Face Serverless API üzerinden Llama 3.3 70B kullanarak:
 * - SMS phishing analizi
 * - Tehdit değerlendirmesi
 * - Güvenlik önerileri
 * - Şüpheli davranış tespiti
 */
object ClaraAI {
    private const val TAG = "ClaraAI"
    private const val API_URL = "https://router.huggingface.co/v1/chat/completions"
    
    // API key'i local.properties veya BuildConfig'den al
    // Güvenlik için hardcode edilmemeli!
    // local.properties'e ekle: HF_API_KEY=hf_xxxxx
    private var apiKey: String = ""
    
    private const val MODEL = "meta-llama/Llama-3.3-70B-Instruct"
    
    /**
     * API key'i ayarla (MainActivity'den çağrılmalı)
     */
    fun setApiKey(key: String) {
        apiKey = key
    }
    
    private const val SYSTEM_PROMPT = """Sen CLARA Security AI asistanısın. Türkçe yanıt ver.
Görevin: Android güvenlik tehditleri, phishing ve malware tespiti konusunda analiz yapmak.

Yanıtlarını şu formatta ver:
- SONUÇ: [GÜVENLİ/ŞÜPHELİ/TEHLİKELİ]
- AÇIKLAMA: [Kısa açıklama]
- ÖNERİ: [Kullanıcıya öneri]

Kısa ve net ol. Maksimum 3-4 cümle."""

    /**
     * SMS mesajını phishing açısından analiz et
     */
    suspend fun analyzeSms(message: String, sender: String): SmsAnalysisResult = withContext(Dispatchers.IO) {
        val prompt = """
Aşağıdaki SMS mesajını phishing/dolandırıcılık açısından analiz et:

Gönderen: $sender
Mesaj: $message

Özellikle şunlara dikkat et:
- Sahte banka/kargo mesajları
- Şüpheli linkler
- Acil para transferi talepleri
- Kişisel bilgi istekleri
- Türkiye'de yaygın dolandırıcılık kalıpları
"""
        
        try {
            val response = callLlama(prompt)
            parseSmsAnalysis(response)
        } catch (e: Exception) {
            Log.e(TAG, "SMS analysis failed", e)
            SmsAnalysisResult(
                threatLevel = ThreatLevel.UNKNOWN,
                explanation = "Analiz yapılamadı: ${e.message}",
                recommendation = "Manuel kontrol önerilir"
            )
        }
    }
    
    /**
     * APK/Uygulama izinlerini analiz et
     */
    suspend fun analyzeAppPermissions(
        appName: String,
        packageName: String,
        permissions: List<String>
    ): AppAnalysisResult = withContext(Dispatchers.IO) {
        val prompt = """
Aşağıdaki Android uygulamasının izinlerini güvenlik açısından analiz et:

Uygulama: $appName
Paket: $packageName
İzinler:
${permissions.joinToString("\n") { "- $it" }}

Bu izinler uygulama türüne uygun mu? Şüpheli durum var mı?
"""
        
        try {
            val response = callLlama(prompt)
            parseAppAnalysis(response)
        } catch (e: Exception) {
            Log.e(TAG, "App analysis failed", e)
            AppAnalysisResult(
                riskLevel = RiskLevel.UNKNOWN,
                suspiciousPermissions = emptyList(),
                explanation = "Analiz yapılamadı",
                recommendation = "Manuel kontrol önerilir"
            )
        }
    }
    
    /**
     * URL güvenlik analizi
     */
    suspend fun analyzeUrl(url: String): UrlAnalysisResult = withContext(Dispatchers.IO) {
        val prompt = """
Aşağıdaki URL'yi güvenlik açısından analiz et:

URL: $url

Kontrol et:
- Domain güvenilir mi?
- Phishing belirtisi var mı?
- Typosquatting (benzer domain) şüphesi var mı?
- HTTPS kullanıyor mu?
"""
        
        try {
            val response = callLlama(prompt)
            parseUrlAnalysis(response)
        } catch (e: Exception) {
            Log.e(TAG, "URL analysis failed", e)
            UrlAnalysisResult(
                isSafe = false,
                threatType = "UNKNOWN",
                explanation = "Analiz yapılamadı"
            )
        }
    }
    
    /**
     * Genel güvenlik sorusu sor
     */
    suspend fun askSecurityQuestion(question: String): String = withContext(Dispatchers.IO) {
        try {
            callLlama(question)
        } catch (e: Exception) {
            Log.e(TAG, "AI query failed", e)
            "Üzgünüm, şu anda yanıt veremiyorum. Lütfen daha sonra tekrar deneyin."
        }
    }
    
    /**
     * Tehdit raporu oluştur
     */
    suspend fun generateThreatReport(
        threats: List<ThreatInfo>
    ): String = withContext(Dispatchers.IO) {
        if (threats.isEmpty()) {
            return@withContext "Hiçbir tehdit tespit edilmedi. Cihazınız güvende görünüyor."
        }
        
        val prompt = """
Aşağıdaki güvenlik tehditlerini özetle ve kullanıcıya anlaşılır bir rapor hazırla:

${threats.joinToString("\n") { "- ${it.type}: ${it.description}" }}

Türkçe, kısa ve anlaşılır bir özet yap. Kritik olanları vurgula.
"""
        
        try {
            callLlama(prompt)
        } catch (e: Exception) {
            "Tehdit raporu oluşturulamadı."
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // API ÇAĞRISI
    // ═══════════════════════════════════════════════════════════════════════════
    
    private suspend fun callLlama(userMessage: String): String = withContext(Dispatchers.IO) {
        val url = URL(API_URL)
        val connection = url.openConnection() as HttpURLConnection
        
        try {
            connection.requestMethod = "POST"
            connection.setRequestProperty("Content-Type", "application/json")
            connection.setRequestProperty("Authorization", "Bearer $apiKey")
            connection.doOutput = true
            connection.connectTimeout = 30000
            connection.readTimeout = 60000
            
            val requestBody = JSONObject().apply {
                put("model", MODEL)
                put("messages", JSONArray().apply {
                    put(JSONObject().apply {
                        put("role", "system")
                        put("content", SYSTEM_PROMPT)
                    })
                    put(JSONObject().apply {
                        put("role", "user")
                        put("content", userMessage)
                    })
                })
                put("max_tokens", 500)
                put("temperature", 0.3)
            }
            
            OutputStreamWriter(connection.outputStream).use { writer ->
                writer.write(requestBody.toString())
                writer.flush()
            }
            
            val responseCode = connection.responseCode
            Log.d(TAG, "API response code: $responseCode")
            
            if (responseCode == HttpURLConnection.HTTP_OK) {
                val response = connection.inputStream.bufferedReader().readText()
                val jsonResponse = JSONObject(response)
                
                jsonResponse
                    .getJSONArray("choices")
                    .getJSONObject(0)
                    .getJSONObject("message")
                    .getString("content")
            } else {
                val error = connection.errorStream?.bufferedReader()?.readText() ?: "Unknown error"
                Log.e(TAG, "API error: $error")
                throw RuntimeException("API error: $responseCode - $error")
            }
        } finally {
            connection.disconnect()
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // PARSE FONKSİYONLARI
    // ═══════════════════════════════════════════════════════════════════════════
    
    private fun parseSmsAnalysis(response: String): SmsAnalysisResult {
        val threatLevel = when {
            response.contains("TEHLİKELİ", ignoreCase = true) -> ThreatLevel.DANGEROUS
            response.contains("ŞÜPHELİ", ignoreCase = true) -> ThreatLevel.SUSPICIOUS
            response.contains("GÜVENLİ", ignoreCase = true) -> ThreatLevel.SAFE
            else -> ThreatLevel.UNKNOWN
        }
        
        val explanation = extractSection(response, "AÇIKLAMA") ?: response.take(200)
        val recommendation = extractSection(response, "ÖNERİ") ?: "Dikkatli olun"
        
        return SmsAnalysisResult(threatLevel, explanation, recommendation)
    }
    
    private fun parseAppAnalysis(response: String): AppAnalysisResult {
        val riskLevel = when {
            response.contains("TEHLİKELİ", ignoreCase = true) -> RiskLevel.HIGH
            response.contains("ŞÜPHELİ", ignoreCase = true) -> RiskLevel.MEDIUM
            response.contains("GÜVENLİ", ignoreCase = true) -> RiskLevel.LOW
            else -> RiskLevel.UNKNOWN
        }
        
        return AppAnalysisResult(
            riskLevel = riskLevel,
            suspiciousPermissions = emptyList(), // TODO: Parse from response
            explanation = extractSection(response, "AÇIKLAMA") ?: response.take(200),
            recommendation = extractSection(response, "ÖNERİ") ?: "Manuel kontrol önerilir"
        )
    }
    
    private fun parseUrlAnalysis(response: String): UrlAnalysisResult {
        val isSafe = response.contains("GÜVENLİ", ignoreCase = true) && 
                     !response.contains("TEHLİKELİ", ignoreCase = true)
        
        val threatType = when {
            response.contains("phishing", ignoreCase = true) -> "PHISHING"
            response.contains("malware", ignoreCase = true) -> "MALWARE"
            response.contains("scam", ignoreCase = true) -> "SCAM"
            else -> if (isSafe) "NONE" else "UNKNOWN"
        }
        
        return UrlAnalysisResult(
            isSafe = isSafe,
            threatType = threatType,
            explanation = extractSection(response, "AÇIKLAMA") ?: response.take(200)
        )
    }
    
    private fun extractSection(text: String, section: String): String? {
        val regex = Regex("$section:\\s*(.+?)(?=\\n[A-ZÇĞİÖŞÜ]+:|$)", RegexOption.DOT_MATCHES_ALL)
        return regex.find(text)?.groupValues?.get(1)?.trim()
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // DATA CLASSES
    // ═══════════════════════════════════════════════════════════════════════════
    
    data class SmsAnalysisResult(
        val threatLevel: ThreatLevel,
        val explanation: String,
        val recommendation: String
    )
    
    data class AppAnalysisResult(
        val riskLevel: RiskLevel,
        val suspiciousPermissions: List<String>,
        val explanation: String,
        val recommendation: String
    )
    
    data class UrlAnalysisResult(
        val isSafe: Boolean,
        val threatType: String,
        val explanation: String
    )
    
    data class ThreatInfo(
        val type: String,
        val description: String
    )
    
    enum class ThreatLevel {
        SAFE, SUSPICIOUS, DANGEROUS, UNKNOWN
    }
    
    enum class RiskLevel {
        LOW, MEDIUM, HIGH, UNKNOWN
    }
}
