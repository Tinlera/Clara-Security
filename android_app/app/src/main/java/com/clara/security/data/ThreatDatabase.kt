package com.clara.security.data

import android.content.Context
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.io.File

/**
 * Tehdit Veritabanı
 * 
 * Tespit edilen tehditleri yerel olarak saklar.
 * JSON dosyası formatında.
 */
object ThreatDatabase {
    private const val TAG = "ThreatDatabase"
    private const val THREATS_FILE = "threats.json"
    private const val MAX_THREATS = 500
    
    /**
     * Tehdit kaydet
     */
    suspend fun saveThreat(
        context: Context,
        type: String,
        source: String,
        description: String,
        data: String = "",
        severity: Int = 5
    ) = withContext(Dispatchers.IO) {
        try {
            val threats = loadThreatsInternal(context).toMutableList()
            
            val threat = JSONObject().apply {
                put("id", System.currentTimeMillis())
                put("timestamp", System.currentTimeMillis())
                put("type", type)
                put("source", source)
                put("description", description)
                put("data", data.take(500)) // Veriyi sınırla
                put("severity", severity)
                put("resolved", false)
            }
            
            threats.add(0, threat)
            
            // Limit aşıldıysa eski tehditleri sil
            val trimmedThreats = threats.take(MAX_THREATS)
            
            saveThreatsInternal(context, trimmedThreats)
            
            Log.d(TAG, "Threat saved: $type from $source")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save threat", e)
        }
    }
    
    /**
     * Tüm tehditleri yükle
     */
    suspend fun loadThreats(context: Context): List<Threat> = withContext(Dispatchers.IO) {
        loadThreatsInternal(context).map { json ->
            Threat(
                id = json.optLong("id"),
                timestamp = json.optLong("timestamp"),
                type = json.optString("type", "UNKNOWN"),
                source = json.optString("source", ""),
                description = json.optString("description", ""),
                data = json.optString("data", ""),
                severity = json.optInt("severity", 5),
                resolved = json.optBoolean("resolved", false)
            )
        }
    }
    
    /**
     * Son X tehdidi al
     */
    suspend fun getRecentThreats(context: Context, count: Int = 20): List<Threat> {
        return loadThreats(context).take(count)
    }
    
    /**
     * Bugünkü tehdit sayısı
     */
    suspend fun getTodayThreatCount(context: Context): Int {
        val today = System.currentTimeMillis() - (24 * 60 * 60 * 1000)
        return loadThreats(context).count { it.timestamp > today }
    }
    
    /**
     * Toplam tehdit sayısı
     */
    suspend fun getTotalThreatCount(context: Context): Int {
        return loadThreats(context).size
    }
    
    /**
     * Tehdidi çözümlendi olarak işaretle
     */
    suspend fun resolveThreat(context: Context, threatId: Long) = withContext(Dispatchers.IO) {
        val threats = loadThreatsInternal(context).toMutableList()
        val index = threats.indexOfFirst { it.optLong("id") == threatId }
        
        if (index >= 0) {
            threats[index].put("resolved", true)
            saveThreatsInternal(context, threats)
        }
    }
    
    /**
     * Tehdidi sil
     */
    suspend fun deleteThreat(context: Context, threatId: Long) = withContext(Dispatchers.IO) {
        val threats = loadThreatsInternal(context).toMutableList()
        threats.removeAll { it.optLong("id") == threatId }
        saveThreatsInternal(context, threats)
    }
    
    /**
     * Tüm tehditleri temizle
     */
    suspend fun clearAllThreats(context: Context) = withContext(Dispatchers.IO) {
        val file = File(context.filesDir, THREATS_FILE)
        if (file.exists()) {
            file.delete()
        }
    }
    
    /**
     * İstatistikleri al
     */
    suspend fun getStats(context: Context): ThreatStats {
        val threats = loadThreats(context)
        val today = System.currentTimeMillis() - (24 * 60 * 60 * 1000)
        val week = System.currentTimeMillis() - (7 * 24 * 60 * 60 * 1000)
        
        return ThreatStats(
            total = threats.size,
            today = threats.count { it.timestamp > today },
            thisWeek = threats.count { it.timestamp > week },
            unresolved = threats.count { !it.resolved },
            byType = threats.groupBy { it.type }.mapValues { it.value.size }
        )
    }
    
    // Internal functions
    
    private fun loadThreatsInternal(context: Context): List<JSONObject> {
        return try {
            val file = File(context.filesDir, THREATS_FILE)
            if (!file.exists()) return emptyList()
            
            val content = file.readText()
            val jsonArray = JSONArray(content)
            
            (0 until jsonArray.length()).map { jsonArray.getJSONObject(it) }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load threats", e)
            emptyList()
        }
    }
    
    private fun saveThreatsInternal(context: Context, threats: List<JSONObject>) {
        try {
            val jsonArray = JSONArray()
            threats.forEach { jsonArray.put(it) }
            
            val file = File(context.filesDir, THREATS_FILE)
            file.writeText(jsonArray.toString())
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save threats", e)
        }
    }
    
    // Data classes
    
    data class Threat(
        val id: Long,
        val timestamp: Long,
        val type: String,
        val source: String,
        val description: String,
        val data: String,
        val severity: Int,
        val resolved: Boolean
    )
    
    data class ThreatStats(
        val total: Int,
        val today: Int,
        val thisWeek: Int,
        val unresolved: Int,
        val byType: Map<String, Int>
    )
}
