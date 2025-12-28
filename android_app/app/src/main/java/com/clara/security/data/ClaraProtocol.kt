package com.clara.security.data

import android.util.Log
import com.clara.security.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * CLARA IPC Protokolü
 * 
 * Daemon'larla komut/cevap tabanlı iletişim protokolü.
 * JSON formatında mesajlar kullanır.
 */
object ClaraProtocol {
    private const val TAG = "ClaraProtocol"
    
    // Komut tipleri
    enum class Command {
        // Durum sorguları
        STATUS,              // Daemon durumu
        STATS,               // İstatistikler
        THREATS,             // Son tehditler
        
        // Kontrol komutları
        START_SCAN,          // Tarama başlat
        STOP_SCAN,           // Tarama durdur
        ENABLE_MODULE,       // Modül etkinleştir
        DISABLE_MODULE,      // Modül devre dışı bırak
        
        // App Lock
        GET_LOCKED_APPS,     // Kilitli uygulamalar
        LOCK_APP,            // Uygulama kilitle
        UNLOCK_APP,          // Kilit kaldır
        SET_PIN,             // PIN ayarla
        VERIFY_PIN,          // PIN doğrula
        
        // Tracker
        GET_TRACKERS,        // Tracker listesi
        ADD_TRACKER,         // Tracker ekle
        REMOVE_TRACKER,      // Tracker kaldır
        UPDATE_BLOCKLIST,    // Blocklist güncelle
        
        // Root Hider
        GET_HIDDEN_APPS,     // Gizlenen uygulamalar
        HIDE_FROM_APP,       // Root gizle
        UNHIDE_FROM_APP,     // Gizleme kaldır
        
        // Ayarlar
        GET_CONFIG,          // Ayarları al
        SET_CONFIG,          // Ayarları kaydet
        
        // Sistem
        RESTART_DAEMONS,     // Daemon'ları yeniden başlat
        CLEAR_LOGS,          // Logları temizle
        CLEAR_QUARANTINE     // Karantinayı temizle
    }
    
    // Cevap durumları
    enum class ResponseStatus {
        OK,
        ERROR,
        UNAUTHORIZED,
        NOT_FOUND,
        TIMEOUT
    }
    
    /**
     * Komut mesajı oluştur
     */
    fun createCommand(command: Command, params: Map<String, Any> = emptyMap()): String {
        val json = JSONObject().apply {
            put("cmd", command.name)
            put("ts", System.currentTimeMillis())
            params.forEach { (key, value) ->
                put(key, value)
            }
        }
        return json.toString()
    }
    
    /**
     * Cevabı parse et
     */
    fun parseResponse(response: String): ProtocolResponse {
        return try {
            val json = JSONObject(response)
            ProtocolResponse(
                status = ResponseStatus.valueOf(json.optString("status", "ERROR")),
                message = json.optString("message", ""),
                data = json.optJSONObject("data")?.toString() ?: "{}"
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse response: $response", e)
            ProtocolResponse(
                status = ResponseStatus.ERROR,
                message = e.message ?: "Parse error",
                data = "{}"
            )
        }
    }
    
    /**
     * Root komutu ile daemon'a komut gönder
     */
    suspend fun sendCommand(command: Command, params: Map<String, Any> = emptyMap()): ProtocolResponse {
        return withContext(Dispatchers.IO) {
            try {
                val cmdJson = createCommand(command, params)
                val socketPath = "/data/clara/orchestrator.sock"
                
                // nc (netcat) ile Unix socket'a gönder
                val shellCmd = "echo '$cmdJson' | nc -U $socketPath 2>/dev/null"
                val process = Runtime.getRuntime().exec(arrayOf("su", "-c", shellCmd))
                
                val response = process.inputStream.bufferedReader().readText()
                process.waitFor()
                
                if (response.isNotBlank()) {
                    parseResponse(response)
                } else {
                    // Socket bağlantısı başarısız, dosya tabanlı fallback
                    executeFileFallback(command, params)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Command failed: ${command.name}", e)
                ProtocolResponse(
                    status = ResponseStatus.ERROR,
                    message = e.message ?: "Unknown error",
                    data = "{}"
                )
            }
        }
    }
    
    /**
     * Socket bağlantısı yoksa dosya tabanlı fallback
     */
    private suspend fun executeFileFallback(command: Command, params: Map<String, Any>): ProtocolResponse {
        return withContext(Dispatchers.IO) {
            try {
                when (command) {
                    Command.STATUS -> {
                        // Daemon PID'lerini kontrol et
                        val daemons = listOf("clara_orchestrator", "clara_security_core", "clara_privacy_core", "clara_app_manager")
                        val statuses = daemons.map { daemon ->
                            val pid = executeRoot("pidof $daemon").trim()
                            """{"name":"$daemon","running":${pid.isNotEmpty()},"pid":"$pid"}"""
                        }
                        ProtocolResponse(
                            status = ResponseStatus.OK,
                            message = "Status retrieved",
                            data = """{"daemons":[${statuses.joinToString(",")}]}"""
                        )
                    }
                    
                    Command.STATS -> {
                        val threats = executeRoot("wc -l < /data/clara/database/threats.log 2>/dev/null").trim()
                        val events = executeRoot("wc -l < /data/clara/database/events.log 2>/dev/null").trim()
                        ProtocolResponse(
                            status = ResponseStatus.OK,
                            message = "Stats retrieved",
                            data = """{"threats":${threats.toIntOrNull() ?: 0},"events":${events.toIntOrNull() ?: 0}}"""
                        )
                    }
                    
                    Command.THREATS -> {
                        val count = params["count"] as? Int ?: 50
                        val threats = executeRoot("tail -n $count /data/clara/database/threats.log 2>/dev/null")
                        ProtocolResponse(
                            status = ResponseStatus.OK,
                            message = "Threats retrieved",
                            data = """{"lines":${threats.lines().filter { it.isNotBlank() }.size}}"""
                        )
                    }
                    
                    Command.START_SCAN -> {
                        executeRoot("touch /data/clara/trigger_scan")
                        ProtocolResponse(ResponseStatus.OK, "Scan triggered", "{}")
                    }
                    
                    Command.RESTART_DAEMONS -> {
                        executeRoot("pkill -f clara_ ; sleep 1 ; /system/bin/clara_orchestrator &")
                        ProtocolResponse(ResponseStatus.OK, "Daemons restarting", "{}")
                    }
                    
                    Command.CLEAR_LOGS -> {
                        executeRoot("echo '' > /data/clara/logs/orchestrator.log")
                        executeRoot("echo '' > /data/clara/logs/security_core.log")
                        ProtocolResponse(ResponseStatus.OK, "Logs cleared", "{}")
                    }
                    
                    Command.CLEAR_QUARANTINE -> {
                        executeRoot("rm -rf /data/clara/quarantine/*")
                        ProtocolResponse(ResponseStatus.OK, "Quarantine cleared", "{}")
                    }
                    
                    else -> {
                        ProtocolResponse(
                            status = ResponseStatus.ERROR,
                            message = "Command not implemented: ${command.name}",
                            data = "{}"
                        )
                    }
                }
            } catch (e: Exception) {
                ProtocolResponse(
                    status = ResponseStatus.ERROR,
                    message = e.message ?: "Fallback error",
                    data = "{}"
                )
            }
        }
    }
    
    /**
     * Root komutu çalıştır
     */
    private fun executeRoot(command: String): String {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
            val output = process.inputStream.bufferedReader().readText()
            process.waitFor()
            output
        } catch (e: Exception) {
            Log.e(TAG, "Root command failed: $command", e)
            ""
        }
    }
}

/**
 * Protokol cevabı
 */
data class ProtocolResponse(
    val status: ClaraProtocol.ResponseStatus,
    val message: String,
    val data: String
) {
    val isSuccess: Boolean
        get() = status == ClaraProtocol.ResponseStatus.OK
    
    fun <T> parseData(parser: (String) -> T): T? {
        return try {
            parser(data)
        } catch (e: Exception) {
            null
        }
    }
}
