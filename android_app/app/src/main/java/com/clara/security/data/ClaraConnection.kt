package com.clara.security.data

import android.util.Log
import com.clara.security.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader
import java.io.OutputStreamWriter
import java.net.Socket

/**
 * CLARA Daemon bağlantı yöneticisi
 * 
 * Unix Domain Socket üzerinden daemon'larla iletişim kurar.
 * Root yetkileri gerektirir.
 */
class ClaraConnection {
    companion object {
        private const val TAG = "ClaraConnection"
        private const val SOCKET_PATH = "/data/clara/orchestrator.sock"
        private const val LOGS_DIR = "/data/clara/logs"
        private const val THREATS_FILE = "/data/clara/database/threats.log"
        private const val EVENTS_FILE = "/data/clara/database/events.log"
    }
    
    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()
    
    private val _daemonStatuses = MutableStateFlow<List<DaemonStatus>>(emptyList())
    val daemonStatuses: StateFlow<List<DaemonStatus>> = _daemonStatuses.asStateFlow()
    
    private val _recentThreats = MutableStateFlow<List<ThreatInfo>>(emptyList())
    val recentThreats: StateFlow<List<ThreatInfo>> = _recentThreats.asStateFlow()
    
    private val _stats = MutableStateFlow(SecurityStats())
    val stats: StateFlow<SecurityStats> = _stats.asStateFlow()
    
    /**
     * Root komutu çalıştır
     */
    private suspend fun executeRootCommand(command: String): String = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = StringBuilder()
            var line: String?
            while (reader.readLine().also { line = it } != null) {
                output.appendLine(line)
            }
            process.waitFor()
            output.toString().trim()
        } catch (e: Exception) {
            Log.e(TAG, "Root command failed: $command", e)
            ""
        }
    }
    
    /**
     * Daemon durumlarını kontrol et
     */
    suspend fun checkDaemonStatuses() = withContext(Dispatchers.IO) {
        val daemons = listOf(
            "clara_orchestrator",
            "clara_security_core",
            "clara_privacy_core",
            "clara_app_manager"
        )
        
        val statuses = daemons.map { daemon ->
            val pidResult = executeRootCommand("pidof $daemon")
            val pid = pidResult.trim().toIntOrNull() ?: 0
            val isRunning = pid > 0
            
            DaemonStatus(
                name = daemon.replace("clara_", "").replace("_", " ").uppercase(),
                isRunning = isRunning,
                pid = pid,
                lastUpdate = System.currentTimeMillis()
            )
        }
        
        _daemonStatuses.value = statuses
        _isConnected.value = statuses.any { it.isRunning }
    }
    
    /**
     * Son tehditleri oku
     */
    suspend fun loadRecentThreats(count: Int = 50) = withContext(Dispatchers.IO) {
        try {
            val result = executeRootCommand("tail -n $count $THREATS_FILE 2>/dev/null")
            val threats = result.lines()
                .filter { it.isNotBlank() && it.startsWith("{") }
                .mapNotNull { line -> parseThreatLine(line) }
                .reversed()
            
            _recentThreats.value = threats
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load threats", e)
        }
    }
    
    /**
     * İstatistikleri yükle
     */
    suspend fun loadStats() = withContext(Dispatchers.IO) {
        try {
            val threatCount = executeRootCommand("wc -l < $THREATS_FILE 2>/dev/null").trim().toIntOrNull() ?: 0
            val eventCount = executeRootCommand("wc -l < $EVENTS_FILE 2>/dev/null").trim().toIntOrNull() ?: 0
            
            // Bugünkü tehditler
            val today = java.text.SimpleDateFormat("yyyy-MM-dd", java.util.Locale.getDefault())
                .format(java.util.Date())
            val todayThreats = executeRootCommand("grep -c '$today' $THREATS_FILE 2>/dev/null").trim().toIntOrNull() ?: 0
            
            // Tracker sayısı
            val trackerCount = executeRootCommand("wc -l < /system/etc/hosts 2>/dev/null").trim().toIntOrNull() ?: 0
            
            _stats.value = SecurityStats(
                totalThreats = threatCount,
                threatsToday = todayThreats,
                eventsProcessed = eventCount,
                trackersBlocked = trackerCount,
                lastScanTime = System.currentTimeMillis()
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load stats", e)
        }
    }
    
    /**
     * Daemon'ı başlat
     */
    suspend fun startDaemon(name: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val daemonName = name.lowercase().replace(" ", "_")
            val fullName = if (daemonName.startsWith("clara_")) daemonName else "clara_$daemonName"
            Log.d(TAG, "Starting daemon: $fullName")
            executeRootCommand("setsid /data/adb/modules/clara_security/system/bin/$fullName > /dev/null 2>&1 &")
            kotlinx.coroutines.delay(1000)
            checkDaemonStatuses()
            _daemonStatuses.value.find { it.name.lowercase().contains(daemonName) }?.isRunning ?: false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to start daemon: $name", e)
            false
        }
    }
    
    /**
     * Daemon'ı durdur
     */
    suspend fun stopDaemon(name: String): Boolean = withContext(Dispatchers.IO) {
        try {
            val fullName = if (name.startsWith("clara_")) name else "clara_$name"
            executeRootCommand("pkill -f $fullName")
            kotlinx.coroutines.delay(500)
            checkDaemonStatuses()
            _daemonStatuses.value.find { it.name.lowercase().contains(name.lowercase()) }?.isRunning == false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to stop daemon: $name", e)
            false
        }
    }
    
    /**
     * Threat log satırını parse et
     */
    private fun parseThreatLine(line: String): ThreatInfo? {
        return try {
            // Basit JSON parse (Gson olmadan)
            val type = Regex("\"type\":\"([^\"]+)\"").find(line)?.groupValues?.get(1) ?: "unknown"
            val level = Regex("\"level\":(\\d+)").find(line)?.groupValues?.get(1)?.toIntOrNull() ?: 0
            val desc = Regex("\"desc\":\"([^\"]+)\"").find(line)?.groupValues?.get(1) ?: ""
            val src = Regex("\"src\":\"([^\"]+)\"").find(line)?.groupValues?.get(1) ?: ""
            
            ThreatInfo(
                type = ThreatType.values().find { it.name.equals(type, ignoreCase = true) } ?: ThreatType.UNKNOWN,
                level = ThreatLevel.values().getOrElse(level) { ThreatLevel.LOW },
                description = desc,
                source = src
            )
        } catch (e: Exception) {
            null
        }
    }
    
    /**
     * Manuel tarama başlat
     */
    suspend fun startScan() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Starting scan...")
        // CLI üzerinden tarama başlat
        val result = executeRootCommand("/data/adb/modules/clara_security/system/bin/clara_cli scan 2>&1")
        Log.d(TAG, "Scan result: $result")
        // İstatistikleri güncelle
        loadStats()
    }
    
    /**
     * Ayarları güncelle
     */
    suspend fun updateSettings(settings: Map<String, Any>) = withContext(Dispatchers.IO) {
        // TODO: Ayarları config.json'a yaz
        val configPath = "/data/clara/config.json"
        val json = settings.entries.joinToString(",", "{", "}") { "\"${it.key}\":\"${it.value}\"" }
        executeRootCommand("echo '$json' > $configPath")
    }
}
