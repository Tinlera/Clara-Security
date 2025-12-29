package com.clara.security.data

import android.content.Context
import android.util.Log
import com.clara.security.model.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext

/**
 * CLARA Bağlantı Yöneticisi
 * 
 * Root komutları, AI analizi ve yerel veritabanını koordine eder.
 * Daemon yoksa fallback modunda çalışır.
 */
class ClaraConnection(private val context: Context) {
    companion object {
        private const val TAG = "ClaraConnection"
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STATE
    // ═══════════════════════════════════════════════════════════════════════════
    
    enum class ConnectionMode {
        FULL,       // Daemon + Root + AI
        ROOT_ONLY,  // Root + AI (daemon yok)
        NO_ROOT     // Sadece yerel (sınırlı özellikler)
    }
    
    private val _connectionMode = MutableStateFlow(ConnectionMode.NO_ROOT)
    val connectionMode: StateFlow<ConnectionMode> = _connectionMode.asStateFlow()
    
    private val _isConnected = MutableStateFlow(false)
    val isConnected: StateFlow<Boolean> = _isConnected.asStateFlow()
    
    private val _hasRoot = MutableStateFlow(false)
    val hasRoot: StateFlow<Boolean> = _hasRoot.asStateFlow()
    
    private val _daemonStatuses = MutableStateFlow<List<DaemonStatus>>(emptyList())
    val daemonStatuses: StateFlow<List<DaemonStatus>> = _daemonStatuses.asStateFlow()
    
    private val _recentThreats = MutableStateFlow<List<ThreatInfo>>(emptyList())
    val recentThreats: StateFlow<List<ThreatInfo>> = _recentThreats.asStateFlow()
    
    private val _stats = MutableStateFlow(SecurityStats())
    val stats: StateFlow<SecurityStats> = _stats.asStateFlow()
    
    private val _isScanning = MutableStateFlow(false)
    val isScanning: StateFlow<Boolean> = _isScanning.asStateFlow()
    
    // ═══════════════════════════════════════════════════════════════════════════
    // INITIALIZATION
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Bağlantıyı başlat ve durumu kontrol et
     */
    suspend fun initialize() = withContext(Dispatchers.IO) {
        Log.d(TAG, "Initializing ClaraConnection...")
        
        // Root kontrolü
        val hasRootAccess = RootExecutor.hasRootAccess()
        _hasRoot.value = hasRootAccess
        
        if (hasRootAccess) {
            Log.d(TAG, "Root access available")
            
            // Daemon kontrolü
            val daemonRunning = RootExecutor.isProcessRunning("clara_orchestrator")
            
            if (daemonRunning) {
                _connectionMode.value = ConnectionMode.FULL
                _isConnected.value = true
                Log.d(TAG, "Mode: FULL (Daemon + Root)")
            } else {
                _connectionMode.value = ConnectionMode.ROOT_ONLY
                _isConnected.value = true
                Log.d(TAG, "Mode: ROOT_ONLY")
            }
        } else {
            _connectionMode.value = ConnectionMode.NO_ROOT
            _isConnected.value = false
            Log.d(TAG, "Mode: NO_ROOT (limited features)")
        }
        
        // Verileri yükle
        loadAllData()
    }
    
    /**
     * Tüm verileri yükle
     */
    suspend fun loadAllData() {
        checkDaemonStatuses()
        loadRecentThreats()
        loadStats()
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // DAEMON MANAGEMENT
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Daemon durumlarını kontrol et
     */
    suspend fun checkDaemonStatuses() = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) {
            // Root yoksa varsayılan durumları göster
            _daemonStatuses.value = listOf(
                DaemonStatus("SECURITY CORE", false, 0, System.currentTimeMillis()),
                DaemonStatus("PRIVACY CORE", false, 0, System.currentTimeMillis()),
                DaemonStatus("APP MANAGER", false, 0, System.currentTimeMillis())
            )
            return@withContext
        }
        
        val services = listOf(
            "clara_security_core" to "SECURITY CORE",
            "clara_privacy_core" to "PRIVACY CORE",
            "clara_app_manager" to "APP MANAGER"
        )
        
        val statuses = services.map { (processName, displayName) ->
            val result = RootExecutor.execute("pidof $processName").getOrNull()
            val pid = result?.trim()?.toIntOrNull() ?: 0
            val isRunning = pid > 0
            
            DaemonStatus(
                name = displayName,
                isRunning = isRunning,
                pid = pid,
                lastUpdate = System.currentTimeMillis()
            )
        }
        
        _daemonStatuses.value = statuses
        _isConnected.value = statuses.any { it.isRunning } || _hasRoot.value
    }
    
    /**
     * Daemon başlat
     */
    suspend fun startDaemon(name: String): Boolean = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) {
            Log.w(TAG, "Cannot start daemon without root")
            return@withContext false
        }
        
        val daemonName = name.lowercase().replace(" ", "_")
        val fullName = "clara_$daemonName"
        
        Log.d(TAG, "Starting daemon: $fullName")
        
        val result = RootExecutor.execute(
            "nohup /data/adb/clara/bin/$fullName > /dev/null 2>&1 &"
        )
        
        kotlinx.coroutines.delay(1000)
        checkDaemonStatuses()
        
        return@withContext _daemonStatuses.value.find { 
            it.name.lowercase().contains(daemonName) 
        }?.isRunning ?: false
    }
    
    /**
     * Daemon durdur
     */
    suspend fun stopDaemon(name: String): Boolean = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) return@withContext false
        
        val daemonName = name.lowercase().replace(" ", "_")
        val fullName = "clara_$daemonName"
        
        RootExecutor.execute("pkill -f $fullName")
        kotlinx.coroutines.delay(500)
        checkDaemonStatuses()
        
        return@withContext true
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // THREATS
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Son tehditleri yükle
     */
    suspend fun loadRecentThreats(count: Int = 20) = withContext(Dispatchers.IO) {
        val threats = ThreatDatabase.getRecentThreats(context, count)
        
        _recentThreats.value = threats.map { threat ->
            ThreatInfo(
                type = ThreatType.fromString(threat.type),
                level = ThreatLevel.fromSeverity(threat.severity),
                description = threat.description,
                source = threat.source,
                timestamp = threat.timestamp
            )
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // STATS
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * İstatistikleri yükle
     */
    suspend fun loadStats() = withContext(Dispatchers.IO) {
        val threatStats = ThreatDatabase.getStats(context)
        
        // Root varsa ek bilgiler al
        var trackersBlocked = 0
        var appsScanned = 0
        
        if (_hasRoot.value) {
            // Hosts dosyasından engellenen domain sayısı
            val hosts = RootExecutor.getHostsFile()
            trackersBlocked = hosts.lines().count { it.startsWith("0.0.0.0 ") }
            
            // Yüklü uygulama sayısı
            val packages = RootExecutor.getInstalledPackages()
            appsScanned = packages.size
        }
        
        _stats.value = SecurityStats(
            totalThreats = threatStats.total,
            threatsToday = threatStats.today,
            eventsProcessed = threatStats.total + appsScanned,
            trackersBlocked = trackersBlocked,
            smsScanned = threatStats.byType["PHISHING"] ?: 0 + threatStats.byType["SUSPICIOUS"] ?: 0,
            filesScanned = appsScanned,
            lastScanTime = System.currentTimeMillis()
        )
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SCANNING
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Manuel tarama başlat
     */
    suspend fun startScan() = withContext(Dispatchers.IO) {
        if (_isScanning.value) {
            Log.w(TAG, "Scan already in progress")
            return@withContext
        }
        
        _isScanning.value = true
        Log.d(TAG, "Starting manual scan...")
        
        try {
            var threatsFound = 0
            
            if (_hasRoot.value) {
                // Root ile kapsamlı tarama
                
                // 1. Tehlikeli izinlere sahip uygulamaları tara
                val packages = RootExecutor.getInstalledPackages()
                for (pkg in packages.take(50)) { // İlk 50 uygulama
                    val dangerousPerms = RootExecutor.checkDangerousPermissions(pkg)
                    if (dangerousPerms.size >= 5) {
                        // 5+ tehlikeli izin - şüpheli
                        ThreatDatabase.saveThreat(
                            context = context,
                            type = "SUSPICIOUS_APP",
                            source = pkg,
                            description = "${dangerousPerms.size} tehlikeli izin: ${dangerousPerms.take(3).joinToString(", ")}",
                            severity = 4
                        )
                        threatsFound++
                    }
                }
                
                // 2. Sistem bütünlüğü kontrolü
                val suResult = RootExecutor.execute("which su").getOrNull()
                if (!suResult.isNullOrBlank()) {
                    Log.d(TAG, "Root detected (expected with KernelSU)")
                }
            }
            
            // İstatistikleri güncelle
            loadStats()
            loadRecentThreats()
            
            // Bildirim göster
            com.clara.security.service.NotificationService.showScanCompleteNotification(
                context, threatsFound
            )
            
            Log.d(TAG, "Scan complete. Threats found: $threatsFound")
            
        } catch (e: Exception) {
            Log.e(TAG, "Scan failed", e)
        } finally {
            _isScanning.value = false
        }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // TRACKER BLOCKING
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Tracker domain'lerini engelle
     */
    suspend fun blockTrackers(domains: List<String>): Boolean = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) {
            Log.w(TAG, "Cannot block trackers without root")
            return@withContext false
        }
        
        val result = RootExecutor.addToHosts(domains)
        if (result) {
            loadStats() // Güncelle
        }
        return@withContext result
    }
    
    /**
     * Varsayılan tracker listesini engelle
     */
    suspend fun blockDefaultTrackers(): Boolean {
        val defaultTrackers = listOf(
            // Analytics
            "analytics.google.com",
            "www.google-analytics.com",
            "ssl.google-analytics.com",
            
            // Facebook
            "graph.facebook.com",
            "pixel.facebook.com",
            
            // Xiaomi
            "tracking.miui.com",
            "data.mistat.xiaomi.com",
            "api.ad.xiaomi.com",
            
            // Diğer
            "app-measurement.com",
            "crashlytics.com",
            "doubleclick.net",
            "adservice.google.com"
        )
        
        return blockTrackers(defaultTrackers)
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // FIREWALL
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Uygulama internet erişimini engelle
     */
    suspend fun blockAppInternet(uid: Int): Boolean = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) return@withContext false
        RootExecutor.blockAppInternet(uid)
    }
    
    /**
     * Uygulama internet engelini kaldır
     */
    suspend fun unblockAppInternet(uid: Int): Boolean = withContext(Dispatchers.IO) {
        if (!_hasRoot.value) return@withContext false
        RootExecutor.unblockAppInternet(uid)
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // SETTINGS
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Ayarları güncelle
     */
    suspend fun updateSettings(settings: Map<String, Any>) = withContext(Dispatchers.IO) {
        // DataStore veya SharedPreferences ile kaydet
        Log.d(TAG, "Settings updated: $settings")
    }
}
