package com.clara.security.data

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Root komut çalıştırıcı
 * 
 * KernelSU/Magisk ile root komutları çalıştırır.
 * Daemon'ları tetikler ve sonuçları alır.
 */
object RootExecutor {
    private const val TAG = "RootExecutor"
    private const val CLARA_BIN_PATH = "/data/adb/clara/bin"
    private const val TIMEOUT_MS = 30000L
    
    /**
     * Root erişimi var mı kontrol et
     */
    suspend fun hasRootAccess(): Boolean = withContext(Dispatchers.IO) {
        try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = reader.readText()
            process.waitFor()
            output.contains("uid=0")
        } catch (e: Exception) {
            Log.e(TAG, "Root check failed", e)
            false
        }
    }
    
    /**
     * Root komutu çalıştır
     */
    suspend fun execute(command: String): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            Log.d(TAG, "Executing: $command")
            
            val process = ProcessBuilder("su", "-c", command)
                .redirectErrorStream(true)
                .start()
            
            val reader = BufferedReader(InputStreamReader(process.inputStream))
            val output = StringBuilder()
            var line: String?
            
            while (reader.readLine().also { line = it } != null) {
                output.appendLine(line)
            }
            
            val exitCode = process.waitFor()
            val result = output.toString().trim()
            
            Log.d(TAG, "Exit code: $exitCode, Output: ${result.take(100)}...")
            
            if (exitCode != 0 && result.isEmpty()) {
                throw RuntimeException("Command failed with exit code $exitCode")
            }
            
            result
        }
    }
    
    /**
     * CLARA daemon çalıştır
     */
    suspend fun runDaemon(daemon: String, vararg args: String): Result<String> {
        val cmd = "$CLARA_BIN_PATH/$daemon ${args.joinToString(" ")}"
        return execute(cmd)
    }
    
    /**
     * Daemon mevcut mu kontrol et
     */
    suspend fun isDaemonInstalled(daemon: String): Boolean = withContext(Dispatchers.IO) {
        execute("test -x $CLARA_BIN_PATH/$daemon && echo 'exists'")
            .getOrNull()?.contains("exists") == true
    }
    
    /**
     * Process çalışıyor mu kontrol et
     */
    suspend fun isProcessRunning(processName: String): Boolean = withContext(Dispatchers.IO) {
        val result = execute("pidof $processName").getOrNull()
        !result.isNullOrBlank()
    }
    
    /**
     * Process'i öldür
     */
    suspend fun killProcess(processName: String): Boolean = withContext(Dispatchers.IO) {
        execute("pkill -f $processName").isSuccess
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // GÜVENLİK FONKSİYONLARI
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Yüklü paket listesini al
     */
    suspend fun getInstalledPackages(): List<String> = withContext(Dispatchers.IO) {
        execute("pm list packages -3")
            .getOrNull()
            ?.lines()
            ?.filter { it.startsWith("package:") }
            ?.map { it.removePrefix("package:") }
            ?: emptyList()
    }
    
    /**
     * Uygulama izinlerini al
     */
    suspend fun getAppPermissions(packageName: String): List<String> = withContext(Dispatchers.IO) {
        execute("dumpsys package $packageName | grep 'permission'")
            .getOrNull()
            ?.lines()
            ?.filter { it.contains("android.permission.") }
            ?.map { it.trim() }
            ?: emptyList()
    }
    
    /**
     * Tehlikeli izinleri kontrol et
     */
    suspend fun checkDangerousPermissions(packageName: String): List<String> {
        val dangerousPerms = listOf(
            "READ_SMS", "RECEIVE_SMS", "SEND_SMS",
            "READ_CONTACTS", "WRITE_CONTACTS",
            "READ_CALL_LOG", "WRITE_CALL_LOG",
            "CAMERA", "RECORD_AUDIO",
            "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
            "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
            "READ_PHONE_STATE", "CALL_PHONE"
        )
        
        val appPerms = getAppPermissions(packageName)
        return dangerousPerms.filter { perm ->
            appPerms.any { it.contains(perm) }
        }
    }
    
    /**
     * Hosts dosyasına domain ekle (tracker engelleme)
     */
    suspend fun addToHosts(domains: List<String>): Boolean = withContext(Dispatchers.IO) {
        if (domains.isEmpty()) return@withContext true
        
        val entries = domains.joinToString("\n") { "0.0.0.0 $it" }
        execute("echo '$entries' >> /system/etc/hosts").isSuccess
    }
    
    /**
     * Hosts dosyasını oku
     */
    suspend fun getHostsFile(): String = withContext(Dispatchers.IO) {
        execute("cat /system/etc/hosts").getOrNull() ?: ""
    }
    
    /**
     * Uygulama internet erişimini engelle (iptables)
     */
    suspend fun blockAppInternet(uid: Int): Boolean = withContext(Dispatchers.IO) {
        execute("iptables -A OUTPUT -m owner --uid-owner $uid -j DROP").isSuccess
    }
    
    /**
     * Uygulama internet engelini kaldır
     */
    suspend fun unblockAppInternet(uid: Int): Boolean = withContext(Dispatchers.IO) {
        execute("iptables -D OUTPUT -m owner --uid-owner $uid -j DROP").isSuccess
    }
    
    /**
     * Logcat'ten güvenlik loglarını al
     */
    suspend fun getSecurityLogs(count: Int = 100): List<String> = withContext(Dispatchers.IO) {
        execute("logcat -d -t $count | grep -i 'clara\\|security\\|threat'")
            .getOrNull()
            ?.lines()
            ?.filter { it.isNotBlank() }
            ?: emptyList()
    }
    
    /**
     * Cihaz bilgilerini al
     */
    suspend fun getDeviceInfo(): Map<String, String> = withContext(Dispatchers.IO) {
        val info = mutableMapOf<String, String>()
        
        execute("getprop ro.product.model").getOrNull()?.let { info["model"] = it }
        execute("getprop ro.build.version.release").getOrNull()?.let { info["android"] = it }
        execute("getprop ro.build.version.security_patch").getOrNull()?.let { info["security_patch"] = it }
        execute("cat /proc/version").getOrNull()?.let { info["kernel"] = it.take(50) }
        
        info
    }
}
