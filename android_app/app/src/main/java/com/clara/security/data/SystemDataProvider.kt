package com.clara.security.data

import android.content.Context
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.TrafficStats
import android.net.wifi.WifiManager
import android.os.Build
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Gerçek Sistem Veri Sağlayıcı
 * 
 * Demo veri yerine gerçek Android API'lerinden veri çeker.
 */
object SystemDataProvider {
    private const val TAG = "SystemDataProvider"
    
    // ═══════════════════════════════════════════════════════════════════════════
    // UYGULAMA BİLGİLERİ
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Yüklü 3. parti uygulamaları al
     */
    suspend fun getInstalledApps(context: Context): List<AppInfo> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }
        
        packages.mapNotNull { pkg ->
            try {
                val appInfo = pkg.applicationInfo ?: return@mapNotNull null
                val isSystemApp = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                
                // 3. parti uygulamaları filtrele (istenirse sistem uygulamaları da dahil edilebilir)
                if (isSystemApp) return@mapNotNull null
                
                val appName = pm.getApplicationLabel(appInfo).toString()
                val uid = appInfo.uid
                
                // Trafik istatistikleri
                val txBytes = TrafficStats.getUidTxBytes(uid)
                val rxBytes = TrafficStats.getUidRxBytes(uid)
                
                AppInfo(
                    packageName = pkg.packageName,
                    appName = appName,
                    uid = uid,
                    versionName = pkg.versionName ?: "?",
                    isSystemApp = isSystemApp,
                    bytesSent = if (txBytes != TrafficStats.UNSUPPORTED.toLong()) txBytes else 0,
                    bytesReceived = if (rxBytes != TrafficStats.UNSUPPORTED.toLong()) rxBytes else 0
                )
            } catch (e: Exception) {
                Log.e(TAG, "Error getting app info: ${pkg.packageName}", e)
                null
            }
        }.sortedBy { it.appName }
    }
    
    /**
     * Sistem uygulamalarını al
     */
    suspend fun getSystemApps(context: Context): List<AppInfo> = withContext(Dispatchers.IO) {
        val pm = context.packageManager
        val packages = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            pm.getInstalledPackages(0)
        }
        
        packages.mapNotNull { pkg ->
            try {
                val appInfo = pkg.applicationInfo ?: return@mapNotNull null
                val isSystemApp = (appInfo.flags and android.content.pm.ApplicationInfo.FLAG_SYSTEM) != 0
                
                if (!isSystemApp) return@mapNotNull null
                
                val appName = pm.getApplicationLabel(appInfo).toString()
                val uid = appInfo.uid
                val txBytes = TrafficStats.getUidTxBytes(uid)
                val rxBytes = TrafficStats.getUidRxBytes(uid)
                
                AppInfo(
                    packageName = pkg.packageName,
                    appName = appName,
                    uid = uid,
                    versionName = pkg.versionName ?: "?",
                    isSystemApp = true,
                    bytesSent = if (txBytes != TrafficStats.UNSUPPORTED.toLong()) txBytes else 0,
                    bytesReceived = if (rxBytes != TrafficStats.UNSUPPORTED.toLong()) rxBytes else 0
                )
            } catch (e: Exception) {
                null
            }
        }.sortedBy { it.appName }
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // WIFI BİLGİLERİ
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Bağlı WiFi bilgilerini al
     */
    @Suppress("DEPRECATION")
    suspend fun getConnectedWifiInfo(context: Context): WifiInfo? = withContext(Dispatchers.IO) {
        try {
            val wifiManager = context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager
            val connectionInfo = wifiManager.connectionInfo
            
            if (connectionInfo.networkId == -1) return@withContext null
            
            val ssid = connectionInfo.ssid?.removeSurrounding("\"") ?: "Unknown"
            val bssid = connectionInfo.bssid ?: "00:00:00:00:00:00"
            val rssi = connectionInfo.rssi
            val signalLevel = WifiManager.calculateSignalLevel(rssi, 100)
            val linkSpeed = connectionInfo.linkSpeed
            
            // Güvenlik seviyesi için scan sonuçlarına bakılmalı
            // Basitleştirilmiş versiyon
            WifiInfo(
                ssid = ssid,
                bssid = bssid,
                signalStrength = signalLevel,
                linkSpeed = linkSpeed,
                rssi = rssi,
                frequency = connectionInfo.frequency,
                isConnected = true
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error getting WiFi info", e)
            null
        }
    }
    
    /**
     * Ağ bağlantı durumunu kontrol et
     */
    fun isNetworkConnected(context: Context): NetworkStatus {
        val connectivityManager = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        
        val network = connectivityManager.activeNetwork ?: return NetworkStatus(false, NetworkType.NONE)
        val capabilities = connectivityManager.getNetworkCapabilities(network) ?: return NetworkStatus(false, NetworkType.NONE)
        
        val type = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.CELLULAR
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkType.ETHERNET
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> NetworkType.VPN
            else -> NetworkType.OTHER
        }
        
        return NetworkStatus(true, type)
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // CİHAZ BİLGİLERİ
    // ═══════════════════════════════════════════════════════════════════════════
    
    /**
     * Cihaz bilgilerini al
     */
    fun getDeviceInfo(): DeviceInfo {
        return DeviceInfo(
            model = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            androidVersion = Build.VERSION.RELEASE,
            sdkLevel = Build.VERSION.SDK_INT,
            securityPatch = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) Build.VERSION.SECURITY_PATCH else "N/A",
            brand = Build.BRAND,
            device = Build.DEVICE,
            hardware = Build.HARDWARE
        )
    }
    
    /**
     * Toplam trafik istatistikleri
     */
    fun getTotalTrafficStats(): TrafficInfo {
        val txBytes = TrafficStats.getTotalTxBytes()
        val rxBytes = TrafficStats.getTotalRxBytes()
        val mobileTxBytes = TrafficStats.getMobileTxBytes()
        val mobileRxBytes = TrafficStats.getMobileRxBytes()
        
        return TrafficInfo(
            totalSent = if (txBytes != TrafficStats.UNSUPPORTED.toLong()) txBytes else 0,
            totalReceived = if (rxBytes != TrafficStats.UNSUPPORTED.toLong()) rxBytes else 0,
            mobileSent = if (mobileTxBytes != TrafficStats.UNSUPPORTED.toLong()) mobileTxBytes else 0,
            mobileReceived = if (mobileRxBytes != TrafficStats.UNSUPPORTED.toLong()) mobileRxBytes else 0
        )
    }
    
    // ═══════════════════════════════════════════════════════════════════════════
    // DATA CLASSES
    // ═══════════════════════════════════════════════════════════════════════════
    
    data class AppInfo(
        val packageName: String,
        val appName: String,
        val uid: Int,
        val versionName: String,
        val isSystemApp: Boolean,
        val bytesSent: Long,
        val bytesReceived: Long
    )
    
    data class WifiInfo(
        val ssid: String,
        val bssid: String,
        val signalStrength: Int,
        val linkSpeed: Int,
        val rssi: Int,
        val frequency: Int,
        val isConnected: Boolean
    )
    
    data class NetworkStatus(
        val isConnected: Boolean,
        val type: NetworkType
    )
    
    enum class NetworkType {
        NONE, WIFI, CELLULAR, ETHERNET, VPN, OTHER
    }
    
    data class DeviceInfo(
        val model: String,
        val manufacturer: String,
        val androidVersion: String,
        val sdkLevel: Int,
        val securityPatch: String,
        val brand: String,
        val device: String,
        val hardware: String
    )
    
    data class TrafficInfo(
        val totalSent: Long,
        val totalReceived: Long,
        val mobileSent: Long,
        val mobileReceived: Long
    )
}
