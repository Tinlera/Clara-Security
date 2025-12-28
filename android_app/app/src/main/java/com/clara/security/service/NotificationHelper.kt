package com.clara.security.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Build
import androidx.core.app.NotificationCompat
import com.clara.security.MainActivity
import com.clara.security.model.ThreatInfo
import com.clara.security.model.ThreatLevel
import com.clara.security.model.ThreatType
import com.clara.security.ui.theme.*

/**
 * CLARA Bildirim Yöneticisi
 * 
 * Tehdit bildirimleri ve durum güncellemeleri için.
 */
class NotificationHelper(private val context: Context) {
    
    companion object {
        // Kanal ID'leri
        const val CHANNEL_THREATS = "clara_threats"
        const val CHANNEL_STATUS = "clara_status"
        const val CHANNEL_SCAN = "clara_scan"
        
        // Bildirim ID'leri
        const val NOTIFICATION_THREAT_BASE = 2000
        const val NOTIFICATION_STATUS = 1001
        const val NOTIFICATION_SCAN = 1002
    }
    
    private val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
    private var threatNotificationId = NOTIFICATION_THREAT_BASE
    
    init {
        createNotificationChannels()
    }
    
    /**
     * Bildirim kanallarını oluştur
     */
    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // Tehdit kanalı (yüksek öncelik)
            val threatChannel = NotificationChannel(
                CHANNEL_THREATS,
                "Güvenlik Tehditleri",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Tespit edilen güvenlik tehditleri için bildirimler"
                enableLights(true)
                lightColor = Color.RED
                enableVibration(true)
                vibrationPattern = longArrayOf(0, 300, 200, 300)
            }
            
            // Durum kanalı (düşük öncelik)
            val statusChannel = NotificationChannel(
                CHANNEL_STATUS,
                "Koruma Durumu",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Sistem koruma durumu bildirimleri"
                setShowBadge(false)
            }
            
            // Tarama kanalı (normal öncelik)
            val scanChannel = NotificationChannel(
                CHANNEL_SCAN,
                "Tarama Bildirimleri",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Güvenlik taraması ilerleme bildirimleri"
            }
            
            notificationManager.createNotificationChannels(
                listOf(threatChannel, statusChannel, scanChannel)
            )
        }
    }
    
    /**
     * Tehdit bildirimi gönder
     */
    fun showThreatNotification(threat: ThreatInfo) {
        val (title, icon, color) = when (threat.level) {
            ThreatLevel.CRITICAL -> Triple(
                "⚠️ KRİTİK TEHDİT!",
                android.R.drawable.ic_dialog_alert,
                Color.RED
            )
            ThreatLevel.HIGH -> Triple(
                "🔴 Yüksek Risk Tehdidi",
                android.R.drawable.ic_dialog_alert,
                Color.rgb(255, 87, 34)
            )
            ThreatLevel.MEDIUM -> Triple(
                "🟠 Orta Seviye Tehdit",
                android.R.drawable.stat_notify_error,
                Color.rgb(255, 152, 0)
            )
            ThreatLevel.LOW -> Triple(
                "🟡 Düşük Seviye Uyarı",
                android.R.drawable.stat_sys_warning,
                Color.rgb(255, 193, 7)
            )
            else -> Triple(
                "Güvenlik Bildirimi",
                android.R.drawable.ic_dialog_info,
                Color.BLUE
            )
        }
        
        val typeDescription = when (threat.type) {
            ThreatType.PHISHING_SMS -> "SMS Phishing tespit edildi"
            ThreatType.PHISHING_URL -> "Zararlı URL tespit edildi"
            ThreatType.MALWARE_FILE -> "Zararlı dosya tespit edildi"
            ThreatType.SUSPICIOUS_APP -> "Şüpheli uygulama tespit edildi"
            ThreatType.NETWORK_ATTACK -> "Ağ saldırısı tespit edildi"
            ThreatType.KEYLOGGER -> "Keylogger tespit edildi"
            ThreatType.ROOT_DETECTION -> "Root algılama girişimi"
            ThreatType.PERMISSION_ABUSE -> "İzin istismarı tespit edildi"
            else -> "Bilinmeyen tehdit"
        }
        
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            putExtra("navigate_to", "threats")
        }
        
        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val notification = NotificationCompat.Builder(context, CHANNEL_THREATS)
            .setSmallIcon(icon)
            .setContentTitle(title)
            .setContentText(typeDescription)
            .setStyle(
                NotificationCompat.BigTextStyle()
                    .bigText("$typeDescription\n\n${threat.description}")
                    .setBigContentTitle(title)
            )
            .setColor(color)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .addAction(
                android.R.drawable.ic_menu_view,
                "Detaylar",
                pendingIntent
            )
            .addAction(
                android.R.drawable.ic_menu_close_clear_cancel,
                "Yoksay",
                null
            )
            .build()
        
        notificationManager.notify(threatNotificationId++, notification)
    }
    
    /**
     * Durum bildirimi göster (kalıcı)
     */
    fun showStatusNotification(isProtected: Boolean, daemonCount: Int) {
        val (title, text, icon) = if (isProtected) {
            Triple(
                "CLARA Security Aktif",
                "$daemonCount servis çalışıyor • Koruma aktif",
                android.R.drawable.ic_lock_lock
            )
        } else {
            Triple(
                "CLARA Security Uyarı",
                "Bazı servisler çalışmıyor",
                android.R.drawable.ic_lock_idle_lock
            )
        }
        
        val intent = Intent(context, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val notification = NotificationCompat.Builder(context, CHANNEL_STATUS)
            .setSmallIcon(icon)
            .setContentTitle(title)
            .setContentText(text)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(pendingIntent)
            .build()
        
        notificationManager.notify(NOTIFICATION_STATUS, notification)
    }
    
    /**
     * Tarama ilerleme bildirimi
     */
    fun showScanProgress(progress: Int, total: Int, currentItem: String) {
        val notification = NotificationCompat.Builder(context, CHANNEL_SCAN)
            .setSmallIcon(android.R.drawable.ic_menu_search)
            .setContentTitle("Güvenlik Taraması")
            .setContentText("Taranan: $currentItem")
            .setProgress(total, progress, false)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
        
        notificationManager.notify(NOTIFICATION_SCAN, notification)
    }
    
    /**
     * Tarama tamamlandı bildirimi
     */
    fun showScanComplete(threatsFound: Int, itemsScanned: Int) {
        val (title, text) = if (threatsFound > 0) {
            Pair(
                "⚠️ Tarama Tamamlandı",
                "$itemsScanned öğe tarandı, $threatsFound tehdit bulundu!"
            )
        } else {
            Pair(
                "✅ Tarama Tamamlandı",
                "$itemsScanned öğe tarandı, tehdit bulunamadı"
            )
        }
        
        val notification = NotificationCompat.Builder(context, CHANNEL_SCAN)
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentTitle(title)
            .setContentText(text)
            .setAutoCancel(true)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .build()
        
        notificationManager.notify(NOTIFICATION_SCAN, notification)
    }
    
    /**
     * Bildirimi iptal et
     */
    fun cancelNotification(id: Int) {
        notificationManager.cancel(id)
    }
    
    /**
     * Tüm tehdit bildirimlerini iptal et
     */
    fun cancelAllThreatNotifications() {
        for (id in NOTIFICATION_THREAT_BASE until threatNotificationId) {
            notificationManager.cancel(id)
        }
        threatNotificationId = NOTIFICATION_THREAT_BASE
    }
}
