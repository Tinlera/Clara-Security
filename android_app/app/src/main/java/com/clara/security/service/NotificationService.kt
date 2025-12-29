package com.clara.security.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import com.clara.security.MainActivity
import com.clara.security.R

/**
 * Bildirim Servisi
 * 
 * Güvenlik tehditleri için bildirim yönetimi.
 */
object NotificationService {
    
    private const val CHANNEL_THREATS = "clara_threats"
    private const val CHANNEL_SECURITY = "clara_security"
    private const val CHANNEL_INFO = "clara_info"
    
    /**
     * Bildirim kanallarını oluştur
     */
    fun createChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            
            // Tehdit kanalı (yüksek öncelik)
            val threatChannel = NotificationChannel(
                CHANNEL_THREATS,
                "Güvenlik Tehditleri",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Phishing, malware ve diğer güvenlik tehditleri"
                enableVibration(true)
                enableLights(true)
            }
            
            // Güvenlik kanalı (orta öncelik)
            val securityChannel = NotificationChannel(
                CHANNEL_SECURITY,
                "Güvenlik Bildirimleri",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "Genel güvenlik bildirimleri"
            }
            
            // Bilgi kanalı (düşük öncelik)
            val infoChannel = NotificationChannel(
                CHANNEL_INFO,
                "Bilgilendirmeler",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Durum güncellemeleri ve bilgilendirmeler"
            }
            
            manager.createNotificationChannels(listOf(threatChannel, securityChannel, infoChannel))
        }
    }
    
    /**
     * Tehdit bildirimi göster
     */
    fun showThreatNotification(
        context: Context,
        title: String,
        body: String,
        threatId: String
    ) {
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            putExtra("threat_id", threatId)
        }
        
        val pendingIntent = PendingIntent.getActivity(
            context, 
            threatId.hashCode(),
            intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val notification = NotificationCompat.Builder(context, CHANNEL_THREATS)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .setColor(0xFFFF0040.toInt()) // Kırmızı
            .build()
        
        try {
            NotificationManagerCompat.from(context).notify(threatId.hashCode(), notification)
        } catch (e: SecurityException) {
            // Bildirim izni yoksa sessizce devam et
        }
    }
    
    /**
     * Güvenlik bildirimi göster
     */
    fun showSecurityNotification(
        context: Context,
        title: String,
        body: String,
        notificationId: Int = System.currentTimeMillis().toInt()
    ) {
        val notification = NotificationCompat.Builder(context, CHANNEL_SECURITY)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(body)
            .setPriority(NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setColor(0xFF00FF41.toInt()) // Yeşil
            .build()
        
        try {
            NotificationManagerCompat.from(context).notify(notificationId, notification)
        } catch (e: SecurityException) {
            // Bildirim izni yoksa sessizce devam et
        }
    }
    
    /**
     * Bilgi bildirimi göster
     */
    fun showInfoNotification(
        context: Context,
        title: String,
        body: String,
        notificationId: Int = System.currentTimeMillis().toInt()
    ) {
        val notification = NotificationCompat.Builder(context, CHANNEL_INFO)
            .setSmallIcon(android.R.drawable.ic_dialog_info)
            .setContentTitle(title)
            .setContentText(body)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setAutoCancel(true)
            .build()
        
        try {
            NotificationManagerCompat.from(context).notify(notificationId, notification)
        } catch (e: SecurityException) {
            // İzin yoksa sessizce devam et
        }
    }
    
    /**
     * Tarama tamamlandı bildirimi
     */
    fun showScanCompleteNotification(
        context: Context,
        threatsFound: Int
    ) {
        val title = if (threatsFound > 0) {
            "⚠️ Tarama Tamamlandı - $threatsFound Tehdit!"
        } else {
            "✅ Tarama Tamamlandı - Güvende!"
        }
        
        val body = if (threatsFound > 0) {
            "$threatsFound adet güvenlik tehdidi tespit edildi. Detaylar için tıklayın."
        } else {
            "Hiçbir tehdit tespit edilmedi. Cihazınız güvende."
        }
        
        val channel = if (threatsFound > 0) CHANNEL_THREATS else CHANNEL_SECURITY
        
        val intent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
            putExtra("screen", "threats")
        }
        
        val pendingIntent = PendingIntent.getActivity(
            context, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        val notification = NotificationCompat.Builder(context, channel)
            .setSmallIcon(if (threatsFound > 0) android.R.drawable.ic_dialog_alert else android.R.drawable.ic_lock_lock)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText(body))
            .setPriority(if (threatsFound > 0) NotificationCompat.PRIORITY_HIGH else NotificationCompat.PRIORITY_DEFAULT)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)
            .build()
        
        try {
            NotificationManagerCompat.from(context).notify(1001, notification)
        } catch (e: SecurityException) {
            // İzin yoksa
        }
    }
    
    /**
     * Bildirimi iptal et
     */
    fun cancelNotification(context: Context, notificationId: Int) {
        NotificationManagerCompat.from(context).cancel(notificationId)
    }
    
    /**
     * Tüm bildirimleri temizle
     */
    fun cancelAllNotifications(context: Context) {
        NotificationManagerCompat.from(context).cancelAll()
    }
}
