package com.clara.security.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.clara.security.MainActivity
import com.clara.security.data.ClaraConnection
import kotlinx.coroutines.*

/**
 * CLARA Connection Service
 * Daemon'larla bağlantıyı sürdürür ve bildirimleri yönetir
 */
class ClaraConnectionService : Service() {
    
    companion object {
        private const val CHANNEL_ID = "clara_security_channel"
        private const val NOTIFICATION_ID = 1001
        private const val TAG = "ClaraService"
    }
    
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val connection = ClaraConnection()
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForeground(NOTIFICATION_ID, createNotification())
        
        // Periyodik durum kontrolü başlat
        startStatusCheck()
        
        return START_STICKY
    }
    
    override fun onBind(intent: Intent?): IBinder? = null
    
    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "CLARA Security",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Güvenlik izleme servisi"
                setShowBadge(false)
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("CLARA Security")
            .setContentText("Sistem koruması aktif")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }
    
    private fun startStatusCheck() {
        serviceScope.launch {
            while (isActive) {
                try {
                    connection.checkDaemonStatuses()
                    connection.loadRecentThreats(10)
                    
                    // Yeni tehdit varsa bildirim gönder
                    val threats = connection.recentThreats.value
                    if (threats.isNotEmpty()) {
                        val lastThreat = threats.first()
                        // TODO: Bildirim gönder
                    }
                } catch (e: Exception) {
                    // Hata yoksay, tekrar dene
                }
                
                delay(30_000) // 30 saniyede bir kontrol
            }
        }
    }
    
    /**
     * Tehdit bildirimi gönder
     */
    fun sendThreatNotification(title: String, message: String) {
        val notificationManager = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        
        val notification = NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle(title)
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .build()
        
        notificationManager.notify(System.currentTimeMillis().toInt(), notification)
    }
}
