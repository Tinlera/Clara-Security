package com.clara.security.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.util.Log

/**
 * Boot Receiver
 * Cihaz açıldığında CLARA servislerinin çalıştığından emin olur
 */
class BootReceiver : BroadcastReceiver() {
    
    companion object {
        private const val TAG = "ClaraBootReceiver"
    }
    
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == Intent.ACTION_BOOT_COMPLETED) {
            Log.i(TAG, "Boot completed, checking CLARA services...")
            
            // KernelSU modülü zaten servisleri başlatıyor
            // Burada sadece bağlantıyı kontrol edebiliriz
            
            // TODO: Foreground service başlat (opsiyonel)
        }
    }
}
