package com.clara.security

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.core.content.ContextCompat
import com.clara.security.data.ClaraConnection
import com.clara.security.service.NotificationService
import com.clara.security.ui.CLARAApp
import com.clara.security.ui.theme.CLARASecurityTheme
import kotlinx.coroutines.launch

/**
 * CLARA Security - Ana Activity
 * 
 * KernelSU modülü ile çalışan güvenlik kontrol uygulaması.
 */
class MainActivity : ComponentActivity() {
    
    companion object {
        private const val TAG = "MainActivity"
    }
    
    private lateinit var connection: ClaraConnection
    
    // İzin launcher'ı
    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val allGranted = permissions.all { it.value }
        Log.d(TAG, "Permissions result: $allGranted")
    }
    
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        
        Log.d(TAG, "CLARA Security starting...")
        
        // Bildirim kanallarını oluştur
        NotificationService.createChannels(this)
        
        // Bağlantı yöneticisini oluştur
        connection = ClaraConnection(applicationContext)
        
        // İzinleri kontrol et
        checkAndRequestPermissions()
        
        setContent {
            CLARASecurityTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background
                ) {
                    // Başlangıçta bağlantıyı başlat
                    val scope = rememberCoroutineScope()
                    
                    LaunchedEffect(Unit) {
                        scope.launch {
                            try {
                                connection.initialize()
                                Log.d(TAG, "Connection initialized: ${connection.connectionMode.value}")
                            } catch (e: Exception) {
                                Log.e(TAG, "Failed to initialize connection", e)
                            }
                        }
                    }
                    
                    CLARAApp(connection = connection)
                }
            }
        }
    }
    
    private fun checkAndRequestPermissions() {
        val requiredPermissions = mutableListOf<String>()
        
        // SMS izni
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECEIVE_SMS) 
            != PackageManager.PERMISSION_GRANTED) {
            requiredPermissions.add(Manifest.permission.RECEIVE_SMS)
        }
        
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_SMS) 
            != PackageManager.PERMISSION_GRANTED) {
            requiredPermissions.add(Manifest.permission.READ_SMS)
        }
        
        // Bildirim izni (Android 13+)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) 
                != PackageManager.PERMISSION_GRANTED) {
                requiredPermissions.add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        
        // Telefon durumu (bazı özellikler için)
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.READ_PHONE_STATE) 
            != PackageManager.PERMISSION_GRANTED) {
            requiredPermissions.add(Manifest.permission.READ_PHONE_STATE)
        }
        
        if (requiredPermissions.isNotEmpty()) {
            Log.d(TAG, "Requesting permissions: $requiredPermissions")
            permissionLauncher.launch(requiredPermissions.toTypedArray())
        } else {
            Log.d(TAG, "All permissions already granted")
        }
    }
    
    override fun onResume() {
        super.onResume()
        // Uygulama ön plana geldiğinde verileri yenile
        kotlinx.coroutines.GlobalScope.launch {
            try {
                connection.loadAllData()
            } catch (e: Exception) {
                Log.e(TAG, "Failed to refresh data", e)
            }
        }
    }
}
