package com.clara.security.ui.screens

import android.widget.Toast
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clara.security.data.ClaraConnection
import com.clara.security.security.AntiTheftManager
import com.clara.security.security.SecurityPreferences
import com.clara.security.security.VoicePrintAuth
import com.clara.security.ui.theme.*
import kotlinx.coroutines.launch

/**
 * Ayarlar Ekranı - Voice Print ile Korumalı
 */
@Composable
fun SettingsScreen(connection: ClaraConnection) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    // Voice print durumu
    val isVoiceEnrolled by VoicePrintAuth.isEnrolled.collectAsState()
    val isVerifying by VoicePrintAuth.isVerifying.collectAsState()
    
    // Erişim durumu
    var hasAccess by remember { mutableStateOf(false) }
    var showVoiceDialog by remember { mutableStateOf(false) }
    var showEnrollDialog by remember { mutableStateOf(false) }
    
    // Eğer voice print kayıtlı değilse direkt erişim ver
    LaunchedEffect(isVoiceEnrolled) {
        if (!isVoiceEnrolled) {
            hasAccess = true
        }
    }
    
    if (!hasAccess && isVoiceEnrolled) {
        // Voice verification ekranı
        VoiceVerificationScreen(
            onVerified = { hasAccess = true },
            onEnroll = { showEnrollDialog = true }
        )
    } else {
        // Ana ayarlar ekranı
        SettingsContent(
            connection = connection,
            isVoiceEnrolled = isVoiceEnrolled,
            onEnrollVoice = { showEnrollDialog = true }
        )
    }
    
    // Voice kayıt dialogu
    if (showEnrollDialog) {
        VoiceEnrollDialog(
            onDismiss = { showEnrollDialog = false },
            onSuccess = {
                showEnrollDialog = false
                Toast.makeText(context, "Ses parmak izi kaydedildi!", Toast.LENGTH_SHORT).show()
            }
        )
    }
}

@Composable
private fun VoiceVerificationScreen(
    onVerified: () -> Unit,
    onEnroll: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    var isVerifying by remember { mutableStateOf(false) }
    var errorMessage by remember { mutableStateOf<String?>(null) }
    
    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        Color(0xFF0A0A0A),
                        Color(0xFF1A1A2E)
                    )
                )
            ),
        contentAlignment = Alignment.Center
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            modifier = Modifier.padding(32.dp)
        ) {
            // Kilit ikonu
            Box(
                modifier = Modifier
                    .size(100.dp)
                    .clip(CircleShape)
                    .background(CLARAPrimary.copy(alpha = 0.2f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Lock,
                    contentDescription = null,
                    tint = CLARAPrimary,
                    modifier = Modifier.size(48.dp)
                )
            }
            
            Spacer(Modifier.height(24.dp))
            
            Text(
                "Ayarlara Erişim",
                style = MaterialTheme.typography.headlineSmall,
                fontWeight = FontWeight.Bold,
                color = Color.White
            )
            
            Text(
                "Ses parmak izinizi doğrulayın",
                style = MaterialTheme.typography.bodyMedium,
                color = Color.Gray,
                modifier = Modifier.padding(top = 8.dp)
            )
            
            Spacer(Modifier.height(32.dp))
            
            // Doğrulama butonu
            Button(
                onClick = {
                    scope.launch {
                        isVerifying = true
                        errorMessage = null
                        val result = VoicePrintAuth.verifyVoice()
                        isVerifying = false
                        
                        if (result.isMatch) {
                            onVerified()
                        } else {
                            errorMessage = result.message
                        }
                    }
                },
                enabled = !isVerifying,
                modifier = Modifier
                    .fillMaxWidth()
                    .height(56.dp),
                colors = ButtonDefaults.buttonColors(containerColor = CLARAPrimary)
            ) {
                if (isVerifying) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(24.dp),
                        color = Color.White
                    )
                } else {
                    Icon(Icons.Default.Mic, contentDescription = null)
                    Spacer(Modifier.width(8.dp))
                    Text("Sesimi Doğrula")
                }
            }
            
            errorMessage?.let { error ->
                Text(
                    error,
                    color = CLARAError,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(top = 16.dp)
                )
            }
            
            Spacer(Modifier.height(16.dp))
            
            // Geç butonu (demo için)
            TextButton(onClick = onVerified) {
                Text("Demo: Atla", color = Color.Gray)
            }
        }
    }
}

@Composable
private fun SettingsContent(
    connection: ClaraConnection,
    isVoiceEnrolled: Boolean,
    onEnrollVoice: () -> Unit
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    
    // Security ayarları
    var antiTheftEnabled by remember { mutableStateOf(SecurityPreferences.isAntiTheftEnabled()) }
    var overlayLockEnabled by remember { mutableStateOf(SecurityPreferences.isOverlayLockEnabled()) }
    var aiAutoAction by remember { mutableStateOf(SecurityPreferences.isAiAutoActionEnabled()) }
    var voicePrintEnabled by remember { mutableStateOf(SecurityPreferences.isVoicePrintEnabled()) }
    var smsScanEnabled by remember { mutableStateOf(SecurityPreferences.isSmsScanEnabled()) }
    var trackerBlockEnabled by remember { mutableStateOf(SecurityPreferences.isTrackerBlockEnabled()) }
    
    var showClearDialog by remember { mutableStateOf(false) }
    
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // Anti-Theft Koruma
        item {
            SettingsSection(title = "🛡️ Anti-Theft Koruma")
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.PhonelinkLock,
                title = "Anti-Theft Koruma",
                description = "Telefon çalınma koruması (sensör izleme)",
                checked = antiTheftEnabled,
                onCheckedChange = { 
                    antiTheftEnabled = it
                    SecurityPreferences.setAntiTheftEnabled(it)
                    if (it) {
                        AntiTheftManager.startProtection()
                    } else {
                        AntiTheftManager.stopProtection()
                    }
                }
            )
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.Lock,
                title = "Overlay Kilit Ekranı",
                description = "Tehdit algılandığında kilit ekranı göster",
                checked = overlayLockEnabled,
                onCheckedChange = { 
                    overlayLockEnabled = it
                    SecurityPreferences.setOverlayLockEnabled(it)
                }
            )
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.SmartToy,
                title = "AI Otomatik Aksiyon",
                description = "Tehdit algılandığında AI otomatik müdahale etsin",
                checked = aiAutoAction,
                onCheckedChange = { 
                    aiAutoAction = it
                    SecurityPreferences.setAiAutoActionEnabled(it)
                }
            )
        }
        
        // Ses Doğrulama
        item {
            Spacer(Modifier.height(8.dp))
            SettingsSection(title = "🎤 Ses Doğrulama")
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.RecordVoiceOver,
                title = "Voice Print Koruması",
                description = "Ayarlara sadece sesinizle erişin",
                checked = voicePrintEnabled,
                onCheckedChange = { 
                    voicePrintEnabled = it
                    SecurityPreferences.setVoicePrintEnabled(it)
                }
            )
        }
        
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(16.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Mic,
                        contentDescription = null,
                        tint = if (isVoiceEnrolled) CLARASuccess else CLARASecondary
                    )
                    Spacer(Modifier.width(16.dp))
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "Ses Parmak İzi",
                            fontWeight = FontWeight.Medium
                        )
                        Text(
                            if (isVoiceEnrolled) "Kayıtlı ✓" else "Kayıtlı değil",
                            style = MaterialTheme.typography.bodySmall,
                            color = if (isVoiceEnrolled) CLARASuccess else Color.Gray
                        )
                    }
                    Button(
                        onClick = onEnrollVoice,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = if (isVoiceEnrolled) CLARASecondary else CLARAPrimary
                        )
                    ) {
                        Text(if (isVoiceEnrolled) "Yeniden Kaydet" else "Kaydet")
                    }
                }
            }
        }
        
        // Tarama ve Engelleme
        item {
            Spacer(Modifier.height(8.dp))
            SettingsSection(title = "🔍 Tarama")
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.Message,
                title = "SMS Phishing Tarama",
                description = "Gelen SMS'leri AI ile tara",
                checked = smsScanEnabled,
                onCheckedChange = { 
                    smsScanEnabled = it
                    SecurityPreferences.setSmsScanEnabled(it)
                }
            )
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.Block,
                title = "Tracker Engelleme",
                description = "Bilinen tracker domain'leri engelle",
                checked = trackerBlockEnabled,
                onCheckedChange = { 
                    trackerBlockEnabled = it
                    SecurityPreferences.setTrackerBlockEnabled(it)
                }
            )
        }
        
        // Hakkında
        item {
            Spacer(Modifier.height(8.dp))
            SettingsSection(title = "ℹ️ Hakkında")
        }
        
        item {
            val hasRoot by connection.hasRoot.collectAsState()
            SettingsInfo(
                icon = Icons.Default.Security,
                title = "Root Durumu",
                value = if (hasRoot) "Aktif ✓" else "Yok"
            )
        }
        
        item {
            SettingsInfo(
                icon = Icons.Default.Info,
                title = "Versiyon",
                value = "1.0.0"
            )
        }
        
        // Tehlikeli İşlemler
        item {
            Spacer(Modifier.height(16.dp))
            SettingsSection(title = "⚠️ Gelişmiş")
        }
        
        item {
            SettingsButton(
                icon = Icons.Default.DeleteForever,
                title = "Tüm Verileri Sil",
                description = "Tehdit kayıtları ve voice print'i sil",
                buttonText = "Temizle",
                isDestructive = true,
                onClick = { showClearDialog = true }
            )
        }
        
        item {
            if (isVoiceEnrolled) {
                SettingsButton(
                    icon = Icons.Default.MicOff,
                    title = "Ses Parmak İzini Sil",
                    description = "Kayıtlı ses verisini sil",
                    buttonText = "Sil",
                    isDestructive = true,
                    onClick = {
                        VoicePrintAuth.deleteVoicePrint()
                        Toast.makeText(context, "Ses parmak izi silindi", Toast.LENGTH_SHORT).show()
                    }
                )
            }
        }
        
        item {
            SettingsButton(
                icon = Icons.Default.RestartAlt,
                title = "Korumayı Yeniden Başlat",
                description = "Anti-theft sistemini yeniden başlat",
                buttonText = "Başlat",
                isDestructive = false,
                onClick = {
                    scope.launch {
                        AntiTheftManager.stopProtection()
                        kotlinx.coroutines.delay(500)
                        AntiTheftManager.startProtection()
                        Toast.makeText(context, "Koruma yeniden başlatıldı", Toast.LENGTH_SHORT).show()
                    }
                }
            )
        }
    }
    
    // Silme onay dialogu
    if (showClearDialog) {
        AlertDialog(
            onDismissRequest = { showClearDialog = false },
            title = { Text("Verileri Sil?") },
            text = { Text("Tüm tehdit kayıtları silinecek. Bu işlem geri alınamaz.") },
            confirmButton = {
                Button(
                    onClick = {
                        scope.launch {
                            com.clara.security.data.ThreatDatabase.clearAllThreats(connection.context)
                            connection.loadAllData()
                            showClearDialog = false
                            Toast.makeText(context, "Veriler silindi", Toast.LENGTH_SHORT).show()
                        }
                    },
                    colors = ButtonDefaults.buttonColors(containerColor = CLARAError)
                ) {
                    Text("Sil")
                }
            },
            dismissButton = {
                TextButton(onClick = { showClearDialog = false }) {
                    Text("İptal")
                }
            }
        )
    }
}

@Composable
private fun VoiceEnrollDialog(
    onDismiss: () -> Unit,
    onSuccess: () -> Unit
) {
    val scope = rememberCoroutineScope()
    var isRecording by remember { mutableStateOf(false) }
    var status by remember { mutableStateOf("Hazır") }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Ses Parmak İzi Kaydet") },
        text = {
            Column(horizontalAlignment = Alignment.CenterHorizontally) {
                Text("'Clara beni tanı' diyerek sesinizi kaydedin")
                
                Spacer(Modifier.height(24.dp))
                
                Box(
                    modifier = Modifier
                        .size(80.dp)
                        .clip(CircleShape)
                        .background(
                            if (isRecording) CLARAError.copy(alpha = 0.2f)
                            else CLARAPrimary.copy(alpha = 0.2f)
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Icon(
                        if (isRecording) Icons.Default.MicOff else Icons.Default.Mic,
                        contentDescription = null,
                        tint = if (isRecording) CLARAError else CLARAPrimary,
                        modifier = Modifier.size(40.dp)
                    )
                }
                
                Spacer(Modifier.height(16.dp))
                
                Text(
                    status,
                    style = MaterialTheme.typography.bodyMedium,
                    color = if (isRecording) CLARAError else Color.Gray
                )
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    scope.launch {
                        isRecording = true
                        status = "Kayıt yapılıyor... (3 saniye)"
                        
                        val success = VoicePrintAuth.enrollVoicePrint()
                        
                        isRecording = false
                        if (success) {
                            status = "Başarılı!"
                            kotlinx.coroutines.delay(500)
                            onSuccess()
                        } else {
                            status = "Kayıt başarısız. Mikrofon izni kontrol edin."
                        }
                    }
                },
                enabled = !isRecording
            ) {
                Text(if (isRecording) "Kayıt..." else "Kaydet")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !isRecording) {
                Text("İptal")
            }
        }
    )
}

@Composable
fun SettingsSection(title: String) {
    Text(
        title,
        style = MaterialTheme.typography.titleSmall,
        color = CLARAPrimary,
        fontWeight = FontWeight.SemiBold,
        modifier = Modifier.padding(vertical = 8.dp)
    )
}

@Composable
fun SettingsSwitch(
    icon: ImageVector,
    title: String,
    description: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = if (checked) CLARASuccess else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp)
            )
            
            Spacer(Modifier.width(16.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Switch(
                checked = checked,
                onCheckedChange = onCheckedChange,
                colors = SwitchDefaults.colors(
                    checkedThumbColor = CLARASuccess,
                    checkedTrackColor = CLARASuccess.copy(alpha = 0.5f)
                )
            )
        }
    }
}

@Composable
fun SettingsInfo(
    icon: ImageVector,
    title: String,
    value: String
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp)
            )
            
            Spacer(Modifier.width(16.dp))
            
            Text(
                title,
                style = MaterialTheme.typography.bodyLarge,
                modifier = Modifier.weight(1f)
            )
            
            Text(
                value,
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun SettingsButton(
    icon: ImageVector,
    title: String,
    description: String,
    buttonText: String,
    isDestructive: Boolean,
    onClick: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = if (isDestructive) CLARAError else MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.size(24.dp)
            )
            
            Spacer(Modifier.width(16.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    title,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    color = if (isDestructive) CLARAError else MaterialTheme.colorScheme.onSurface
                )
                Text(
                    description,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Button(
                onClick = onClick,
                colors = if (isDestructive) {
                    ButtonDefaults.buttonColors(containerColor = CLARAError)
                } else {
                    ButtonDefaults.buttonColors()
                }
            ) {
                Text(buttonText)
            }
        }
    }
}
