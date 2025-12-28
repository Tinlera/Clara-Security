package com.clara.security.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clara.security.data.ClaraConnection
import com.clara.security.ui.theme.*

/**
 * Ayarlar Ekranı
 */
@Composable
fun SettingsScreen(connection: ClaraConnection) {
    // Ayar değerleri
    var autonomousMode by remember { mutableStateOf(false) }
    var notificationsEnabled by remember { mutableStateOf(true) }
    var darkTheme by remember { mutableStateOf(true) }
    var updateInterval by remember { mutableStateOf("6") }
    var showExpandedNotifs by remember { mutableStateOf(true) }
    
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        // Genel Ayarlar
        item {
            SettingsSection(title = "Genel")
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.AutoMode,
                title = "Otonom Mod",
                description = "Tehditlere otomatik müdahale et",
                checked = autonomousMode,
                onCheckedChange = { autonomousMode = it }
            )
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.Notifications,
                title = "Bildirimler",
                description = "Tehdit bildirimleri göster",
                checked = notificationsEnabled,
                onCheckedChange = { notificationsEnabled = it }
            )
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.DarkMode,
                title = "Karanlık Tema",
                description = "Koyu renk teması kullan",
                checked = darkTheme,
                onCheckedChange = { darkTheme = it }
            )
        }
        
        // Tarama Ayarları
        item {
            Spacer(Modifier.height(8.dp))
            SettingsSection(title = "Tarama")
        }
        
        item {
            SettingsSlider(
                icon = Icons.Default.Update,
                title = "Blocklist Güncelleme",
                description = "Her $updateInterval saatte bir güncelle",
                value = updateInterval.toFloatOrNull() ?: 6f,
                valueRange = 1f..24f,
                steps = 23,
                onValueChange = { updateInterval = it.toInt().toString() }
            )
        }
        
        item {
            SettingsSwitch(
                icon = Icons.Default.Fullscreen,
                title = "Detaylı Bildirimler",
                description = "Tehdit detaylarını bildirimde göster",
                checked = showExpandedNotifs,
                onCheckedChange = { showExpandedNotifs = it }
            )
        }
        
        // Hakkında
        item {
            Spacer(Modifier.height(8.dp))
            SettingsSection(title = "Hakkında")
        }
        
        item {
            SettingsInfo(
                icon = Icons.Default.Info,
                title = "Versiyon",
                value = "0.2.0"
            )
        }
        
        item {
            SettingsInfo(
                icon = Icons.Default.Android,
                title = "Modül Tipi",
                value = "KernelSU"
            )
        }
        
        item {
            SettingsInfo(
                icon = Icons.Default.Code,
                title = "Daemon Versiyonu",
                value = "0.2.0-arm64"
            )
        }
        
        // Tehlikeli İşlemler
        item {
            Spacer(Modifier.height(16.dp))
            SettingsSection(title = "Gelişmiş")
        }
        
        item {
            SettingsButton(
                icon = Icons.Default.DeleteForever,
                title = "Tüm Verileri Sil",
                description = "Log ve karantina dosyalarını temizle",
                buttonText = "Temizle",
                isDestructive = true,
                onClick = {
                    // TODO: Veri temizleme
                }
            )
        }
        
        item {
            SettingsButton(
                icon = Icons.Default.RestartAlt,
                title = "Servisleri Yeniden Başlat",
                description = "Tüm daemon'ları yeniden başlat",
                buttonText = "Yeniden Başlat",
                isDestructive = false,
                onClick = {
                    // TODO: Servis yeniden başlatma
                }
            )
        }
    }
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
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
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
                onCheckedChange = onCheckedChange
            )
        }
    }
}

@Composable
fun SettingsSlider(
    icon: ImageVector,
    title: String,
    description: String,
    value: Float,
    valueRange: ClosedFloatingPointRange<Float>,
    steps: Int,
    onValueChange: (Float) -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    icon,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.size(24.dp)
                )
                
                Spacer(Modifier.width(16.dp))
                
                Column {
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
            }
            
            Spacer(Modifier.height(8.dp))
            
            Slider(
                value = value,
                onValueChange = onValueChange,
                valueRange = valueRange,
                steps = steps
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
