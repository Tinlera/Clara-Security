package com.clara.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clara.security.data.ClaraConnection
import com.clara.security.data.ThreatDatabase
import com.clara.security.model.ThreatInfo
import com.clara.security.security.SecurityPreferences
import com.clara.security.ui.theme.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * İstatistik Ekranı
 * 
 * Normal kullanıcının gördüğü ana ekran.
 * Sadece istatistikler ve ne olmuş ne bitmiş bilgisi.
 * Ayarlara erişim YOK (voice print gerektirir)
 */
@Composable
fun StatisticsScreen(connection: ClaraConnection) {
    val scope = rememberCoroutineScope()
    val stats by connection.stats.collectAsState()
    val recentThreats by connection.recentThreats.collectAsState()
    val isConnected by connection.isConnected.collectAsState()
    val hasRoot by connection.hasRoot.collectAsState()
    
    // Koruma durumları
    val antiTheftEnabled by SecurityPreferences.antiTheftEnabled.collectAsState()
    val overlayEnabled by SecurityPreferences.overlayLockEnabled.collectAsState()
    val aiEnabled by SecurityPreferences.aiAutoActionEnabled.collectAsState()
    
    LazyColumn(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        // Koruma Durumu Kartı
        item {
            ProtectionStatusCard(
                isProtected = isConnected && antiTheftEnabled,
                hasRoot = hasRoot,
                aiEnabled = aiEnabled
            )
        }
        
        // Aktif Korumalar
        item {
            Text(
                "Aktif Korumalar",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold
            )
        }
        
        item {
            Card(
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(16.dp)
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    ProtectionRow(
                        icon = Icons.Default.PhonelinkLock,
                        title = "Anti-Theft Koruma",
                        isActive = antiTheftEnabled
                    )
                    Divider(modifier = Modifier.padding(vertical = 8.dp))
                    ProtectionRow(
                        icon = Icons.Default.Lock,
                        title = "Overlay Kilit",
                        isActive = overlayEnabled
                    )
                    Divider(modifier = Modifier.padding(vertical = 8.dp))
                    ProtectionRow(
                        icon = Icons.Default.SmartToy,
                        title = "AI Otomatik Aksiyon",
                        isActive = aiEnabled
                    )
                    Divider(modifier = Modifier.padding(vertical = 8.dp))
                    ProtectionRow(
                        icon = Icons.Default.Message,
                        title = "SMS Tarama",
                        isActive = SecurityPreferences.isSmsScanEnabled()
                    )
                    Divider(modifier = Modifier.padding(vertical = 8.dp))
                    ProtectionRow(
                        icon = Icons.Default.Block,
                        title = "Tracker Engelleme",
                        isActive = SecurityPreferences.isTrackerBlockEnabled()
                    )
                }
            }
        }
        
        // İstatistikler
        item {
            Text(
                "Özet İstatistikler",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 8.dp)
            )
        }
        
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatBox(
                    modifier = Modifier.weight(1f),
                    value = stats.threatsToday.toString(),
                    label = "Bugün",
                    icon = Icons.Default.Today,
                    color = if (stats.threatsToday > 0) CLARAError else CLARASuccess
                )
                StatBox(
                    modifier = Modifier.weight(1f),
                    value = stats.totalThreats.toString(),
                    label = "Toplam Tehdit",
                    icon = Icons.Default.Warning,
                    color = CLARASecondary
                )
            }
        }
        
        item {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                StatBox(
                    modifier = Modifier.weight(1f),
                    value = stats.trackersBlocked.toString(),
                    label = "Engellenen Tracker",
                    icon = Icons.Default.Block,
                    color = CLARATertiary
                )
                StatBox(
                    modifier = Modifier.weight(1f),
                    value = stats.smsScanned.toString(),
                    label = "Taranan SMS",
                    icon = Icons.Default.Message,
                    color = CLARAPrimary
                )
            }
        }
        
        // Son Olaylar
        item {
            Text(
                "Son Olaylar",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.SemiBold,
                modifier = Modifier.padding(top = 8.dp)
            )
        }
        
        if (recentThreats.isEmpty()) {
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(12.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(24.dp),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.CheckCircle,
                            contentDescription = null,
                            tint = CLARASuccess,
                            modifier = Modifier.size(24.dp)
                        )
                        Spacer(Modifier.width(12.dp))
                        Text(
                            "Hiçbir tehdit tespit edilmedi",
                            color = CLARASuccess
                        )
                    }
                }
            }
        } else {
            items(recentThreats.take(5)) { threat ->
                ThreatEventCard(threat)
            }
        }
        
        // Son güncelleme
        item {
            Text(
                "Son güncelleme: ${formatTime(System.currentTimeMillis())}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(top = 8.dp)
            )
        }
        
        // Yenile butonu
        item {
            Button(
                onClick = {
                    scope.launch {
                        connection.loadAllData()
                    }
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Default.Refresh, contentDescription = null)
                Spacer(Modifier.width(8.dp))
                Text("Yenile")
            }
        }
    }
}

@Composable
private fun ProtectionStatusCard(
    isProtected: Boolean,
    hasRoot: Boolean,
    aiEnabled: Boolean
) {
    val gradientColors = if (isProtected) {
        listOf(Color(0xFF00D4FF), Color(0xFF0099CC))
    } else {
        listOf(Color(0xFFFF4444), Color(0xFFCC0000))
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(24.dp),
        colors = CardDefaults.cardColors(containerColor = Color.Transparent)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(Brush.linearGradient(gradientColors))
                .padding(24.dp)
        ) {
            Column {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Box(
                        modifier = Modifier
                            .size(64.dp)
                            .clip(CircleShape)
                            .background(Color.White.copy(alpha = 0.2f)),
                        contentAlignment = Alignment.Center
                    ) {
                        Icon(
                            Icons.Default.Shield,
                            contentDescription = null,
                            tint = Color.White,
                            modifier = Modifier.size(36.dp)
                        )
                    }
                    
                    Spacer(Modifier.width(16.dp))
                    
                    Column {
                        Text(
                            "PROTECTED BY CLARA",
                            style = MaterialTheme.typography.headlineSmall,
                            color = Color.White,
                            fontWeight = FontWeight.Bold
                        )
                        Text(
                            if (hasRoot) "KERNEL LEVEL ENFORCEMENT" else "USER MODE",
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color.White.copy(alpha = 0.8f)
                        )
                    }
                }
                
                Spacer(Modifier.height(16.dp))
                
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    StatusChip(
                        label = if (hasRoot) "Root ✓" else "Root ✗",
                        isActive = hasRoot
                    )
                    StatusChip(
                        label = if (aiEnabled) "AI ✓" else "AI ✗",
                        isActive = aiEnabled
                    )
                    StatusChip(
                        label = "Koruma ✓",
                        isActive = isProtected
                    )
                }
            }
        }
    }
}

@Composable
private fun StatusChip(label: String, isActive: Boolean) {
    Surface(
        shape = RoundedCornerShape(20.dp),
        color = if (isActive) Color.White.copy(alpha = 0.3f) else Color.Black.copy(alpha = 0.2f)
    ) {
        Text(
            label,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            color = Color.White,
            style = MaterialTheme.typography.labelMedium
        )
    }
}

@Composable
private fun ProtectionRow(
    icon: ImageVector,
    title: String,
    isActive: Boolean
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Icon(
            icon,
            contentDescription = null,
            tint = if (isActive) CLARASuccess else CLARAError,
            modifier = Modifier.size(24.dp)
        )
        Spacer(Modifier.width(12.dp))
        Text(
            title,
            modifier = Modifier.weight(1f)
        )
        Box(
            modifier = Modifier
                .size(12.dp)
                .clip(CircleShape)
                .background(if (isActive) CLARASuccess else CLARAError)
        )
    }
}

@Composable
private fun StatBox(
    modifier: Modifier = Modifier,
    value: String,
    label: String,
    icon: ImageVector,
    color: Color
) {
    Card(
        modifier = modifier,
        shape = RoundedCornerShape(16.dp)
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(icon, contentDescription = null, tint = color)
            Spacer(Modifier.height(8.dp))
            Text(
                value,
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            Text(
                label,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ThreatEventCard(threat: ThreatInfo) {
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
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(CircleShape)
                    .background(
                        when (threat.level) {
                            com.clara.security.model.ThreatLevel.CRITICAL -> CLARAError
                            com.clara.security.model.ThreatLevel.HIGH -> Color(0xFFFF6B00)
                            com.clara.security.model.ThreatLevel.MEDIUM -> CLARASecondary
                            else -> CLARATertiary
                        }.copy(alpha = 0.2f)
                    ),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Warning,
                    contentDescription = null,
                    tint = when (threat.level) {
                        com.clara.security.model.ThreatLevel.CRITICAL -> CLARAError
                        com.clara.security.model.ThreatLevel.HIGH -> Color(0xFFFF6B00)
                        com.clara.security.model.ThreatLevel.MEDIUM -> CLARASecondary
                        else -> CLARATertiary
                    }
                )
            }
            
            Spacer(Modifier.width(12.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    threat.type.name.replace("_", " "),
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    threat.description.take(50) + if (threat.description.length > 50) "..." else "",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            Text(
                formatTime(threat.timestamp),
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

private fun formatTime(timestamp: Long): String {
    val sdf = SimpleDateFormat("HH:mm", Locale.getDefault())
    return sdf.format(Date(timestamp))
}
