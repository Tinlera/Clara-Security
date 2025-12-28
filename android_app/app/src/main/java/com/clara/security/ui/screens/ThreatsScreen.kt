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
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.clara.security.data.ClaraConnection
import com.clara.security.model.ThreatInfo
import com.clara.security.model.ThreatLevel
import com.clara.security.model.ThreatType
import com.clara.security.ui.theme.*
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

/**
 * Tehditler Ekranı
 * Tespit edilen tehditlerin listesi
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ThreatsScreen(connection: ClaraConnection) {
    val scope = rememberCoroutineScope()
    val threats by connection.recentThreats.collectAsState()
    var selectedFilter by remember { mutableStateOf<ThreatLevel?>(null) }
    
    val filteredThreats = remember(threats, selectedFilter) {
        if (selectedFilter == null) threats
        else threats.filter { it.level == selectedFilter }
    }
    
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
    ) {
        // Filtre Chips
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(bottom = 16.dp),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FilterChip(
                selected = selectedFilter == null,
                onClick = { selectedFilter = null },
                label = { Text("Tümü") }
            )
            FilterChip(
                selected = selectedFilter == ThreatLevel.CRITICAL,
                onClick = { selectedFilter = ThreatLevel.CRITICAL },
                label = { Text("Kritik") },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = CLARAError.copy(alpha = 0.2f)
                )
            )
            FilterChip(
                selected = selectedFilter == ThreatLevel.HIGH,
                onClick = { selectedFilter = ThreatLevel.HIGH },
                label = { Text("Yüksek") },
                colors = FilterChipDefaults.filterChipColors(
                    selectedContainerColor = CLARAWarning.copy(alpha = 0.2f)
                )
            )
            FilterChip(
                selected = selectedFilter == ThreatLevel.MEDIUM,
                onClick = { selectedFilter = ThreatLevel.MEDIUM },
                label = { Text("Orta") }
            )
        }
        
        // Tehdit Listesi
        if (filteredThreats.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .weight(1f),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        Icons.Default.CheckCircle,
                        contentDescription = null,
                        modifier = Modifier.size(64.dp),
                        tint = CLARASuccess
                    )
                    Spacer(Modifier.height(16.dp))
                    Text(
                        "Tehdit Bulunamadı",
                        style = MaterialTheme.typography.titleLarge,
                        fontWeight = FontWeight.SemiBold
                    )
                    Text(
                        "Sisteminiz güvende görünüyor",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                items(filteredThreats) { threat ->
                    ThreatCard(threat = threat)
                }
            }
        }
    }
}

@Composable
fun ThreatCard(threat: ThreatInfo) {
    val levelColor = when (threat.level) {
        ThreatLevel.CRITICAL -> CLARAError
        ThreatLevel.HIGH -> CLARAWarning
        ThreatLevel.MEDIUM -> Color(0xFFF97316) // Orange
        ThreatLevel.LOW -> CLARATertiary
        ThreatLevel.NONE -> CLARASuccess
    }
    
    val typeIcon = when (threat.type) {
        ThreatType.PHISHING_SMS -> Icons.Default.Message
        ThreatType.PHISHING_URL -> Icons.Default.Link
        ThreatType.MALWARE_FILE -> Icons.Default.InsertDriveFile
        ThreatType.SUSPICIOUS_APP -> Icons.Default.Apps
        ThreatType.NETWORK_ATTACK -> Icons.Default.Wifi
        ThreatType.KEYLOGGER -> Icons.Default.Keyboard
        ThreatType.ROOT_DETECTION -> Icons.Default.AdminPanelSettings
        ThreatType.PERMISSION_ABUSE -> Icons.Default.PrivacyTip
        else -> Icons.Default.Warning
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(16.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.Top
        ) {
            // Seviye göstergesi
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(levelColor.copy(alpha = 0.1f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    typeIcon,
                    contentDescription = null,
                    tint = levelColor,
                    modifier = Modifier.size(24.dp)
                )
            }
            
            Spacer(Modifier.width(12.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Text(
                        getThreatTypeName(threat.type),
                        style = MaterialTheme.typography.titleSmall,
                        fontWeight = FontWeight.SemiBold
                    )
                    
                    Surface(
                        color = levelColor.copy(alpha = 0.1f),
                        shape = RoundedCornerShape(4.dp)
                    ) {
                        Text(
                            getThreatLevelName(threat.level),
                            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
                            style = MaterialTheme.typography.labelSmall,
                            color = levelColor,
                            fontWeight = FontWeight.Medium
                        )
                    }
                }
                
                Spacer(Modifier.height(4.dp))
                
                Text(
                    threat.description,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2
                )
                
                Spacer(Modifier.height(8.dp))
                
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.AccessTime,
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        formatTimestamp(threat.timestamp),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    
                    if (threat.source.isNotBlank()) {
                        Spacer(Modifier.width(12.dp))
                        Icon(
                            Icons.Default.Source,
                            contentDescription = null,
                            modifier = Modifier.size(14.dp),
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(Modifier.width(4.dp))
                        Text(
                            threat.source.take(30),
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        }
    }
}

fun getThreatTypeName(type: ThreatType): String = when (type) {
    ThreatType.PHISHING_SMS -> "SMS Phishing"
    ThreatType.PHISHING_URL -> "Zararlı URL"
    ThreatType.MALWARE_FILE -> "Zararlı Dosya"
    ThreatType.SUSPICIOUS_APP -> "Şüpheli Uygulama"
    ThreatType.NETWORK_ATTACK -> "Ağ Saldırısı"
    ThreatType.KEYLOGGER -> "Keylogger"
    ThreatType.ROOT_DETECTION -> "Root Algılandı"
    ThreatType.PERMISSION_ABUSE -> "İzin İstismarı"
    else -> "Bilinmeyen Tehdit"
}

fun getThreatLevelName(level: ThreatLevel): String = when (level) {
    ThreatLevel.CRITICAL -> "Kritik"
    ThreatLevel.HIGH -> "Yüksek"
    ThreatLevel.MEDIUM -> "Orta"
    ThreatLevel.LOW -> "Düşük"
    ThreatLevel.NONE -> "Yok"
}

fun formatTimestamp(timestamp: Long): String {
    val sdf = SimpleDateFormat("dd MMM, HH:mm", Locale("tr", "TR"))
    return sdf.format(Date(timestamp))
}
