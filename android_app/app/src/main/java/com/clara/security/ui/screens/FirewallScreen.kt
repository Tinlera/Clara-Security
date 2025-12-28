package com.clara.security.ui.screens

import androidx.compose.animation.*
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
import kotlinx.coroutines.delay

/**
 * Firewall kural tipi
 */
enum class FirewallAction {
    ALLOW,      // İzin ver
    DENY,       // Engelle
    LOG_ONLY    // Sadece logla
}

/**
 * Uygulama firewall kuralı
 */
data class FirewallRule(
    val packageName: String,
    val appName: String,
    val wifiAction: FirewallAction,
    val mobileAction: FirewallAction,
    val bytesSent: Long,
    val bytesReceived: Long,
    val isSystemApp: Boolean = false
)

/**
 * Network Firewall ekranı
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun FirewallScreen(
    connection: ClaraConnection,
    onBack: () -> Unit
) {
    var rules by remember { mutableStateOf<List<FirewallRule>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var searchQuery by remember { mutableStateOf("") }
    var showSystemApps by remember { mutableStateOf(false) }
    var selectedRule by remember { mutableStateOf<FirewallRule?>(null) }
    
    // Demo veriler
    LaunchedEffect(Unit) {
        delay(500)
        rules = listOf(
            FirewallRule(
                "com.whatsapp", "WhatsApp",
                FirewallAction.ALLOW, FirewallAction.ALLOW,
                256_000_000, 128_000_000
            ),
            FirewallRule(
                "com.instagram.android", "Instagram",
                FirewallAction.ALLOW, FirewallAction.LOG_ONLY,
                512_000_000, 1_024_000_000
            ),
            FirewallRule(
                "com.facebook.katana", "Facebook",
                FirewallAction.DENY, FirewallAction.DENY,
                0, 0
            ),
            FirewallRule(
                "com.tiktok.android", "TikTok",
                FirewallAction.ALLOW, FirewallAction.DENY,
                1_500_000_000, 500_000_000
            ),
            FirewallRule(
                "com.google.android.gm", "Gmail",
                FirewallAction.ALLOW, FirewallAction.ALLOW,
                50_000_000, 100_000_000
            ),
            FirewallRule(
                "com.android.chrome", "Chrome",
                FirewallAction.ALLOW, FirewallAction.ALLOW,
                2_000_000_000, 500_000_000
            ),
            FirewallRule(
                "com.android.systemui", "System UI",
                FirewallAction.ALLOW, FirewallAction.ALLOW,
                10_000_000, 5_000_000,
                isSystemApp = true
            )
        )
        isLoading = false
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Network Firewall") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Geri")
                    }
                },
                actions = {
                    // Sistem uygulamalarını göster/gizle
                    IconButton(onClick = { showSystemApps = !showSystemApps }) {
                        Icon(
                            if (showSystemApps) Icons.Default.VisibilityOff 
                            else Icons.Default.Visibility,
                            "Sistem Uygulamaları"
                        )
                    }
                }
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // İstatistik kartları
            FirewallStatsRow(rules)
            
            // Arama
            OutlinedTextField(
                value = searchQuery,
                onValueChange = { searchQuery = it },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp),
                placeholder = { Text("Uygulama ara...") },
                leadingIcon = { Icon(Icons.Default.Search, null) },
                singleLine = true,
                shape = RoundedCornerShape(12.dp)
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            // Uygulama listesi
            if (isLoading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else {
                val filteredRules = rules
                    .filter { showSystemApps || !it.isSystemApp }
                    .filter { 
                        searchQuery.isEmpty() || 
                        it.appName.contains(searchQuery, ignoreCase = true) ||
                        it.packageName.contains(searchQuery, ignoreCase = true)
                    }
                
                LazyColumn(
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(filteredRules) { rule ->
                        FirewallRuleCard(
                            rule = rule,
                            onEdit = { selectedRule = rule },
                            onToggleWifi = { 
                                // TODO: WiFi kuralını değiştir
                            },
                            onToggleMobile = {
                                // TODO: Mobil kuralını değiştir
                            }
                        )
                    }
                }
            }
        }
    }
    
    // Kural düzenleme dialog
    selectedRule?.let { rule ->
        FirewallRuleDialog(
            rule = rule,
            onDismiss = { selectedRule = null },
            onSave = { newRule ->
                // TODO: Kuralı kaydet
                selectedRule = null
            }
        )
    }
}

@Composable
private fun FirewallStatsRow(rules: List<FirewallRule>) {
    val blockedCount = rules.count { it.wifiAction == FirewallAction.DENY || it.mobileAction == FirewallAction.DENY }
    val totalSent = rules.sumOf { it.bytesSent }
    val totalReceived = rules.sumOf { it.bytesReceived }
    
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        StatCard(
            title = "Engellenen",
            value = blockedCount.toString(),
            icon = Icons.Default.Block,
            color = Color(0xFFF44336),
            modifier = Modifier.weight(1f)
        )
        StatCard(
            title = "Gönderilen",
            value = formatBytes(totalSent),
            icon = Icons.Default.ArrowUpward,
            color = Color(0xFF2196F3),
            modifier = Modifier.weight(1f)
        )
        StatCard(
            title = "Alınan",
            value = formatBytes(totalReceived),
            icon = Icons.Default.ArrowDownward,
            color = Color(0xFF4CAF50),
            modifier = Modifier.weight(1f)
        )
    }
}

@Composable
private fun StatCard(
    title: String,
    value: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    color: Color,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier,
        colors = CardDefaults.cardColors(
            containerColor = color.copy(alpha = 0.1f)
        )
    ) {
        Column(
            modifier = Modifier.padding(12.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            Icon(
                icon,
                contentDescription = null,
                tint = color,
                modifier = Modifier.size(24.dp)
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = value,
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold,
                color = color
            )
            Text(
                text = title,
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun FirewallRuleCard(
    rule: FirewallRule,
    onEdit: () -> Unit,
    onToggleWifi: () -> Unit,
    onToggleMobile: () -> Unit
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (rule.wifiAction == FirewallAction.DENY && rule.mobileAction == FirewallAction.DENY)
                Color(0xFFF44336).copy(alpha = 0.1f)
            else
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Uygulama ikonu placeholder
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .clip(CircleShape)
                        .background(MaterialTheme.colorScheme.primary.copy(alpha = 0.2f)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = rule.appName.first().toString(),
                        style = MaterialTheme.typography.titleLarge,
                        color = MaterialTheme.colorScheme.primary
                    )
                }
                
                Spacer(modifier = Modifier.width(12.dp))
                
                Column(modifier = Modifier.weight(1f)) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        Text(
                            text = rule.appName,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        if (rule.isSystemApp) {
                            Spacer(modifier = Modifier.width(4.dp))
                            Surface(
                                color = MaterialTheme.colorScheme.secondary.copy(alpha = 0.2f),
                                shape = RoundedCornerShape(4.dp)
                            ) {
                                Text(
                                    text = "SİSTEM",
                                    modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                                    style = MaterialTheme.typography.labelSmall
                                )
                            }
                        }
                    }
                    Text(
                        text = "↑ ${formatBytes(rule.bytesSent)} / ↓ ${formatBytes(rule.bytesReceived)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                IconButton(onClick = onEdit) {
                    Icon(Icons.Default.MoreVert, "Düzenle")
                }
            }
            
            Spacer(modifier = Modifier.height(12.dp))
            Divider()
            Spacer(modifier = Modifier.height(12.dp))
            
            // WiFi ve Mobil kontrolleri
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                NetworkControlChip(
                    label = "WiFi",
                    icon = Icons.Default.Wifi,
                    action = rule.wifiAction,
                    onClick = onToggleWifi
                )
                
                NetworkControlChip(
                    label = "Mobil",
                    icon = Icons.Default.SignalCellularAlt,
                    action = rule.mobileAction,
                    onClick = onToggleMobile
                )
            }
        }
    }
}

@Composable
private fun NetworkControlChip(
    label: String,
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    action: FirewallAction,
    onClick: () -> Unit
) {
    val (color, statusText) = when (action) {
        FirewallAction.ALLOW -> Color(0xFF4CAF50) to "İzinli"
        FirewallAction.DENY -> Color(0xFFF44336) to "Engelli"
        FirewallAction.LOG_ONLY -> Color(0xFFFF9800) to "Log"
    }
    
    FilterChip(
        selected = true,
        onClick = onClick,
        label = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(icon, null, Modifier.size(16.dp))
                Spacer(Modifier.width(4.dp))
                Text("$label: $statusText")
            }
        },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = color.copy(alpha = 0.2f),
            selectedLabelColor = color
        )
    )
}

@Composable
private fun FirewallRuleDialog(
    rule: FirewallRule,
    onDismiss: () -> Unit,
    onSave: (FirewallRule) -> Unit
) {
    var wifiAction by remember { mutableStateOf(rule.wifiAction) }
    var mobileAction by remember { mutableStateOf(rule.mobileAction) }
    
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("${rule.appName} Kuralları") },
        text = {
            Column {
                Text(
                    text = "WiFi Erişimi",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FirewallAction.entries.forEach { action ->
                        FilterChip(
                            selected = wifiAction == action,
                            onClick = { wifiAction = action },
                            label = { Text(action.name) }
                        )
                    }
                }
                
                Spacer(modifier = Modifier.height(16.dp))
                
                Text(
                    text = "Mobil Veri Erişimi",
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold
                )
                Spacer(modifier = Modifier.height(8.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    FirewallAction.entries.forEach { action ->
                        FilterChip(
                            selected = mobileAction == action,
                            onClick = { mobileAction = action },
                            label = { Text(action.name) }
                        )
                    }
                }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onSave(rule.copy(wifiAction = wifiAction, mobileAction = mobileAction))
                }
            ) {
                Text("Kaydet")
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) {
                Text("İptal")
            }
        }
    )
}

private fun formatBytes(bytes: Long): String {
    return when {
        bytes >= 1_000_000_000 -> String.format("%.1f GB", bytes / 1_000_000_000.0)
        bytes >= 1_000_000 -> String.format("%.1f MB", bytes / 1_000_000.0)
        bytes >= 1_000 -> String.format("%.1f KB", bytes / 1_000.0)
        else -> "$bytes B"
    }
}
