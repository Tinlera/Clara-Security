package com.clara.security.ui.screens

import androidx.compose.animation.*
import androidx.compose.animation.core.*
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
import androidx.compose.ui.draw.rotate
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.clara.security.data.ClaraConnection
import kotlinx.coroutines.delay

/**
 * WiFi güvenlik seviyesi
 */
enum class WifiSecurityLevel {
    OPEN,       // Şifresiz
    WEP,        // Zayıf
    WPA,        // Orta
    WPA2,       // İyi
    WPA3        // Mükemmel
}

/**
 * Tehdit tipi
 */
enum class WifiThreatType {
    OPEN_NETWORK,
    WEAK_ENCRYPTION,
    EVIL_TWIN,
    DNS_HIJACKING,
    ARP_SPOOFING
}

/**
 * WiFi audit sonucu
 */
data class WifiAuditResult(
    val ssid: String,
    val bssid: String,
    val securityLevel: WifiSecurityLevel,
    val signalStrength: Int,
    val overallScore: Int,
    val threats: List<WifiThreatType>,
    val warnings: List<String>,
    val recommendations: List<String>,
    val isConnected: Boolean = true
)

/**
 * WiFi Security Audit ekranı
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WifiAuditScreen(
    connection: ClaraConnection,
    onBack: () -> Unit
) {
    var auditResult by remember { mutableStateOf<WifiAuditResult?>(null) }
    var isScanning by remember { mutableStateOf(false) }
    var nearbyNetworks by remember { mutableStateOf<List<Pair<String, Int>>>(emptyList()) }
    
    // Demo veri
    LaunchedEffect(Unit) {
        auditResult = WifiAuditResult(
            ssid = "HomeNetwork_5G",
            bssid = "AA:BB:CC:DD:EE:FF",
            securityLevel = WifiSecurityLevel.WPA2,
            signalStrength = 85,
            overallScore = 75,
            threats = listOf(),
            warnings = listOf(
                "Router firmware güncellemesi kontrol edilmeli",
                "WPS devre dışı bırakılmalı"
            ),
            recommendations = listOf(
                "WPA3 desteği olan router kullanın",
                "Güçlü ve benzersiz WiFi şifresi kullanın",
                "Misafir ağı ayarlayın"
            )
        )
        
        nearbyNetworks = listOf(
            "HomeNetwork_5G" to 85,
            "Neighbor_WiFi" to 45,
            "FREE_PUBLIC_WIFI" to 30,
            "CoffeeShop" to 25
        )
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("WiFi Güvenlik Taraması") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Geri")
                    }
                },
                actions = {
                    IconButton(
                        onClick = { 
                            isScanning = true
                            // TODO: Gerçek tarama
                        },
                        enabled = !isScanning
                    ) {
                        if (isScanning) {
                            val rotation by rememberInfiniteTransition(label = "scan").animateFloat(
                                initialValue = 0f,
                                targetValue = 360f,
                                animationSpec = infiniteRepeatable(
                                    animation = tween(1000, easing = LinearEasing)
                                ),
                                label = "rotation"
                            )
                            Icon(
                                Icons.Default.Sync,
                                "Taranıyor",
                                Modifier.rotate(rotation)
                            )
                        } else {
                            Icon(Icons.Default.Refresh, "Yeniden Tara")
                        }
                    }
                }
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // Ana skor kartı
            item {
                auditResult?.let { result ->
                    SecurityScoreCard(result)
                }
            }
            
            // Bağlı ağ bilgisi
            item {
                auditResult?.let { result ->
                    ConnectedNetworkCard(result)
                }
            }
            
            // Tehditler
            auditResult?.threats?.takeIf { it.isNotEmpty() }?.let { threats ->
                item {
                    Text(
                        "🚨 Tespit Edilen Tehditler",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFF44336)
                    )
                }
                items(threats) { threat ->
                    ThreatCard(threat)
                }
            }
            
            // Uyarılar
            auditResult?.warnings?.takeIf { it.isNotEmpty() }?.let { warnings ->
                item {
                    Text(
                        "⚠️ Uyarılar",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = Color(0xFFFF9800)
                    )
                }
                items(warnings) { warning ->
                    WarningCard(warning)
                }
            }
            
            // Öneriler
            auditResult?.recommendations?.takeIf { it.isNotEmpty() }?.let { recommendations ->
                item {
                    Text(
                        "💡 Öneriler",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                }
                items(recommendations) { recommendation ->
                    RecommendationCard(recommendation)
                }
            }
            
            // Yakındaki ağlar
            item {
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    "📡 Yakındaki Ağlar",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold
                )
            }
            
            items(nearbyNetworks) { (ssid, signal) ->
                NearbyNetworkCard(ssid, signal)
            }
        }
    }
}

@Composable
private fun SecurityScoreCard(result: WifiAuditResult) {
    val scoreColor = when {
        result.overallScore >= 80 -> Color(0xFF4CAF50)
        result.overallScore >= 60 -> Color(0xFF8BC34A)
        result.overallScore >= 40 -> Color(0xFFFF9800)
        else -> Color(0xFFF44336)
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = scoreColor.copy(alpha = 0.1f)
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // Büyük skor
            Box(
                modifier = Modifier
                    .size(120.dp)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            colors = listOf(
                                scoreColor.copy(alpha = 0.3f),
                                scoreColor.copy(alpha = 0.1f)
                            )
                        )
                    ),
                contentAlignment = Alignment.Center
            ) {
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "${result.overallScore}",
                        fontSize = 42.sp,
                        fontWeight = FontWeight.Bold,
                        color = scoreColor
                    )
                    Text(
                        text = "/100",
                        fontSize = 14.sp,
                        color = scoreColor.copy(alpha = 0.7f)
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Text(
                text = when {
                    result.overallScore >= 80 -> "Güvenli Ağ"
                    result.overallScore >= 60 -> "Kabul Edilebilir"
                    result.overallScore >= 40 -> "Dikkatli Olun"
                    else -> "Tehlikeli!"
                },
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = scoreColor
            )
            
            Text(
                text = "WiFi güvenlik durumu",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
private fun ConnectedNetworkCard(result: WifiAuditResult) {
    val securityIcon = when (result.securityLevel) {
        WifiSecurityLevel.WPA3 -> Icons.Default.VerifiedUser
        WifiSecurityLevel.WPA2 -> Icons.Default.Lock
        WifiSecurityLevel.WPA -> Icons.Default.Lock
        WifiSecurityLevel.WEP -> Icons.Default.Warning
        WifiSecurityLevel.OPEN -> Icons.Default.LockOpen
    }
    
    val securityColor = when (result.securityLevel) {
        WifiSecurityLevel.WPA3 -> Color(0xFF4CAF50)
        WifiSecurityLevel.WPA2 -> Color(0xFF8BC34A)
        WifiSecurityLevel.WPA -> Color(0xFFFF9800)
        WifiSecurityLevel.WEP -> Color(0xFFF44336)
        WifiSecurityLevel.OPEN -> Color(0xFFF44336)
    }
    
    Card(
        modifier = Modifier.fillMaxWidth()
    ) {
        Column(
            modifier = Modifier.padding(16.dp)
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically
            ) {
                Icon(
                    Icons.Default.Wifi,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(32.dp)
                )
                Spacer(modifier = Modifier.width(12.dp))
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        text = result.ssid,
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold
                    )
                    Text(
                        text = result.bssid,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                // Sinyal gücü
                Column(
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Icon(
                        when {
                            result.signalStrength >= 80 -> Icons.Default.NetworkWifi
                            result.signalStrength >= 60 -> Icons.Default.NetworkWifi
                            result.signalStrength >= 40 -> Icons.Default.NetworkWifi
                            else -> Icons.Default.SignalWifiOff
                        },
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary
                    )
                    Text(
                        text = "${result.signalStrength}%",
                        style = MaterialTheme.typography.labelSmall
                    )
                }
            }
            
            Spacer(modifier = Modifier.height(16.dp))
            Divider()
            Spacer(modifier = Modifier.height(16.dp))
            
            // Şifreleme tipi
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        securityIcon,
                        contentDescription = null,
                        tint = securityColor,
                        modifier = Modifier.size(24.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text("Şifreleme:")
                }
                
                Surface(
                    color = securityColor.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    Text(
                        text = result.securityLevel.name,
                        modifier = Modifier.padding(horizontal = 12.dp, vertical = 4.dp),
                        color = securityColor,
                        fontWeight = FontWeight.Bold
                    )
                }
            }
        }
    }
}

@Composable
private fun ThreatCard(threat: WifiThreatType) {
    val (title, description, icon) = when (threat) {
        WifiThreatType.OPEN_NETWORK -> Triple(
            "Açık Ağ",
            "Bu ağda şifreleme yok. Tüm trafiğiniz görülebilir!",
            Icons.Default.LockOpen
        )
        WifiThreatType.WEAK_ENCRYPTION -> Triple(
            "Zayıf Şifreleme",
            "WEP şifreleme kolayca kırılabilir.",
            Icons.Default.Warning
        )
        WifiThreatType.EVIL_TWIN -> Triple(
            "Evil Twin Tespit Edildi!",
            "Aynı isimde sahte bir ağ var. Dikkat!",
            Icons.Default.ContentCopy
        )
        WifiThreatType.DNS_HIJACKING -> Triple(
            "DNS Hijacking",
            "DNS ayarları değiştirilmiş olabilir.",
            Icons.Default.Dns
        )
        WifiThreatType.ARP_SPOOFING -> Triple(
            "ARP Spoofing",
            "Ağda man-in-the-middle saldırısı olabilir.",
            Icons.Default.SwapHoriz
        )
    }
    
    Card(
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFF44336).copy(alpha = 0.1f)
        )
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
                tint = Color(0xFFF44336),
                modifier = Modifier.size(32.dp)
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.Bold,
                    color = Color(0xFFF44336)
                )
                Text(
                    text = description,
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun WarningCard(warning: String) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFFFF9800).copy(alpha = 0.1f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.Warning,
                contentDescription = null,
                tint = Color(0xFFFF9800),
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = warning,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun RecommendationCard(recommendation: String) {
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.Lightbulb,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.size(20.dp)
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = recommendation,
                style = MaterialTheme.typography.bodyMedium
            )
        }
    }
}

@Composable
private fun NearbyNetworkCard(ssid: String, signal: Int) {
    val signalColor = when {
        signal >= 70 -> Color(0xFF4CAF50)
        signal >= 50 -> Color(0xFF8BC34A)
        signal >= 30 -> Color(0xFFFF9800)
        else -> Color(0xFFF44336)
    }
    
    Card(
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                Icons.Default.Wifi,
                contentDescription = null,
                tint = signalColor
            )
            Spacer(modifier = Modifier.width(12.dp))
            Text(
                text = ssid,
                modifier = Modifier.weight(1f)
            )
            LinearProgressIndicator(
                progress = signal / 100f,
                modifier = Modifier
                    .width(60.dp)
                    .height(4.dp)
                    .clip(RoundedCornerShape(2.dp)),
                color = signalColor,
                trackColor = signalColor.copy(alpha = 0.2f)
            )
            Spacer(modifier = Modifier.width(8.dp))
            Text(
                text = "${signal}%",
                style = MaterialTheme.typography.bodySmall,
                color = signalColor
            )
        }
    }
}
