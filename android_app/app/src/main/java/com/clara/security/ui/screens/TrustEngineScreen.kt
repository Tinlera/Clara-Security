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
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.clara.security.data.ClaraConnection
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

/**
 * Root komutu çalıştır (TrustEngine için)
 */
private suspend fun executeRootCommand(command: String): String = withContext(Dispatchers.IO) {
    try {
        val process = Runtime.getRuntime().exec(arrayOf("su", "-c", command))
        val reader = BufferedReader(InputStreamReader(process.inputStream))
        val output = StringBuilder()
        var line: String?
        while (reader.readLine().also { line = it } != null) {
            output.appendLine(line)
        }
        process.waitFor()
        output.toString().trim()
    } catch (e: Exception) {
        ""
    }
}

/**
 * Uygulama güven durumu
 */
enum class AppTrustStatus {
    TRUSTED,        // 80-100: Yeşil
    NORMAL,         // 50-79: Mavi
    SUSPICIOUS,     // 20-49: Turuncu
    QUARANTINED,    // 0-19: Kırmızı
    SYSTEM          // Sistem uygulaması
}

/**
 * Uygulama güven bilgisi
 */
data class AppTrustInfo(
    val packageName: String,
    val appName: String,
    val score: Int,
    val maxScore: Int,
    val status: AppTrustStatus,
    val installSource: String,
    val violationCount: Int,
    val isWhitelisted: Boolean,
    val isQuarantined: Boolean,
    val lastViolation: String? = null
)

/**
 * Trust Engine ekranı
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrustEngineScreen(
    connection: ClaraConnection,
    onBack: () -> Unit
) {
    var apps by remember { mutableStateOf<List<AppTrustInfo>>(emptyList()) }
    var isLoading by remember { mutableStateOf(true) }
    var selectedFilter by remember { mutableStateOf<AppTrustStatus?>(null) }
    var showQuarantineDialog by remember { mutableStateOf<AppTrustInfo?>(null) }
    
    val scope = rememberCoroutineScope()
    
    // Gerçek veri yükleme - daemon'dan
    LaunchedEffect(Unit) {
        scope.launch {
            try {
                // Trust Engine veritabanından uygulama listesini çek
                val result = executeRootCommand("cat /data/clara/database/trust_scores.json 2>/dev/null || echo '[]'")
                
                // Eğer Trust Engine veritabanı boşsa, yüklü uygulamaları listele
                if (result.isBlank() || result == "[]") {
                    val packagesResult = executeRootCommand("""
                        pm list packages -3 | while read pkg; do
                            name=${'$'}(echo ${'$'}pkg | cut -d: -f2)
                            installer=${'$'}(pm dump ${'$'}name 2>/dev/null | grep 'installerPackageName' | head -1 | cut -d= -f2)
                            echo "${'$'}name|${'$'}installer"
                        done
                    """.trimIndent())
                    
                    apps = packagesResult.lines()
                        .filter { it.contains("|") }
                        .take(20) // İlk 20 uygulama
                        .map { line ->
                            val parts = line.split("|")
                            val packageName = parts[0]
                            val installer = parts.getOrElse(1) { "unknown" }
                            
                            val (status, score, maxScore) = when {
                                installer.contains("vending") -> Triple(AppTrustStatus.TRUSTED, 80, 95)
                                installer.contains("fdroid") -> Triple(AppTrustStatus.TRUSTED, 85, 95)
                                installer.isBlank() || installer == "null" -> Triple(AppTrustStatus.SUSPICIOUS, 30, 70)
                                else -> Triple(AppTrustStatus.NORMAL, 60, 85)
                            }
                            
                            val installSource = when {
                                installer.contains("vending") -> "Play Store"
                                installer.contains("fdroid") -> "F-Droid"
                                installer.isBlank() || installer == "null" -> "Sideload"
                                else -> installer.take(30)
                            }
                            
                            AppTrustInfo(
                                packageName = packageName,
                                appName = packageName.substringAfterLast(".").replaceFirstChar { it.uppercase() },
                                score = score,
                                maxScore = maxScore,
                                status = status,
                                installSource = installSource,
                                violationCount = 0,
                                isWhitelisted = false,
                                isQuarantined = false
                            )
                        }
                }
            } catch (e: Exception) {
                // Hata durumunda boş liste
                apps = emptyList()
            }
            isLoading = false
        }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Trust Engine") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, "Geri")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // Üst özet kartı
            TrustSummaryCard(apps)
            
            // Filtre butonları
            FilterChipsRow(
                selectedFilter = selectedFilter,
                onFilterSelected = { selectedFilter = it }
            )
            
            // Uygulama listesi
            if (isLoading) {
                Box(
                    modifier = Modifier.fillMaxSize(),
                    contentAlignment = Alignment.Center
                ) {
                    CircularProgressIndicator()
                }
            } else {
                val filteredApps = if (selectedFilter != null) {
                    apps.filter { it.status == selectedFilter }
                } else {
                    apps
                }
                
                LazyColumn(
                    modifier = Modifier.fillMaxSize(),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(filteredApps) { app ->
                        AppTrustCard(
                            app = app,
                            onQuarantine = { showQuarantineDialog = app },
                            onWhitelist = { /* whitelist toggle */ },
                            onRelease = { /* release from quarantine */ }
                        )
                    }
                }
            }
        }
    }
    
    // Karantina dialog
    showQuarantineDialog?.let { app ->
        AlertDialog(
            onDismissRequest = { showQuarantineDialog = null },
            title = { Text("Karantinaya Al") },
            text = { 
                Text("${app.appName} uygulamasını karantinaya almak istiyor musunuz?\n\nUygulama askıya alınacak ve ağ erişimi engellenecek.")
            },
            confirmButton = {
                Button(
                    onClick = { 
                        // TODO: Karantinaya al
                        showQuarantineDialog = null
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error
                    )
                ) {
                    Text("Karantinaya Al")
                }
            },
            dismissButton = {
                TextButton(onClick = { showQuarantineDialog = null }) {
                    Text("İptal")
                }
            }
        )
    }
}

@Composable
private fun TrustSummaryCard(apps: List<AppTrustInfo>) {
    val trusted = apps.count { it.status == AppTrustStatus.TRUSTED }
    val normal = apps.count { it.status == AppTrustStatus.NORMAL }
    val suspicious = apps.count { it.status == AppTrustStatus.SUSPICIOUS }
    val quarantined = apps.count { it.status == AppTrustStatus.QUARANTINED }
    
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f)
        )
    ) {
        Column(
            modifier = Modifier.padding(20.dp)
        ) {
            Text(
                "Uygulama Güven Özeti",
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
            
            Spacer(modifier = Modifier.height(16.dp))
            
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceEvenly
            ) {
                TrustStatItem("Güvenilir", trusted, Color(0xFF4CAF50))
                TrustStatItem("Normal", normal, Color(0xFF2196F3))
                TrustStatItem("Şüpheli", suspicious, Color(0xFFFF9800))
                TrustStatItem("Karantina", quarantined, Color(0xFFF44336))
            }
        }
    }
}

@Composable
private fun TrustStatItem(label: String, count: Int, color: Color) {
    Column(
        horizontalAlignment = Alignment.CenterHorizontally
    ) {
        Box(
            modifier = Modifier
                .size(48.dp)
                .clip(CircleShape)
                .background(color.copy(alpha = 0.2f)),
            contentAlignment = Alignment.Center
        ) {
            Text(
                text = count.toString(),
                fontSize = 20.sp,
                fontWeight = FontWeight.Bold,
                color = color
            )
        }
        Spacer(modifier = Modifier.height(4.dp))
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun FilterChipsRow(
    selectedFilter: AppTrustStatus?,
    onFilterSelected: (AppTrustStatus?) -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp)
    ) {
        FilterChip(
            selected = selectedFilter == null,
            onClick = { onFilterSelected(null) },
            label = { Text("Tümü") }
        )
        FilterChip(
            selected = selectedFilter == AppTrustStatus.TRUSTED,
            onClick = { onFilterSelected(AppTrustStatus.TRUSTED) },
            label = { Text("Güvenilir") },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = Color(0xFF4CAF50).copy(alpha = 0.2f)
            )
        )
        FilterChip(
            selected = selectedFilter == AppTrustStatus.SUSPICIOUS,
            onClick = { onFilterSelected(AppTrustStatus.SUSPICIOUS) },
            label = { Text("Şüpheli") },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = Color(0xFFFF9800).copy(alpha = 0.2f)
            )
        )
        FilterChip(
            selected = selectedFilter == AppTrustStatus.QUARANTINED,
            onClick = { onFilterSelected(AppTrustStatus.QUARANTINED) },
            label = { Text("Karantina") },
            colors = FilterChipDefaults.filterChipColors(
                selectedContainerColor = Color(0xFFF44336).copy(alpha = 0.2f)
            )
        )
    }
}

@Composable
private fun AppTrustCard(
    app: AppTrustInfo,
    onQuarantine: () -> Unit,
    onWhitelist: () -> Unit,
    onRelease: () -> Unit
) {
    val statusColor = when (app.status) {
        AppTrustStatus.TRUSTED -> Color(0xFF4CAF50)
        AppTrustStatus.NORMAL -> Color(0xFF2196F3)
        AppTrustStatus.SUSPICIOUS -> Color(0xFFFF9800)
        AppTrustStatus.QUARANTINED -> Color(0xFFF44336)
        AppTrustStatus.SYSTEM -> Color(0xFF9E9E9E)
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = if (app.isQuarantined) 
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
                // Puan göstergesi
                Box(
                    modifier = Modifier
                        .size(56.dp)
                        .clip(CircleShape)
                        .background(
                            Brush.radialGradient(
                                colors = listOf(
                                    statusColor.copy(alpha = 0.3f),
                                    statusColor.copy(alpha = 0.1f)
                                )
                            )
                        ),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = "${app.score}",
                        fontSize = 20.sp,
                        fontWeight = FontWeight.Bold,
                        color = statusColor
                    )
                }
                
                Spacer(modifier = Modifier.width(16.dp))
                
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = app.appName,
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold
                        )
                        
                        if (app.isWhitelisted) {
                            Spacer(modifier = Modifier.width(8.dp))
                            Icon(
                                Icons.Default.Verified,
                                contentDescription = "Whitelist",
                                tint = Color(0xFF4CAF50),
                                modifier = Modifier.size(18.dp)
                            )
                        }
                        
                        if (app.isQuarantined) {
                            Spacer(modifier = Modifier.width(8.dp))
                            Icon(
                                Icons.Default.Block,
                                contentDescription = "Karantina",
                                tint = Color(0xFFF44336),
                                modifier = Modifier.size(18.dp)
                            )
                        }
                    }
                    
                    Text(
                        text = app.installSource,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    
                    // Puan çubuğu
                    Spacer(modifier = Modifier.height(8.dp))
                    LinearProgressIndicator(
                        progress = app.score / 100f,
                        modifier = Modifier
                            .fillMaxWidth()
                            .height(6.dp)
                            .clip(RoundedCornerShape(3.dp)),
                        color = statusColor,
                        trackColor = statusColor.copy(alpha = 0.2f)
                    )
                }
            }
            
            // Son ihlal
            app.lastViolation?.let { violation ->
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        Icons.Default.Warning,
                        contentDescription = null,
                        tint = Color(0xFFFF9800),
                        modifier = Modifier.size(16.dp)
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    Text(
                        text = "Son ihlal: $violation",
                        style = MaterialTheme.typography.bodySmall,
                        color = Color(0xFFFF9800)
                    )
                }
            }
            
            // Aksiyonlar
            if (app.status != AppTrustStatus.SYSTEM) {
                Spacer(modifier = Modifier.height(12.dp))
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End
                ) {
                    if (app.isQuarantined) {
                        OutlinedButton(
                            onClick = onRelease,
                            colors = ButtonDefaults.outlinedButtonColors(
                                contentColor = Color(0xFF4CAF50)
                            )
                        ) {
                            Icon(Icons.Default.LockOpen, null, Modifier.size(18.dp))
                            Spacer(Modifier.width(4.dp))
                            Text("Serbest Bırak")
                        }
                    } else {
                        if (!app.isWhitelisted) {
                            TextButton(onClick = onWhitelist) {
                                Icon(Icons.Default.Verified, null, Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text("Güven")
                            }
                        }
                        
                        if (app.status == AppTrustStatus.SUSPICIOUS) {
                            Spacer(modifier = Modifier.width(8.dp))
                            Button(
                                onClick = onQuarantine,
                                colors = ButtonDefaults.buttonColors(
                                    containerColor = Color(0xFFF44336)
                                )
                            ) {
                                Icon(Icons.Default.Block, null, Modifier.size(18.dp))
                                Spacer(Modifier.width(4.dp))
                                Text("Karantina")
                            }
                        }
                    }
                }
            }
        }
    }
}
