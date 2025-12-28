package com.clara.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
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
import com.clara.security.model.BlockedTracker
import com.clara.security.model.TrackerCategory
import com.clara.security.ui.theme.*
import kotlinx.coroutines.launch

/**
 * Tracker Yönetim Ekranı
 * Engellenen domainleri ve kategorileri gösterir
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TrackerScreen(
    connection: ClaraConnection,
    onBack: () -> Unit
) {
    val scope = rememberCoroutineScope()
    
    // Kategori filtreleri
    var selectedCategory by remember { mutableStateOf<TrackerCategory?>(null) }
    var showAddDialog by remember { mutableStateOf(false) }
    var newDomain by remember { mutableStateOf("") }
    
    // Örnek tracker listesi (gerçekte daemon'dan gelecek)
    var trackers by remember {
        mutableStateOf(listOf(
            BlockedTracker("facebook.com", TrackerCategory.SOCIAL, 1542, System.currentTimeMillis()),
            BlockedTracker("google-analytics.com", TrackerCategory.ANALYTICS, 3210, System.currentTimeMillis()),
            BlockedTracker("doubleclick.net", TrackerCategory.ADVERTISING, 2876, System.currentTimeMillis()),
            BlockedTracker("ads.yahoo.com", TrackerCategory.ADVERTISING, 890, System.currentTimeMillis()),
            BlockedTracker("amplitude.com", TrackerCategory.ANALYTICS, 456, System.currentTimeMillis()),
            BlockedTracker("mixpanel.com", TrackerCategory.ANALYTICS, 234, System.currentTimeMillis()),
            BlockedTracker("coinhive.com", TrackerCategory.CRYPTOMINER, 12, System.currentTimeMillis()),
            BlockedTracker("twitter.com/i/jot", TrackerCategory.SOCIAL, 678, System.currentTimeMillis()),
            BlockedTracker("appsflyer.com", TrackerCategory.ADVERTISING, 1123, System.currentTimeMillis()),
            BlockedTracker("adjust.com", TrackerCategory.ADVERTISING, 789, System.currentTimeMillis())
        ))
    }
    
    val filteredTrackers = remember(trackers, selectedCategory) {
        if (selectedCategory == null) trackers
        else trackers.filter { it.category == selectedCategory }
    }
    
    // Kategori istatistikleri
    val categoryStats = remember(trackers) {
        trackers.groupBy { it.category }
            .mapValues { it.value.sumOf { t -> t.blockCount } }
    }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Tracker Engelleme") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Geri")
                    }
                },
                actions = {
                    IconButton(onClick = { /* TODO: Blocklist güncelle */ }) {
                        Icon(Icons.Default.Refresh, contentDescription = "Güncelle")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showAddDialog = true },
                containerColor = CLARAPrimary
            ) {
                Icon(Icons.Default.Add, contentDescription = "Domain Ekle")
            }
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            // Özet kartı
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    shape = RoundedCornerShape(20.dp),
                    colors = CardDefaults.cardColors(
                        containerColor = CLARAPrimary
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(20.dp)
                    ) {
                        Text(
                            "Toplam Engellenen",
                            style = MaterialTheme.typography.bodyMedium,
                            color = Color.White.copy(alpha = 0.8f)
                        )
                        Text(
                            "${trackers.sumOf { it.blockCount }}",
                            style = MaterialTheme.typography.displaySmall,
                            color = Color.White,
                            fontWeight = FontWeight.Bold
                        )
                        Spacer(Modifier.height(8.dp))
                        Text(
                            "${trackers.size} domain engelleniyor",
                            style = MaterialTheme.typography.bodySmall,
                            color = Color.White.copy(alpha = 0.7f)
                        )
                    }
                }
            }
            
            // Kategori filtreleri
            item {
                Text(
                    "Kategoriler",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold
                )
            }
            
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState()),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    CategoryChip(
                        label = "Tümü",
                        count = trackers.sumOf { it.blockCount },
                        selected = selectedCategory == null,
                        color = CLARAPrimary,
                        onClick = { selectedCategory = null }
                    )
                    CategoryChip(
                        label = "Reklam",
                        count = categoryStats[TrackerCategory.ADVERTISING] ?: 0,
                        selected = selectedCategory == TrackerCategory.ADVERTISING,
                        color = CLARAWarning,
                        onClick = { selectedCategory = TrackerCategory.ADVERTISING }
                    )
                    CategoryChip(
                        label = "Analitik",
                        count = categoryStats[TrackerCategory.ANALYTICS] ?: 0,
                        selected = selectedCategory == TrackerCategory.ANALYTICS,
                        color = CLARATertiary,
                        onClick = { selectedCategory = TrackerCategory.ANALYTICS }
                    )
                    CategoryChip(
                        label = "Sosyal",
                        count = categoryStats[TrackerCategory.SOCIAL] ?: 0,
                        selected = selectedCategory == TrackerCategory.SOCIAL,
                        color = CLARASecondary,
                        onClick = { selectedCategory = TrackerCategory.SOCIAL }
                    )
                    CategoryChip(
                        label = "Kripto",
                        count = categoryStats[TrackerCategory.CRYPTOMINER] ?: 0,
                        selected = selectedCategory == TrackerCategory.CRYPTOMINER,
                        color = CLARAError,
                        onClick = { selectedCategory = TrackerCategory.CRYPTOMINER }
                    )
                }
            }
            
            // Tracker listesi
            item {
                Text(
                    "Engellenen Domainler (${filteredTrackers.size})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
            
            items(filteredTrackers.sortedByDescending { it.blockCount }) { tracker ->
                TrackerCard(
                    tracker = tracker,
                    onRemove = {
                        trackers = trackers.filter { it.domain != tracker.domain }
                    }
                )
            }
        }
    }
    
    // Yeni domain ekleme dialog
    if (showAddDialog) {
        AlertDialog(
            onDismissRequest = { showAddDialog = false },
            title = { Text("Domain Ekle") },
            text = {
                Column {
                    Text(
                        "Engellemek istediğiniz domain adını girin:",
                        style = MaterialTheme.typography.bodyMedium
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = newDomain,
                        onValueChange = { newDomain = it },
                        label = { Text("Domain") },
                        placeholder = { Text("örn: tracker.example.com") },
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (newDomain.isNotBlank()) {
                            trackers = trackers + BlockedTracker(
                                domain = newDomain,
                                category = TrackerCategory.CUSTOM,
                                blockCount = 0,
                                lastBlocked = 0
                            )
                            newDomain = ""
                            showAddDialog = false
                        }
                    },
                    enabled = newDomain.isNotBlank()
                ) {
                    Text("Ekle")
                }
            },
            dismissButton = {
                TextButton(onClick = { showAddDialog = false }) {
                    Text("İptal")
                }
            }
        )
    }
}

@Composable
fun CategoryChip(
    label: String,
    count: Int,
    selected: Boolean,
    color: Color,
    onClick: () -> Unit
) {
    FilterChip(
        selected = selected,
        onClick = onClick,
        label = {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(label)
                Spacer(Modifier.width(4.dp))
                Surface(
                    color = if (selected) Color.White.copy(alpha = 0.3f) else color.copy(alpha = 0.2f),
                    shape = RoundedCornerShape(4.dp)
                ) {
                    Text(
                        formatCount(count),
                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 1.dp),
                        style = MaterialTheme.typography.labelSmall,
                        fontWeight = FontWeight.Medium
                    )
                }
            }
        },
        colors = FilterChipDefaults.filterChipColors(
            selectedContainerColor = color,
            selectedLabelColor = Color.White
        )
    )
}

@Composable
fun TrackerCard(
    tracker: BlockedTracker,
    onRemove: () -> Unit
) {
    val categoryColor = when (tracker.category) {
        TrackerCategory.ADVERTISING -> CLARAWarning
        TrackerCategory.ANALYTICS -> CLARATertiary
        TrackerCategory.SOCIAL -> CLARASecondary
        TrackerCategory.CRYPTOMINER -> CLARAError
        TrackerCategory.MALWARE -> CLARAError
        TrackerCategory.CUSTOM -> CLARAPrimary
    }
    
    val categoryIcon = when (tracker.category) {
        TrackerCategory.ADVERTISING -> Icons.Default.Campaign
        TrackerCategory.ANALYTICS -> Icons.Default.Analytics
        TrackerCategory.SOCIAL -> Icons.Default.People
        TrackerCategory.CRYPTOMINER -> Icons.Default.CurrencyBitcoin
        TrackerCategory.MALWARE -> Icons.Default.BugReport
        TrackerCategory.CUSTOM -> Icons.Default.Block
    }
    
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Box(
                modifier = Modifier
                    .size(40.dp)
                    .clip(RoundedCornerShape(10.dp))
                    .background(categoryColor.copy(alpha = 0.1f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    categoryIcon,
                    contentDescription = null,
                    tint = categoryColor,
                    modifier = Modifier.size(20.dp)
                )
            }
            
            Spacer(Modifier.width(12.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    tracker.domain,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = FontWeight.Medium
                )
                Text(
                    "${formatCount(tracker.blockCount)} engelleme",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            IconButton(onClick = onRemove) {
                Icon(
                    Icons.Default.RemoveCircleOutline,
                    contentDescription = "Kaldır",
                    tint = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

private fun formatCount(count: Int): String {
    return when {
        count >= 1_000_000 -> String.format("%.1fM", count / 1_000_000.0)
        count >= 1_000 -> String.format("%.1fK", count / 1_000.0)
        else -> count.toString()
    }
}
