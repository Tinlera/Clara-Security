package com.clara.security.ui.screens

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import com.clara.security.data.ClaraConnection
import com.clara.security.model.LockedApp
import com.clara.security.model.LockType
import com.clara.security.ui.theme.*
import kotlinx.coroutines.launch

/**
 * App Lock Yönetim Ekranı
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppLockScreen(
    connection: ClaraConnection,
    onBack: () -> Unit
) {
    val scope = rememberCoroutineScope()
    
    // Örnek kilitli uygulamalar (gerçekte daemon'dan gelecek)
    var lockedApps by remember {
        mutableStateOf(listOf(
            LockedApp("com.whatsapp", "WhatsApp", LockType.PIN, true),
            LockedApp("com.google.android.apps.photos", "Google Fotoğraflar", LockType.PIN, true),
            LockedApp("com.android.settings", "Ayarlar", LockType.FINGERPRINT, true),
            LockedApp("com.google.android.gm", "Gmail", LockType.PIN, false)
        ))
    }
    
    var showPinDialog by remember { mutableStateOf(false) }
    var showAppSelector by remember { mutableStateOf(false) }
    var masterPin by remember { mutableStateOf("") }
    var confirmPin by remember { mutableStateOf("") }
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Uygulama Kilidi") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.Default.ArrowBack, contentDescription = "Geri")
                    }
                },
                actions = {
                    IconButton(onClick = { showPinDialog = true }) {
                        Icon(Icons.Default.Key, contentDescription = "PIN Değiştir")
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showAppSelector = true },
                containerColor = CLARAPrimary
            ) {
                Icon(Icons.Default.Add, contentDescription = "Uygulama Ekle")
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
            // Bilgi kartı
            item {
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = CLARAPrimary.copy(alpha = 0.1f)
                    ),
                    shape = RoundedCornerShape(16.dp)
                ) {
                    Row(
                        modifier = Modifier.padding(16.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Icon(
                            Icons.Default.Info,
                            contentDescription = null,
                            tint = CLARAPrimary
                        )
                        Spacer(Modifier.width(12.dp))
                        Text(
                            "Kilitli uygulamalar açılmadan önce PIN veya parmak izi gerektirir.",
                            style = MaterialTheme.typography.bodyMedium
                        )
                    }
                }
            }
            
            item {
                Text(
                    "Kilitli Uygulamalar (${lockedApps.count { it.isLocked }})",
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.SemiBold,
                    modifier = Modifier.padding(top = 8.dp)
                )
            }
            
            items(lockedApps) { app ->
                LockedAppCard(
                    app = app,
                    onToggle = { enabled ->
                        lockedApps = lockedApps.map {
                            if (it.packageName == app.packageName) it.copy(isLocked = enabled)
                            else it
                        }
                    },
                    onRemove = {
                        lockedApps = lockedApps.filter { it.packageName != app.packageName }
                    }
                )
            }
            
            if (lockedApps.isEmpty()) {
                item {
                    Box(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(32.dp),
                        contentAlignment = Alignment.Center
                    ) {
                        Column(horizontalAlignment = Alignment.CenterHorizontally) {
                            Icon(
                                Icons.Default.LockOpen,
                                contentDescription = null,
                                modifier = Modifier.size(48.dp),
                                tint = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                            Spacer(Modifier.height(8.dp))
                            Text(
                                "Henüz kilitli uygulama yok",
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
            }
        }
    }
    
    // PIN Değiştirme Dialog
    if (showPinDialog) {
        AlertDialog(
            onDismissRequest = { showPinDialog = false },
            title = { Text("Master PIN Ayarla") },
            text = {
                Column {
                    OutlinedTextField(
                        value = masterPin,
                        onValueChange = { if (it.length <= 6) masterPin = it },
                        label = { Text("Yeni PIN") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth()
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedTextField(
                        value = confirmPin,
                        onValueChange = { if (it.length <= 6) confirmPin = it },
                        label = { Text("PIN Tekrar") },
                        visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        if (masterPin == confirmPin && masterPin.length >= 4) {
                            // TODO: PIN'i kaydet
                            showPinDialog = false
                            masterPin = ""
                            confirmPin = ""
                        }
                    },
                    enabled = masterPin == confirmPin && masterPin.length >= 4
                ) {
                    Text("Kaydet")
                }
            },
            dismissButton = {
                TextButton(onClick = { showPinDialog = false }) {
                    Text("İptal")
                }
            }
        )
    }
}

@Composable
fun LockedAppCard(
    app: LockedApp,
    onToggle: (Boolean) -> Unit,
    onRemove: () -> Unit
) {
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
            // App icon placeholder
            Box(
                modifier = Modifier
                    .size(48.dp)
                    .clip(RoundedCornerShape(12.dp))
                    .background(CLARASecondary.copy(alpha = 0.1f)),
                contentAlignment = Alignment.Center
            ) {
                Icon(
                    Icons.Default.Apps,
                    contentDescription = null,
                    tint = CLARASecondary
                )
            }
            
            Spacer(Modifier.width(12.dp))
            
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    app.appName,
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium
                )
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        when (app.lockType) {
                            LockType.PIN -> Icons.Default.Pin
                            LockType.PATTERN -> Icons.Default.Pattern
                            LockType.FINGERPRINT -> Icons.Default.Fingerprint
                            else -> Icons.Default.Lock
                        },
                        contentDescription = null,
                        modifier = Modifier.size(14.dp),
                        tint = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(Modifier.width(4.dp))
                    Text(
                        when (app.lockType) {
                            LockType.PIN -> "PIN"
                            LockType.PATTERN -> "Desen"
                            LockType.FINGERPRINT -> "Parmak İzi"
                            else -> "Yok"
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
            }
            
            Switch(
                checked = app.isLocked,
                onCheckedChange = onToggle
            )
            
            IconButton(onClick = onRemove) {
                Icon(
                    Icons.Default.Delete,
                    contentDescription = "Kaldır",
                    tint = CLARAError
                )
            }
        }
    }
}
