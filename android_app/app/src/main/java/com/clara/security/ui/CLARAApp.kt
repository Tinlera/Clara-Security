package com.clara.security.ui

import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.navigation.NavDestination.Companion.hierarchy
import androidx.navigation.NavGraph.Companion.findStartDestination
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.clara.security.data.ClaraConnection
import com.clara.security.ui.screens.*

/**
 * Ana navigasyon rotaları
 */
sealed class Screen(
    val route: String,
    val title: String,
    val icon: @Composable () -> Unit,
    val selectedIcon: @Composable () -> Unit
) {
    object Dashboard : Screen(
        "dashboard",
        "Dashboard",
        { Icon(Icons.Outlined.Dashboard, contentDescription = null) },
        { Icon(Icons.Filled.Dashboard, contentDescription = null) }
    )
    object Threats : Screen(
        "threats",
        "Tehditler",
        { Icon(Icons.Outlined.Warning, contentDescription = null) },
        { Icon(Icons.Filled.Warning, contentDescription = null) }
    )
    object Protection : Screen(
        "protection",
        "Koruma",
        { Icon(Icons.Outlined.Shield, contentDescription = null) },
        { Icon(Icons.Filled.Shield, contentDescription = null) }
    )
    object Settings : Screen(
        "settings",
        "Ayarlar",
        { Icon(Icons.Outlined.Settings, contentDescription = null) },
        { Icon(Icons.Filled.Settings, contentDescription = null) }
    )
}

/**
 * CLARA Security Ana Uygulama
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun CLARAApp(connection: ClaraConnection) {
    val navController = rememberNavController()
    
    val screens = listOf(
        Screen.Dashboard,
        Screen.Threats,
        Screen.Protection,
        Screen.Settings
    )
    
    // Bağlantı durumunu izle
    val isConnected by connection.isConnected.collectAsState()
    val hasRoot by connection.hasRoot.collectAsState()
    val connectionMode by connection.connectionMode.collectAsState()
    
    Scaffold(
        topBar = {
            TopAppBar(
                title = { 
                    Text("CLARA Security") 
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.surface
                ),
                actions = {
                    // Bağlantı durumu göstergesi
                    val isConnected by connection.isConnected.collectAsState()
                    IconButton(onClick = { /* refresh */ }) {
                        Icon(
                            Icons.Default.Circle,
                            contentDescription = if (isConnected) "Bağlı" else "Bağlı Değil",
                            tint = if (isConnected) 
                                MaterialTheme.colorScheme.primary 
                            else 
                                MaterialTheme.colorScheme.error
                        )
                    }
                }
            )
        },
        bottomBar = {
            NavigationBar {
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentDestination = navBackStackEntry?.destination
                
                screens.forEach { screen ->
                    val selected = currentDestination?.hierarchy?.any { it.route == screen.route } == true
                    
                    NavigationBarItem(
                        icon = { if (selected) screen.selectedIcon() else screen.icon() },
                        label = { Text(screen.title) },
                        selected = selected,
                        onClick = {
                            navController.navigate(screen.route) {
                                popUpTo(navController.graph.findStartDestination().id) {
                                    saveState = true
                                }
                                launchSingleTop = true
                                restoreState = true
                            }
                        }
                    )
                }
            }
        }
    ) { innerPadding ->
        NavHost(
            navController = navController,
            startDestination = Screen.Dashboard.route,
            modifier = Modifier.padding(innerPadding)
        ) {
            composable(Screen.Dashboard.route) {
                DashboardScreen(connection)
            }
            composable(Screen.Threats.route) {
                ThreatsScreen(connection)
            }
            composable(Screen.Protection.route) {
                ProtectionScreen(
                    connection = connection,
                    onNavigateToAppLock = { navController.navigate("app_lock") },
                    onNavigateToTrackers = { navController.navigate("trackers") },
                    onNavigateToTrustEngine = { navController.navigate("trust_engine") },
                    onNavigateToWifiAudit = { navController.navigate("wifi_audit") },
                    onNavigateToFirewall = { navController.navigate("firewall") },
                    onNavigateToVpn = { navController.navigate("vpn") }
                )
            }
            composable(Screen.Settings.route) {
                SettingsScreen(connection)
            }
            composable("app_lock") {
                AppLockScreen(
                    connection = connection,
                    onBack = { navController.popBackStack() }
                )
            }
            composable("trackers") {
                TrackerScreen(
                    connection = connection,
                    onBack = { navController.popBackStack() }
                )
            }
            composable("trust_engine") {
                TrustEngineScreen(
                    connection = connection,
                    onBack = { navController.popBackStack() }
                )
            }
            composable("wifi_audit") {
                WifiAuditScreen(
                    connection = connection,
                    onBack = { navController.popBackStack() }
                )
            }
            composable("firewall") {
                FirewallScreen(
                    connection = connection,
                    onBack = { navController.popBackStack() }
                )
            }
            composable("vpn") {
                VpnScreen(
                    connection = connection,
                    onBack = { navController.popBackStack() }
                )
            }
        }
    }
}
