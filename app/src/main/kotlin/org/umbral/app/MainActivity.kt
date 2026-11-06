package org.umbral.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Home
import androidx.compose.material.icons.filled.Apps
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.Public
import androidx.compose.material.icons.filled.Security
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material.icons.filled.Troubleshoot
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import org.umbral.app.ui.AppsScreen
import org.umbral.app.ui.DashboardScreen
import org.umbral.app.ui.DiagnosticsScreen
import org.umbral.app.ui.DnsScreen
import org.umbral.app.ui.I2pScreen
import org.umbral.app.ui.NetScreen
import org.umbral.app.ui.RoutingScreen
import org.umbral.app.ui.SettingsScreen
import org.umbral.app.ui.TorScreen
import org.umbral.app.ui.UmbralTheme

class MainActivity : ComponentActivity() {

    private var pendingViewModel: MainViewModel? = null
    private var startAfterPermission = false

    private val vpnPermission =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
            if (result.resultCode == Activity.RESULT_OK) {
                pendingViewModel?.let { vm -> if (startAfterPermission) vm.reallyStart(this) }
            }
        }

    private val notifPermission =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            UmbralTheme {
                val vm: MainViewModel = viewModel()
                pendingViewModel = vm
                Root(vm, onToggleVpn = { start ->
                    if (start) requestStart() else vm.stopVpn(this)
                })
            }
        }
    }

    private fun requestStart() {
        if (Build.VERSION.SDK_INT >= 33) {
            notifPermission.launch(android.Manifest.permission.POST_NOTIFICATIONS)
        }
        val prepare = VpnService.prepare(this)
        if (prepare != null) {
            startAfterPermission = true
            vpnPermission.launch(prepare)
        } else {
            startAfterPermission = false
            pendingViewModel?.reallyStart(this)
        }
    }
}

private data class Tab(val route: String, val label: String, val icon: ImageVector)

@Composable
private fun Root(vm: MainViewModel, onToggleVpn: (Boolean) -> Unit) {
    val nav = rememberNavController()
    val tabs = listOf(
        Tab("dashboard", "Home", Icons.Filled.Home),
        Tab("apps", "Apps", Icons.Filled.Apps),
        Tab("net", "Advanced", Icons.Filled.Dns),
        Tab("diagnostics", "Logs", Icons.Filled.Troubleshoot),
        Tab("settings", "Settings", Icons.Filled.Settings)
    )
    val backStack by nav.currentBackStackEntryAsState()
    val current = backStack?.destination?.route ?: "dashboard"
    val snackbar = remember { SnackbarHostState() }
    val toast by vm.toast.collectAsState()

    LaunchedEffect(toast) {
        toast?.let {
            snackbar.showSnackbar(it)
            vm.clearToast()
        }
    }

    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        bottomBar = {
            NavigationBar {
                tabs.forEach { tab ->
                    NavigationBarItem(
                        selected = current == tab.route,
                        onClick = {
                            nav.navigate(tab.route) {
                                popUpTo(nav.graph.startDestinationId) { saveState = true }
                                launchSingleTop = true
                                restoreState = true
                            }
                        },
                        icon = { Icon(tab.icon, contentDescription = tab.label) },
                        label = { Text(tab.label) }
                    )
                }
            }
        }
    ) { padding ->
        NavHost(
            navController = nav,
            startDestination = "dashboard",
            modifier = Modifier.padding(padding)
        ) {
            composable("dashboard") { DashboardScreen(vm, onToggleVpn) { nav.navigate("routing") } }
            composable("apps") { AppsScreen(vm) }
            composable("net") { NetScreen(vm) }
            composable("dns") { DnsScreen(vm) }
            composable("tor") { TorScreen(vm) }
            composable("i2p") { I2pScreen(vm) }
            composable("routing") { RoutingScreen(vm) }
            composable("diagnostics") { DiagnosticsScreen(vm) }
            composable("settings") { SettingsScreen(vm) }
        }
    }
}
