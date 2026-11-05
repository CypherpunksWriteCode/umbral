package org.umbral.app.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.umbral.app.MainViewModel
import org.umbral.core.model.ModuleState
import org.umbral.core.model.PresetId
import org.umbral.core.model.RouteAction

@Composable
fun DashboardScreen(vm: MainViewModel, onToggleVpn: (Boolean) -> Unit, onOpenRouting: () -> Unit = {}) {
    val cfg by vm.config.collectAsState()
    val vpnActive by vm.vpnActive.collectAsState()
    val vpnError by vm.vpnError.collectAsState()
    val needsRestart by vm.needsRestart.collectAsState()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Umbral", style = MaterialTheme.typography.headlineMedium)

        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = if (vpnActive)
                    MaterialTheme.colorScheme.primaryContainer
                else MaterialTheme.colorScheme.surfaceVariant
            )
        ) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    if (vpnActive) "Protection active" else "Protection off",
                    style = MaterialTheme.typography.titleLarge
                )
                Text(
                    when {
                        vpnActive && cfg.tor.enabled -> "All tunnelled traffic routes through Tor. DNS is encrypted."
                        vpnActive -> "Encrypted DNS + application firewall active. Traffic leaves directly."
                        else -> "No traffic is being filtered or routed."
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
                if (!vpnActive) vpnError?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
                Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                    Button(onClick = { onToggleVpn(!vpnActive) }) {
                        Text(if (vpnActive) "Stop" else "Start protection")
                    }
                }
                if (needsRestart && vpnActive) {
                    Text(
                        "Configuration changed. Restart the tunnel to apply.",
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall
                    )
                }
            }
        }

        val states = vm.moduleStates(cfg)
        ModuleRow("VPN tunnel & firewall", states["vpn"] ?: ModuleState.OFF)
        ModuleRow("DNS privacy (${cfg.dns.mode})", states["dns"] ?: ModuleState.OFF)
        ModuleRow(
            "Tor routing (global route: ${cfg.defaultRoute.name.lowercase()})",
            states["tor"] ?: ModuleState.OFF
        )
        if (cfg.i2p.enabled) ModuleRow("I2P router (i2pd)", states["i2p"] ?: ModuleState.OFF)
        if (cfg.tor.enabled && vpnActive) {
            val (daemon, boot, socks) = vm.torState()
            Text("Tor: $daemon  bootstrap: $boot%  SOCKS: ${if (socks > 0) socks else "—"}",
                style = MaterialTheme.typography.bodySmall)
            if (boot in 1..99) LinearProgressIndicator(progress = { boot / 100f }, modifier = Modifier.fillMaxWidth())
        }

        Spacer(Modifier.height(8.dp))
        Text("Routing", style = MaterialTheme.typography.titleMedium)
        Card(
            Modifier
                .fillMaxWidth()
                .clickable { onOpenRouting() }
        ) {
            Column(Modifier.padding(12.dp)) {
                Text(
                    "Global tunnel route: ${cfg.defaultRoute.name.lowercase()}  •  strict no-fallback: ${if (cfg.vpn.strictNoFallback) "on" else "off"}\n" +
                        "Bypassed apps: ${cfg.vpn.bypassUids.size} • Blocked apps: ${cfg.appRules.count { it.value.wifi == RouteAction.BLOCK || it.value.mobile == RouteAction.BLOCK }}",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        Spacer(Modifier.height(8.dp))
        Text("Presets", style = MaterialTheme.typography.titleMedium)
        PresetChip("Privacy First", "Encrypted DNS + firewall, direct traffic", PresetId.PRIVACY_FIRST, vm, cfg.tor.enabled || cfg.defaultRoute != RouteAction.DIRECT)
        PresetChip("Tor Routing", "Everything tunneled through Tor", PresetId.TOR_ROUTING, vm, cfg.defaultRoute != RouteAction.TOR)
        PresetChip("I2P Routing", "Tunnelled traffic through I2P (i2pd)", PresetId.I2P_ROUTING, vm, cfg.defaultRoute != RouteAction.I2P)
        PresetChip("DNS Firewall", "Encrypted DNS + firewall only", PresetId.DNS_FIREWALL, vm, false)

        Spacer(Modifier.height(8.dp))
        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("What this does NOT protect against", style = MaterialTheme.typography.titleSmall)
                Text(
                    "• A compromised operating system or rooted device.\n" +
                        "• Traffic you send over HTTPS is still visible to the destination server.\n" +
                        "• Tor does not anonymize traffic you route outside it.\n" +
                        "• Apps excluded (bypassed) from the tunnel use direct connections.\n" +
                        "• A global adversary can attempt traffic analysis on Tor.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}

@Composable
private fun ModuleRow(name: String, state: ModuleState) {
    Card(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(name, style = MaterialTheme.typography.bodyLarge)
                Text(
                    when (state) {
                        ModuleState.OFF -> "off"
                        ModuleState.STARTING -> "starting…"
                        ModuleState.ACTIVE -> "active"
                        ModuleState.ERROR -> "error"
                        ModuleState.STOPPING -> "stopping…"
                    },
                    color = when (state) {
                        ModuleState.ACTIVE -> MaterialTheme.colorScheme.primary
                        ModuleState.ERROR -> MaterialTheme.colorScheme.error
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    style = MaterialTheme.typography.bodySmall
                )
            }
            Spacer(Modifier.height(0.dp))
        }
    }
}

@Composable
private fun PresetChip(
    title: String,
    subtitle: String,
    preset: PresetId,
    vm: MainViewModel,
    warnIfChanged: Boolean
) {
    Card(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(subtitle, style = MaterialTheme.typography.bodySmall)
            }
            OutlinedButton(onClick = { vm.applyPreset(preset) }) { Text("Apply") }
        }
    }
}
