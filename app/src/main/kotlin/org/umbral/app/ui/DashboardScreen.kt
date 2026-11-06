package org.umbral.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import androidx.compose.runtime.LaunchedEffect
import org.umbral.app.MainViewModel
import org.umbral.core.model.DnsProviders

/** Home: one big switch for protection, one toggle per module. Nothing else. */
@Composable
fun DashboardScreen(vm: MainViewModel, onToggleVpn: (Boolean) -> Unit, onOpenRouting: () -> Unit = {}) {
    val cfg by vm.config.collectAsState()
    val vpnActive by vm.vpnActive.collectAsState()
    val vpnError by vm.vpnError.collectAsState()

    // Module statuses live in volatile fields; poll them once a second.
    var tick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) { while (true) { delay(1000); tick++ } }
    val tor = remember(tick) { vm.torState() }
    val i2p = remember(tick) { vm.i2pState() }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
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
                        vpnActive && cfg.tor.enabled && tor.third > 0 ->
                            "Traffic goes through Tor. Bootstrap ${tor.second}%."
                        vpnActive && cfg.tor.enabled -> "Starting Tor… traffic waits for the daemon."
                        vpnActive && cfg.i2p.enabled -> "Traffic goes through I2P."
                        vpnActive -> "Firewall + encrypted DNS. Traffic leaves directly (not anonymous)."
                        else -> "Nothing is filtered right now."
                    },
                    style = MaterialTheme.typography.bodyMedium
                )
                if (!vpnActive) vpnError?.let { Text("Error: $it", color = MaterialTheme.colorScheme.error) }
                Button(onClick = { onToggleVpn(!vpnActive) }) {
                    Text(if (vpnActive) "Stop" else "Start protection")
                }
            }
        }

        Text("Modules", style = MaterialTheme.typography.titleMedium)

        ModuleToggle(
            title = "Tor",
            subtitle = when {
                !cfg.tor.enabled -> "Off — direct connection"
                vpnActive && tor.third > 0 -> "Running, SOCKS :${tor.third}" + if (tor.second < 100) ", bootstrap ${tor.second}%" else ""
                vpnActive && tor.first == "ERROR" -> "Error — check Logs"
                vpnActive -> "Starting…"
                else -> "Enabled — starts with protection"
            },
            checked = cfg.tor.enabled,
            onToggle = vm::toggleTor,
            extra = {
                if (cfg.tor.enabled && vpnActive && tor.second in 1..99) {
                    LinearProgressIndicator(
                        progress = { tor.second / 100f },
                        modifier = Modifier.fillMaxWidth().padding(top = 6.dp)
                    )
                }
                if (cfg.tor.enabled && vpnActive && tor.third > 0) {
                    TextButton(onClick = { vm.newTorIdentity() }) { Text("New circuit") }
                }
            }
        )

        ModuleToggle(
            title = "I2P (i2pd)",
            subtitle = when {
                !cfg.i2p.enabled -> "Off — *.i2p unreachable"
                vpnActive && i2p.socksReady -> "Router running, SOCKS :${i2p.socksPort}"
                vpnActive -> "Router starting (bootstrap takes minutes)…"
                else -> "Enabled — starts with protection"
            },
            checked = cfg.i2p.enabled,
            onToggle = vm::toggleI2p
        )

        ModuleToggle(
            title = "Encrypted DNS",
            subtitle = if (cfg.dns.mode != org.umbral.core.model.DnsMode.SYSTEM_PASSTHROUGH) {
                val p = DnsProviders.byId(cfg.dns.providerId)
                "On — ${p?.label ?: "custom"}" + if (cfg.dns.viaTor) ", via Tor" else ""
            } else "Off — queries go in plaintext",
            checked = cfg.dns.mode != org.umbral.core.model.DnsMode.SYSTEM_PASSTHROUGH,
            onToggle = vm::toggleEncryptedDns
        )

        ModuleToggle(
            title = "Anti-DPI",
            subtitle = if (cfg.antiDpi.enabled) "On — hides SNI from packet inspectors"
            else "Off — TLS hostnames visible to the network",
            checked = cfg.antiDpi.enabled,
            onToggle = vm::toggleAntiDpi
        )

        Spacer(Modifier.padding(bottom = 4.dp))
        Text(
            "Toggles apply immediately. Apps rules: Apps tab. Everything else: Advanced tab.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun ModuleToggle(
    title: String,
    subtitle: String,
    checked: Boolean,
    onToggle: (Boolean) -> Unit,
    extra: @Composable () -> Unit = {}
) {
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(horizontal = 16.dp, vertical = 10.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(title, style = MaterialTheme.typography.titleMedium)
                    Text(
                        subtitle,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                Switch(checked = checked, onCheckedChange = onToggle)
            }
            extra()
        }
    }
}
