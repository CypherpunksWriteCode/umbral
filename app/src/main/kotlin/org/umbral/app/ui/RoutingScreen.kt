package org.umbral.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.umbral.app.MainViewModel
import org.umbral.core.model.RouteAction

@Composable
fun RoutingScreen(vm: MainViewModel) {
    val cfg by vm.config.collectAsState()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("Routing", style = MaterialTheme.typography.headlineSmall)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "Global route for all tunnelled apps. Per-app exceptions: " +
                        "Apps → Tunnel / Bypass / Block. There is NO silent fallback: " +
                        "if Tor or the proxy is unreachable and strict mode is on, " +
                        "connections are refused, never sent directly.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        Text("Default route", style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            RouteChip("Direct", RouteAction.DIRECT, cfg, vm)
            RouteChip("Tor", RouteAction.TOR, cfg, vm)
            RouteChip("I2P", RouteAction.I2P, cfg, vm)
            RouteChip("Proxy", RouteAction.PROXY, cfg, vm)
        }

        SwitchRow(
            "Strict: no fallback to direct",
            "If Tor or the proxy fails, connections fail closed. Turning this off leaks traffic directly — not recommended.",
            cfg.vpn.strictNoFallback
        ) { on -> vm.update { it.copy(vpn = it.vpn.copy(strictNoFallback = on)) } }

        Text("Anti-DPI (TLS ClientHello fragmentation)", style = MaterialTheme.typography.titleMedium)
        Text(
            "Splits the first TLS record of every tunneled HTTPS connection into small TCP writes. " +
                "Bytes on the wire do not change (the TLS handshake stays valid), but packet-inspecting " +
                "middleboxes that do not reassemble segments lose sight of the SNI hostname. " +
                "Real SNI *rewriting* is impossible without a MITM proxy (it breaks the Finished MAC) — " +
                "this is the honest, working variant of the trick.",
            style = MaterialTheme.typography.bodySmall
        )
        SwitchRow(
            "Fragment ClientHello",
            "Recommended chunk size 8 bytes. Slight latency cost, no TLS breakage.",
            cfg.antiDpi.enabled
        ) { on -> vm.update { it.copy(antiDpi = it.antiDpi.copy(enabled = on)) } }
        if (cfg.antiDpi.enabled) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                listOf(1, 4, 8, 16).forEach { size ->
                    FilterChip(
                        selected = cfg.antiDpi.chunkSize == size,
                        onClick = { vm.update { it.copy(antiDpi = it.antiDpi.copy(chunkSize = size)) } },
                        label = { Text("$size B") }
                    )
                }
            }
        }
        Text(
            "Observed SNI hostnames appear in Diagnostics → Connections.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )

        if (cfg.defaultRoute == RouteAction.PROXY || cfg.advancedMode) {
            Text("Custom SOCKS5 proxy", style = MaterialTheme.typography.titleMedium)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = cfg.proxy.host,
                    onValueChange = { h -> vm.update { it.copy(proxy = it.proxy.copy(host = h.trim())) } },
                    label = { Text("Host") },
                    modifier = Modifier.weight(2f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = cfg.proxy.port.takeIf { it != 0 }?.toString() ?: "",
                    onValueChange = { p -> vm.update { it.copy(proxy = it.proxy.copy(port = p.toIntOrNull() ?: 0)) } },
                    label = { Text("Port") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = cfg.proxy.username ?: "",
                    onValueChange = { u -> vm.update { it.copy(proxy = it.proxy.copy(username = u.ifBlank { null })) } },
                    label = { Text("User (optional)") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
                OutlinedTextField(
                    value = cfg.proxy.password ?: "",
                    onValueChange = { p -> vm.update { it.copy(proxy = it.proxy.copy(password = p.ifBlank { null })) } },
                    label = { Text("Password (optional)") },
                    modifier = Modifier.weight(1f),
                    singleLine = true
                )
            }
            Text(
                "Hostnames are sent to the proxy (remote DNS). Stored locally only.",
                style = MaterialTheme.typography.bodySmall
            )
        }

        Text(
            "Bypassed apps (${cfg.vpn.bypassUids.size} UIDs) use direct, unfiltered connections.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}

@Composable
private fun RouteChip(label: String, action: RouteAction, cfg: org.umbral.core.model.UmbralConfig, vm: MainViewModel) {
    FilterChip(
        selected = cfg.defaultRoute == action,
        onClick = {
            vm.update { c ->
                c.copy(
                    defaultRoute = action,
                    tor = if (action == RouteAction.TOR) c.tor.copy(enabled = true) else c.tor,
                    i2p = if (action == RouteAction.I2P) c.i2p.copy(enabled = true) else c.i2p
                )
            }
        },
        label = { Text(label) }
    )
}
