package org.umbral.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.umbral.app.MainViewModel
import org.umbral.core.dns.DnsEngine

@Composable
fun DiagnosticsScreen(vm: MainViewModel) {
    var tab by remember { mutableIntStateOf(0) }
    val vpnActive by vm.vpnActive.collectAsState()
    val vpnError by vm.vpnError.collectAsState()

    Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Diagnostics", style = MaterialTheme.typography.headlineSmall)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(10.dp)) {
                Text(if (vpnActive) "Tunnel: ACTIVE" else "Tunnel: inactive")
                vpnError?.let { Text("Last error: $it", color = MaterialTheme.colorScheme.error) }
                Text(
                    "VPN-based diagnostics observe only what Android exposes: filtered "
                        + "connections and DNS handled by this app. Traffic of bypassed "
                        + "apps, and anything outside this device, is NOT visible. " +
                        "WebRTC leaks happen inside browsers; we cannot see them.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        TabRow(selectedTabIndex = tab) {
            Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("Connections") })
            Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("DNS") })
            Tab(selected = tab == 2, onClick = { tab = 2 }, text = { Text("Tor log") })
            Tab(selected = tab == 3, onClick = { tab = 3 }, text = { Text("Crash") })
        }

        OutlinedButton(onClick = { vm.diag.clear(); org.umbral.core.vpn.CrashReporter.clear() }) { Text("Clear") }

        when (tab) {
            0 -> LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                items(vm.diag.recentConnections().take(200)) { e ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(8.dp)) {
                            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                Text(e.protocol, style = MaterialTheme.typography.labelMedium)
                                Text(e.destination, style = MaterialTheme.typography.bodySmall, modifier = Modifier.weight(1f))
                                Text(
                                    if (e.blocked) "BLOCKED" else (e.action?.name ?: ""),
                                    color = if (e.blocked) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
                                    style = MaterialTheme.typography.labelMedium
                                )
                            }
                            Text(e.detail, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
            1 -> LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                items(vm.diag.recentDns().take(200)) { l: DnsEngine.QueryLog ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(8.dp)) {
                            Text(l.name, style = MaterialTheme.typography.bodyMedium)
                            Text(
                                "type=${l.type} rcode=${l.rcode} ${if (l.cached) "cache" else "upstream"} ${l.latencyMs}ms",
                                style = MaterialTheme.typography.bodySmall
                            )
                            Text(l.upstream, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
            2 -> LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                items(vm.diag.recentTorLog().take(200)) { line ->
                    Text(line, style = MaterialTheme.typography.bodySmall, modifier = Modifier.padding(4.dp))
                }
            }
            else -> LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                val reports = org.umbral.core.vpn.CrashReporter.reports()
                if (reports.isEmpty()) {
                    item {
                        Text(
                            "No crashes recorded. If the app died, launch it again and check here — " +
                                "the stack trace is saved locally and never uploaded.",
                            style = MaterialTheme.typography.bodySmall,
                            modifier = Modifier.padding(8.dp)
                        )
                    }
                }
                items(reports) { f ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(8.dp)) {
                            Text(f.name, style = MaterialTheme.typography.labelMedium)
                            Text(
                                f.readText().take(4000),
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
            }
        }
    }
}
