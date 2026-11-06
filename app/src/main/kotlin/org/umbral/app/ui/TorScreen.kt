package org.umbral.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.umbral.app.MainViewModel
import org.umbral.core.model.BridgeBatch
import org.umbral.core.model.BuiltinBridges
import org.umbral.core.model.TorConfig

@Composable
fun TorScreen(vm: MainViewModel) {
    val cfg by vm.config.collectAsState()
    val vpnActive by vm.vpnActive.collectAsState()

    // Tor log tail refreshes once a second (fields are volatile in the kernel).
    var tick by remember { mutableStateOf(0) }
    LaunchedEffect(Unit) { while (true) { kotlinx.coroutines.delay(1000); tick++ } }
    val torLog = remember(tick) { vm.diag.recentTorLog().take(24) }
    val (daemon, boot, socks) = remember(tick) { vm.torState() }

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("Tor", style = MaterialTheme.typography.headlineSmall)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text(
                    if (cfg.tor.enabled) "Module enabled" else "Module disabled",
                    style = MaterialTheme.typography.titleMedium
                )
                if (cfg.tor.enabled && vpnActive) {
                    Text("daemon: $daemon  •  bootstrap: $boot%  •  SOCKS: ${if (socks > 0) socks else "—"}")
                    if (boot in 1..99) LinearProgressIndicator(progress = { boot / 100f }, modifier = Modifier.fillMaxWidth())
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        OutlinedButton(onClick = { vm.newTorIdentity() }) { Text("New circuit (NEWNYM)") }
                    }
                    Text(
                        "Traffic currently routed through Tor: ${cfg.appRules.values.count { it.wifi == org.umbral.core.model.RouteAction.TOR }} apps + tunnel default"
                    )
                    if (boot < 100) {
                        Text(
                            "If bootstrap stalls, your network is blocking direct Tor connections. " +
                                "Enable bridges below — Snowflake works in most censored networks; " +
                                "obfs4/webtunnel lines from bridges.torproject.org can be pasted as a list.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.error
                        )
                    }
                } else if (cfg.tor.enabled) {
                    Text("Start protection to boot the Tor daemon.")
                }
            }
        }

        SwitchRow(
            "Enable bundled Tor daemon",
            "Routes tunnelled traffic through Tor and exposes SOCKS on loopback.",
            cfg.tor.enabled
        ) { on -> vm.update { it.copy(tor = it.tor.copy(enabled = on)) } }

        if (cfg.tor.enabled && vpnActive) {
            Text("Tor log (live)", style = MaterialTheme.typography.titleMedium)
            Card(Modifier.fillMaxWidth()) {
                Column(
                    Modifier.padding(8.dp).heightIn(max = 220.dp).verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(2.dp)
                ) {
                    if (torLog.isEmpty()) {
                        Text("no log lines yet…", style = MaterialTheme.typography.bodySmall)
                    } else {
                        torLog.reversed().forEach { line ->
                            Text(line, style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            }
        }

        Text("Bridges", style = MaterialTheme.typography.titleMedium)
        Text(
            "Bridges hide the fact you use Tor from the local network. Pick a built-in set " +
                "or paste your own list (BridgesDB, friends). Formats: " +
                "<transport> <address:port> <fingerprint> [args] (obfs4, snowflake, webtunnel, meek_lite…) " +
                "or a vanilla bridge — just <ip:port> <fingerprint>.",
            style = MaterialTheme.typography.bodySmall
        )
        SwitchRow(
            "Use bridges",
            "Tor connects only through bridges instead of public relays.",
            cfg.tor.useBridges
        ) { on -> vm.update { it.copy(tor = it.tor.copy(useBridges = on)) } }

        if (cfg.tor.useBridges) {
            Text("Source", style = MaterialTheme.typography.titleSmall)
            val builtin = remember { vm.loadBuiltinBridges() }
            BuiltinBridges.SETS.forEach { set ->
                Card(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                    Row(
                        Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                    ) {
                        Column(Modifier.weight(1f)) {
                            Text(set.label, style = MaterialTheme.typography.bodyLarge)
                            Text(set.description, style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                        FilterChip(
                            selected = cfg.tor.builtinBridgeSet == set.id,
                            onClick = { vm.selectBuiltinBridges(set.id, builtin[set.id] ?: emptyList()) },
                            label = { Text(if (cfg.tor.builtinBridgeSet == set.id) "Active" else "Use") }
                        )
                    }
                }
            }
            Card(Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                Row(
                    Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text("Custom list", style = MaterialTheme.typography.bodyLarge)
                        Text("Your own bridge lines below", style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    FilterChip(
                        selected = cfg.tor.builtinBridgeSet == "",
                        onClick = { vm.update { it.copy(tor = it.tor.copy(builtinBridgeSet = "")) } },
                        label = { Text(if (cfg.tor.builtinBridgeSet == "") "Active" else "Use") }
                    )
                }
            }
        }

        if (cfg.tor.bridges.isNotEmpty()) {
            Text("Active bridges (${cfg.tor.bridges.size})", style = MaterialTheme.typography.titleSmall)
        }
        cfg.tor.bridges.forEachIndexed { i, b ->
            Card(Modifier.fillMaxWidth()) {
                Row(
                    Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
                    verticalAlignment = androidx.compose.ui.Alignment.CenterVertically
                ) {
                    Text(
                        b.line.take(48) + if (b.line.length > 48) "…" else "",
                        modifier = Modifier.weight(1f),
                        style = MaterialTheme.typography.bodySmall
                    )
                    if (cfg.tor.builtinBridgeSet == "") {
                        OutlinedButton(onClick = {
                            vm.update { c ->
                                c.copy(tor = c.tor.copy(bridges = c.tor.bridges.filterIndexed { j, _ -> j != i }))
                            }
                        }) { Text("Remove") }
                    }
                }
            }
        }

        if (cfg.tor.builtinBridgeSet == "") {
            var batch by remember { mutableStateOf("") }
            var batchResult by remember { mutableStateOf<String?>(null) }
            OutlinedTextField(
                value = batch,
                onValueChange = { batch = it },
                label = { Text("Paste bridge list (one per line)") },
                modifier = Modifier.fillMaxWidth(),
                minLines = 3
            )
            Button(onClick = {
                val res = BridgeBatch.parse(batch)
                if (res.bridges.isNotEmpty()) {
                    vm.update { c ->
                        c.copy(tor = c.tor.copy(bridges = c.tor.bridges + res.bridges, useBridges = true))
                    }
                    batch = ""
                }
                batchResult = when {
                    res.bridges.isEmpty() && res.errors.isEmpty() -> "Nothing to add"
                    res.errors.isEmpty() -> "Added ${res.bridges.size} bridges"
                    else -> "Added ${res.bridges.size}, rejected ${res.errors.size}:\n" + res.errors.joinToString("\n")
                }
            }) { Text("Add batch") }
            batchResult?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }

        if (cfg.advancedMode) {
            Text("Advanced", style = MaterialTheme.typography.titleMedium)
            Text(
                "Extra torrc lines (allow-list): ExitNodes, EntryNodes, ExcludeNodes, StrictNodes, " +
                    "NumEntryGuards, MaxCircuitDirtiness, CircuitStreamTimeout, ConnectionPadding, " +
                    "ReducedConnectionPadding, ReducedCircuitPadding, UseIPv4, UseIPv6.",
                style = MaterialTheme.typography.bodySmall
            )
            OutlinedTextField(
                value = cfg.tor.extraTorrc.joinToString("\n"),
                onValueChange = { t ->
                    val lines = t.lines().filter { it.isNotBlank() }
                    vm.update { c -> c.copy(tor = c.tor.copy(extraTorrc = lines)) }
                },
                label = { Text("Extra torrc") },
                modifier = Modifier.fillMaxWidth()
            )
        }

        Text(
            "Limitations: this build ships no geoip database (ExitNodes/ExcludeNodes by country are ignored). " +
                "Tor hides sources from destinations, but cannot protect against a compromised device, " +
                "traffic confirmation, or identifying behavior in protocols carried over Tor.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
