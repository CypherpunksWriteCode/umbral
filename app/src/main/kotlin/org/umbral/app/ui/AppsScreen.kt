package org.umbral.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.clickable
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.umbral.app.AppEntry
import org.umbral.app.MainViewModel
import org.umbral.core.model.RouteAction
import org.umbral.core.model.UmbralConfig

@Composable
fun AppsScreen(vm: MainViewModel) {
    val cfg by vm.config.collectAsState()
    val apps by vm.apps.collectAsState()
    var query by remember { mutableStateOf("") }
    var showSystem by remember { mutableStateOf(false) }

    Column(Modifier.fillMaxSize().padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text("Apps", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Tunnel: filtered + routed.  Bypass: direct, unfiltered.  Block: no network in tunnel.",
            style = MaterialTheme.typography.bodySmall
        )
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            OutlinedTextField(
                value = query,
                onValueChange = { query = it },
                label = { Text("Search") },
                modifier = Modifier.weight(1f),
                singleLine = true
            )
        }
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            FilterChip(selected = showSystem, onClick = { showSystem = !showSystem }, label = { Text("System apps") })
            Text("${apps.size} apps", style = MaterialTheme.typography.bodySmall)
        }
        LazyColumn(verticalArrangement = Arrangement.spacedBy(4.dp)) {
            val filtered = apps.filter {
                (showSystem || !it.isSystem) &&
                    (query.isBlank() || it.label.contains(query, true) || it.packageName.contains(query, true))
            }
            items(filtered, key = { it.uid.toString() + it.packageName }) { app ->
                AppRow(vm, cfg, app)
            }
        }
    }
}

@Composable
private fun AppRow(vm: MainViewModel, cfg: UmbralConfig, app: AppEntry) {
    val mode = vm.appMode(cfg, app)
    Card(Modifier.fillMaxWidth()) {
        Column(Modifier.padding(horizontal = 12.dp, vertical = 8.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(app.label, style = MaterialTheme.typography.bodyLarge, maxLines = 1)
                    Text(
                        app.packageName + if (app.isSystem) " • system" else "",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 1
                    )
                }
                Text(
                    when (mode) {
                        "tunnel" -> "TUNNEL"
                        "bypass" -> "BYPASS"
                        "block" -> "BLOCK"
                        "block_wifi" -> "BLOCK (Wi-Fi)"
                        "block_mobile" -> "BLOCK (mobile)"
                        else -> "?"
                    },
                    style = MaterialTheme.typography.labelMedium,
                    color = when (mode) {
                        "bypass" -> MaterialTheme.colorScheme.tertiary
                        "tunnel" -> MaterialTheme.colorScheme.primary
                        else -> MaterialTheme.colorScheme.error
                    }
                )
            }
            if (cfg.advancedMode) {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ModeChip(vm, app, "tunnel", "Tunnel", mode == "tunnel")
                    ModeChip(vm, app, "bypass", "Bypass", mode == "bypass")
                    ModeChip(vm, app, "block", "Block", mode == "block")
                    if (mode.startsWith("block_")) {
                        AssistChip(onClick = {}, label = { Text(if (mode == "block_wifi") "Wi-Fi" else "Mobile") })
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ModeChip(vm, app, "block_wifi", "No Wi-Fi", mode == "block_wifi")
                    ModeChip(vm, app, "block_mobile", "No mobile", mode == "block_mobile")
                }
            } else {
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    ModeChip(vm, app, "tunnel", "Tunnel", mode == "tunnel")
                    ModeChip(vm, app, "bypass", "Bypass", mode == "bypass")
                    ModeChip(vm, app, "block", "Block", mode == "block")
                }
            }
        }
    }
}

@Composable
private fun ModeChip(vm: MainViewModel, app: AppEntry, mode: String, label: String, selected: Boolean) {
    FilterChip(
        selected = selected,
        onClick = { vm.setAppMode(app, mode) },
        label = { Text(label) }
    )
}
