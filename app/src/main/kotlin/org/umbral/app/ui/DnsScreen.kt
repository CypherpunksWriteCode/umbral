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
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.umbral.app.MainViewModel
import org.umbral.core.model.DnsMode
import org.umbral.core.model.DnsProviders

@Composable
fun DnsScreen(vm: MainViewModel) {
    val cfg by vm.config.collectAsState()
    val dns = cfg.dns

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("DNS privacy", style = MaterialTheme.typography.headlineSmall)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    "Encrypted DNS hides queries from the local network, but the "
                        + "resolver still sees them. It provides privacy, NOT anonymity.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }

        Text("Transport", style = MaterialTheme.typography.titleMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = dns.mode == DnsMode.DOH,
                onClick = { vm.update { it.copy(dns = it.dns.copy(mode = DnsMode.DOH)) } },
                label = { Text("DoH (HTTPS)") }
            )
            FilterChip(
                selected = dns.mode == DnsMode.DOT,
                onClick = { vm.update { it.copy(dns = it.dns.copy(mode = DnsMode.DOT)) } },
                label = { Text("DoT (TLS)") }
            )
            FilterChip(
                selected = dns.mode == DnsMode.SYSTEM_PASSTHROUGH,
                onClick = { vm.update { it.copy(dns = it.dns.copy(mode = DnsMode.SYSTEM_PASSTHROUGH)) } },
                label = { Text("None (passthrough)") }
            )
        }

        Text("Provider", style = MaterialTheme.typography.titleMedium)
        DnsProviders.ALL.forEach { p ->
            Card(Modifier.fillMaxWidth()) {
                Row(
                    Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Column(Modifier.weight(1f)) {
                        Text(p.label, style = MaterialTheme.typography.bodyLarge)
                        Text(
                            listOfNotNull(
                                p.dohUrl, p.dotHost?.let { "DoT: $it" },
                                if (p.filters) "filters some domains" else null
                            ).joinToString(" • "),
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                    FilterChip(
                        selected = dns.providerId == p.id,
                        onClick = { vm.update { it.copy(dns = it.dns.copy(providerId = p.id)) } },
                        label = { Text(if (dns.providerId == p.id) "Selected" else "Use") }
                    )
                }
            }
        }

        if (dns.providerId == "custom") {
            if (dns.mode == DnsMode.DOH) {
                OutlinedTextField(
                    value = dns.customDohUrl,
                    onValueChange = { u -> vm.update { it.copy(dns = it.dns.copy(customDohUrl = u.trim())) } },
                    label = { Text("DoH URL (https://…/dns-query)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            } else {
                OutlinedTextField(
                    value = dns.customDotHost,
                    onValueChange = { h -> vm.update { it.copy(dns = it.dns.copy(customDotHost = h.trim())) } },
                    label = { Text("DoT hostname (port 853)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true
                )
            }
        }

        SwitchRow(
            "Resolve DNS through Tor",
            "The resolver sees queries coming from the Tor exit, not from you. Requires the Tor module.",
            dns.viaTor
        ) { on -> vm.update { it.copy(dns = it.dns.copy(viaTor = on), tor = if (on) it.tor.copy(enabled = true) else it.tor) } }

        SwitchRow(
            "Cache answers locally",
            "Faster and fewer queries leaving the device.",
            dns.cache
        ) { on -> vm.update { it.copy(dns = it.dns.copy(cache = on)) } }

        SwitchRow(
            "Block non-DNS UDP (QUIC etc.)",
            "Default on. Forces apps to TCP so traffic stays inside the enforced path.",
            dns.blockNonDnsUdp
        ) { on -> vm.update { it.copy(dns = it.dns.copy(blockNonDnsUdp = on)) } }

        if (!cfg.advancedMode) {
            Text(
                "DNSSEC: this build does not validate DNSSEC itself. Providers that "
                    + "support it are marked; their validation happens upstream.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}

@Composable
fun SwitchRow(title: String, subtitle: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Card(Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column(Modifier.weight(1f)) {
                Text(title, style = MaterialTheme.typography.bodyLarge)
                Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            Switch(checked = checked, onCheckedChange = onChange)
        }
    }
}
