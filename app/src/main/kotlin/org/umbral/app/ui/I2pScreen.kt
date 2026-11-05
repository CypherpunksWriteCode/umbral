package org.umbral.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.umbral.app.MainViewModel

@Composable
fun I2pScreen(vm: MainViewModel) {
    val cfg by vm.config.collectAsState()
    val vpnActive by vm.vpnActive.collectAsState()

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("I2P (i2pd)", style = MaterialTheme.typography.headlineSmall)

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                val st = vm.i2pState()
                Text(if (cfg.i2p.enabled) "Module enabled" else "Module disabled", style = MaterialTheme.typography.titleMedium)
                if (cfg.i2p.enabled && vpnActive) {
                    Text(
                        "router: ${st.router}  •  SOCKS ${if (st.socksReady) "ready" else "not ready"} " +
                            "at 127.0.0.1:${st.socksPort.takeIf { it > 0 } ?: cfg.i2p.socksPort}"
                    )
                    if (st.router == "STARTING") {
                        Text(
                            "Bootstrapping into the I2P network (reseed over HTTPS, building " +
                                "tunnels). This can take a few minutes on first start.",
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                } else if (cfg.i2p.enabled) {
                    Text("Start protection to launch the router.")
                }
            }
        }

        SwitchRow(
            "Enable bundled i2pd router",
            "Runs the Purple I2P router (BSD-3) as a child process. SOCKS proxy " +
                "serves *.i2p destinations; clearnet hosts need an outproxy.",
            cfg.i2p.enabled
        ) { on ->
            vm.update {
                it.copy(
                    i2p = it.i2p.copy(enabled = on),
                    defaultRoute = if (on) org.umbral.core.model.RouteAction.I2P else it.defaultRoute
                )
            }
        }

        if (cfg.advancedMode) {
            Text("Advanced", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = cfg.i2p.socksPort.takeIf { it != 4447 }?.toString() ?: "4447",
                onValueChange = { p -> vm.update { it.copy(i2p = it.i2p.copy(socksPort = p.toIntOrNull() ?: 4447)) } },
                label = { Text("SOCKS port") },
                singleLine = true
            )
            OutlinedTextField(
                value = cfg.i2p.httpProxyPort.takeIf { it != 4448 }?.toString() ?: "4448",
                onValueChange = { p -> vm.update { it.copy(i2p = it.i2p.copy(httpProxyPort = p.toIntOrNull() ?: 4448)) } },
                label = { Text("HTTP proxy port") },
                singleLine = true
            )
            OutlinedTextField(
                value = cfg.i2p.outproxyUrl,
                onValueChange = { u -> vm.update { it.copy(i2p = it.i2p.copy(outproxyUrl = u.trim())) } },
                label = { Text("Outproxy (clearnet via I2P, e.g. http://outproxy…)") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            SwitchRow(
                "SAM bridge",
                "For other local apps speaking the SAM protocol (loopback only).",
                cfg.i2p.samEnabled
            ) { on -> vm.update { it.copy(i2p = it.i2p.copy(samEnabled = on)) } }
            SwitchRow(
                "Participate in transit (share bandwidth)",
                "Off by default: your device relays other people's I2P traffic. Your choice.",
                cfg.i2p.transitEnabled
            ) { on -> vm.update { it.copy(i2p = it.i2p.copy(transitEnabled = on)) } }
            OutlinedTextField(
                value = cfg.i2p.extraOptions.joinToString("\n"),
                onValueChange = { t ->
                    vm.update { c -> c.copy(i2p = c.i2p.copy(extraOptions = t.lines().filter { it.isNotBlank() })) }
                },
                label = { Text("Extra i2pd.conf options (allow-listed)") },
                modifier = Modifier.fillMaxWidth()
            )
        }

        Text(
            "How it works: the bundled i2pd (Purple I2P, BSD-3, upstream release 3.0.0) " +
                "runs locally and offers a SOCKS proxy. Route 'I2P' sends tunnelled " +
                "*.i2p connections through it; hostnames are resolved inside I2P " +
                "(no local DNS). Like Tor, I2P is not magic: a compromised device, " +
                "traffic correlation, or hostile floodfills are outside its (and our) power.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
