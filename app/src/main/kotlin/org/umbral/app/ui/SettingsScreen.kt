package org.umbral.app.ui

import android.content.Intent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import org.umbral.app.MainViewModel
import org.umbral.core.config.ConfigVault

@Composable
fun SettingsScreen(vm: MainViewModel) {
    val cfg by vm.config.collectAsState()
    var passphrase by remember { mutableStateOf("") }
    var importText by remember { mutableStateOf("") }
    val context = LocalContext.current

    Column(
        Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(12.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp)
    ) {
        Text("Setup", style = MaterialTheme.typography.headlineSmall)

        SwitchRow(
            "Advanced mode",
            "Shows per-network blocking, torrc editor and proxy fields everywhere.",
            cfg.advancedMode
        ) { on -> vm.update { it.copy(advancedMode = on) } }

        SwitchRow(
            "Start automatically after boot",
            "Requires that the VPN permission was granted before rebooting.",
            cfg.autoStartOnBoot
        ) { on -> vm.update { it.copy(autoStartOnBoot = on) } }

        Text("Configuration backup", style = MaterialTheme.typography.titleMedium)
        Text(
            "Export writes a JSON file you choose how to store. With a passphrase it is " +
                "AES-256-GCM encrypted (PBKDF2, 210k iterations). Without a passphrase it is plaintext.",
            style = MaterialTheme.typography.bodySmall
        )
        OutlinedTextField(
            value = passphrase,
            onValueChange = { passphrase = it },
            label = { Text("Passphrase (optional)") },
            modifier = Modifier.fillMaxWidth(),
            singleLine = true
        )

        val exportLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.CreateDocument("application/json")
        ) { uri ->
            uri ?: return@rememberLauncherForActivityResult
            val data = vm.exportConfig(passphrase.takeIf { it.isNotEmpty() }) ?: return@rememberLauncherForActivityResult
            context.contentResolver.openOutputStream(uri)?.use { os ->
                os.write(data.toByteArray(Charsets.UTF_8))
            }
        }
        Button(onClick = {
            exportLauncher.launch("umbral-config.json")
        }) { Text("Export configuration") }

        Text("Restore", style = MaterialTheme.typography.titleMedium)
        val importLauncher = rememberLauncherForActivityResult(
            ActivityResultContracts.OpenDocument()
        ) { uri ->
            uri ?: return@rememberLauncherForActivityResult
            val text = context.contentResolver.openInputStream(uri)?.use { it.readBytes().toString(Charsets.UTF_8) }
            if (text != null) {
                if (ConfigVault.isEncryptedExport(text)) {
                    importText = text // decrypt after user enters passphrase
                } else {
                    vm.importConfig(text, null)
                }
            }
        }
        OutlinedButton(onClick = { importLauncher.launch(arrayOf("*/*")) }) { Text("Pick configuration file") }
        if (importText.isNotEmpty()) {
            OutlinedTextField(
                value = passphrase,
                onValueChange = { passphrase = it },
                label = { Text("Passphrase for this file") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Button(onClick = {
                runCatching { ConfigVault.decrypt(importText, passphrase.toCharArray()) }
                    .onSuccess { vm.importConfig(it, null); importText = "" }
                    .onFailure { vm.importConfig("", null) }
            }) { Text("Decrypt and import") }
        }

        Card(Modifier.fillMaxWidth()) {
            Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("About", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Umbral 0.1.0 — an open-source privacy suite.\n" +
                        "Tor: © The Tor Project, BSD-3 (tor-android 0.4.9.14).\n" +
                        "tun2socks: hev-socks5-tunnel 2.19.3, MIT.\n" +
                        "Pluggable transports: IPtProxy 5.7.0, MIT.\n" +
                        "This program is distributed under GPLv3+. No analytics, no accounts, " +
                        "no telemetry. All configuration stays on the device unless you export it.",
                    style = MaterialTheme.typography.bodySmall
                )
            }
        }
    }
}
