package org.umbral.app

import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.umbral.core.config.ConfigVault
import org.umbral.core.model.AppRule
import org.umbral.core.model.BuiltinBridges
import org.umbral.core.model.ModuleState
import org.umbral.core.model.PresetId
import org.umbral.core.model.Presets
import org.umbral.core.model.RouteAction
import org.umbral.core.model.UmbralConfig
import org.umbral.core.vpn.PrivacyVpnService
import org.umbral.core.vpn.U

data class AppEntry(
    val uid: Int,
    val packageName: String,
    val label: String,
    val isSystem: Boolean
)

sealed class VpnUiState {
    data object Inactive : VpnUiState()
    data object NeedsPermission : VpnUiState()
    data object Active : VpnUiState()
}

class MainViewModel(app: Application) : AndroidViewModel(app) {
    private val kernel = U.mgr(app)

    val config: StateFlow<UmbralConfig> = kernel.configRepo.config
        .stateIn(viewModelScope, SharingStarted.Eagerly, UmbralConfig())

    val vpnActive: StateFlow<Boolean> = kernel.diagnostics.vpnState
    val vpnError: StateFlow<String?> = kernel.diagnostics.vpnError
    val diag = kernel.diagnostics

    private val _apps = MutableStateFlow<List<AppEntry>>(emptyList())
    val apps: StateFlow<List<AppEntry>> = _apps

    private val _toast = MutableStateFlow<String?>(null)
    val toast: StateFlow<String?> = _toast

    val needsRestart = MutableStateFlow(false)

    init {
        refreshApps()
        viewModelScope.launch {
            config.collect { needsRestart.value = vpnActive.value }
        }
    }

    fun refreshApps() {
        viewModelScope.launch {
            _apps.value = loadApps()
        }
    }

    private suspend fun loadApps(): List<AppEntry> = withContext(Dispatchers.IO) {
        val pm = getApplication<Application>().packageManager
        val self = getApplication<Application>().packageName
        pm.getInstalledApplications(PackageManager.GET_META_DATA)
            .asSequence()
            .filter { it.packageName != self }
            .map { info: ApplicationInfo ->
                AppEntry(
                    uid = info.uid,
                    packageName = info.packageName,
                    label = runCatching { pm.getApplicationLabel(info).toString() }.getOrDefault(info.packageName),
                    isSystem = (info.flags and ApplicationInfo.FLAG_SYSTEM) != 0
                )
            }
            .distinctBy { it.uid to it.packageName }
            .sortedBy { it.label.lowercase() }
            .toList()
    }

    fun update(transform: (UmbralConfig) -> UmbralConfig) {
        viewModelScope.launch {
            kernel.configRepo.update(transform)
            needsRestart.value = vpnActive.value
        }
    }

    /**
     * Quick toggles for the Home screen: apply immediately. If the tunnel is
     * running it is restarted in place — no "restart required" nagging.
     */
    fun toggleTor(on: Boolean) = quickToggle { cfg ->
        cfg.copy(
            tor = cfg.tor.copy(enabled = on),
            defaultRoute = when {
                on -> org.umbral.core.model.RouteAction.TOR
                cfg.defaultRoute == org.umbral.core.model.RouteAction.TOR -> org.umbral.core.model.RouteAction.DIRECT
                else -> cfg.defaultRoute
            }
        )
    }

    fun toggleI2p(on: Boolean) = quickToggle { cfg ->
        cfg.copy(
            i2p = cfg.i2p.copy(enabled = on),
            defaultRoute = when {
                on -> org.umbral.core.model.RouteAction.I2P
                cfg.defaultRoute == org.umbral.core.model.RouteAction.I2P -> org.umbral.core.model.RouteAction.DIRECT
                else -> cfg.defaultRoute
            }
        )
    }

    fun toggleEncryptedDns(on: Boolean) = quickToggle { cfg ->
        val mode = if (on) org.umbral.core.model.DnsMode.DOH else org.umbral.core.model.DnsMode.SYSTEM_PASSTHROUGH
        cfg.copy(dns = cfg.dns.copy(mode = mode))
    }

    fun toggleAntiDpi(on: Boolean) = quickToggle { cfg ->
        cfg.copy(antiDpi = cfg.antiDpi.copy(enabled = on))
    }

    private fun quickToggle(transform: (UmbralConfig) -> UmbralConfig) {
        viewModelScope.launch {
            kernel.configRepo.update(transform)
            needsRestart.value = false
            if (vpnActive.value) {
                // In-place reconfigure: daemons (Tor/i2pd) survive, the tunnel
                // is rebuilt. Stopping the whole service here would SIGABRT
                // libtor on Android.
                val app = getApplication<Application>()
                val i = Intent(app, PrivacyVpnService::class.java)
                    .setAction(PrivacyVpnService.ACTION_RESTART)
                app.startForegroundService(i)
            }
        }
    }

    fun applyPreset(preset: PresetId) {
        update { Presets.apply(preset, it) }
    }

    fun startVpn(activity: Context): Boolean {
        val prepare = VpnService.prepare(activity)
        return if (prepare != null) {
            false // caller must launch intent
        } else {
            reallyStart(activity)
            true
        }
    }

    fun reallyStart(context: Context) {
        val i = Intent(context, PrivacyVpnService::class.java)
            .setAction(PrivacyVpnService.ACTION_START)
        context.startForegroundService(i)
    }

    fun stopVpn(context: Context) {
        val i = Intent(context, PrivacyVpnService::class.java)
            .setAction(PrivacyVpnService.ACTION_STOP)
        context.startService(i)
    }

    fun setAppMode(entry: AppEntry, mode: String) {
        update { cfg ->
            var next = cfg
            val rules = cfg.appRules.toMutableMap()
            when (mode) {
                "tunnel" -> {
                    rules.remove(entry.packageName)
                    next = next.copy(vpn = cfg.vpn.copy(bypassUids = cfg.vpn.bypassUids - entry.uid))
                }
                "bypass" -> {
                    rules.remove(entry.packageName)
                    next = next.copy(vpn = cfg.vpn.copy(bypassUids = cfg.vpn.bypassUids + entry.uid))
                }
                "block" -> {
                    next = next.copy(vpn = cfg.vpn.copy(bypassUids = cfg.vpn.bypassUids - entry.uid))
                    rules[entry.packageName] = AppRule(uid = entry.uid, wifi = RouteAction.BLOCK, mobile = RouteAction.BLOCK)
                }
                "block_wifi" -> {
                    val cur = rules[entry.packageName] ?: AppRule(entry.uid)
                    rules[entry.packageName] = cur.copy(wifi = RouteAction.BLOCK, mobile = null)
                }
                "block_mobile" -> {
                    val cur = rules[entry.packageName] ?: AppRule(entry.uid)
                    rules[entry.packageName] = cur.copy(wifi = null, mobile = RouteAction.BLOCK)
                }
            }
            next.copy(appRules = rules)
        }
    }

    fun appMode(cfg: UmbralConfig, entry: AppEntry): String = when {
        entry.uid in cfg.vpn.bypassUids -> "bypass"
        cfg.appRules[entry.packageName]?.let { it.wifi == RouteAction.BLOCK && it.mobile == RouteAction.BLOCK } == true -> "block"
        cfg.appRules[entry.packageName]?.wifi == RouteAction.BLOCK -> "block_wifi"
        cfg.appRules[entry.packageName]?.mobile == RouteAction.BLOCK -> "block_mobile"
        else -> "tunnel"
    }

    fun newTorIdentity() {
        val tc = kernel.tor ?: run {
            _toast.value = "Tor is not running"
            return
        }
        val ok = tc.newIdentity()
        _toast.value = if (ok) "New Tor circuit requested" else "Tor control not ready"
    }

    /** Built-in bridge lists from the app asset (public Orbot/Tor Project set). */
    fun loadBuiltinBridges(): Map<String, List<String>> {
        val app = getApplication<Application>()
        return runCatching {
            val text = app.assets.open("builtin-bridges.json").bufferedReader().use { it.readText() }
            BuiltinBridges.parse(text)
        }.getOrDefault(emptyMap())
    }

    fun selectBuiltinBridges(setId: String, lines: List<String>) {
        update { cfg ->
            cfg.copy(
                tor = cfg.tor.copy(
                    builtinBridgeSet = setId,
                    useBridges = true,
                    bridges = lines.map { org.umbral.core.model.BridgeLine(it, enabled = true) }
                )
            )
        }
    }

    fun clearToast() { _toast.value = null }

    fun exportConfig(passphrase: String?): String? {
        val cfg = config.value
        return try {
            val plain = kernel.configRepo.export(cfg)
            if (passphrase != null) ConfigVault.encrypt(plain, passphrase.toCharArray())
            else plain
        } catch (e: Exception) {
            _toast.value = "Export failed: ${e.message}"
            null
        }
    }

    fun importConfig(text: String, passphrase: String?) {
        viewModelScope.launch {
            try {
                val json = if (passphrase != null) ConfigVault.decrypt(text, passphrase.toCharArray()) else text
                val cfg = kernel.configRepo.import(json)
                kernel.configRepo.replace(cfg)
                _toast.value = "Configuration imported"
                needsRestart.value = vpnActive.value
            } catch (e: Exception) {
                _toast.value = "Import failed: ${e.message}"
            }
        }
    }

    fun torState(): Triple<String, Int, Int> =
        Triple(diag.torDaemon, diag.torBootstrap, diag.torSocksPort)

    data class I2pUiState(val router: String, val socksReady: Boolean, val socksPort: Int)

    fun i2pState(): I2pUiState =
        I2pUiState(diag.i2pRouter, diag.i2pSocksReady, diag.i2pSocksPort)

    fun moduleStates(cfg: UmbralConfig): Map<String, ModuleState> = mapOf(
        "vpn" to if (vpnActive.value) ModuleState.ACTIVE else ModuleState.OFF,
        "dns" to if (vpnActive.value) ModuleState.ACTIVE else ModuleState.OFF,
        "tor" to when {
            !cfg.tor.enabled -> ModuleState.OFF
            vpnActive.value && diag.torSocksPort > 0 -> ModuleState.ACTIVE
            vpnActive.value -> ModuleState.STARTING
            else -> ModuleState.OFF
        },
        "i2p" to when {
            !cfg.i2p.enabled -> ModuleState.OFF
            vpnActive.value && diag.i2pSocksReady -> ModuleState.ACTIVE
            vpnActive.value -> ModuleState.STARTING
            else -> ModuleState.OFF
        }
    )
}
