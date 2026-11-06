package org.umbral.core.tor

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.os.IBinder
import androidx.localbroadcastmanager.content.LocalBroadcastManager
import IPtProxy.Controller
import IPtProxy.OnTransportEvents
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import net.freehaven.tor.control.RawEventListener
import net.freehaven.tor.control.TorControlCommands
import net.freehaven.tor.control.TorControlConnection
import org.umbral.core.model.ModuleState
import org.umbral.core.model.TorConfig
import org.torproject.jni.TorService
import java.io.File

/**
 * Owns the bundled Tor daemon (tor-android `org.torproject.jni.TorService`).
 *
 * Lifecycle verified against TorService.java (tor-android 0.4.9.14):
 *  - tor config is read from TorService.getTorrc(context); the service also
 *    writes its own `torrc-defaults` with SOCKSPort (9050 if free, else auto).
 *  - status arrives as LocalBroadcastManager intents ACTION_STATUS with
 *    EXTRA_STATUS in {OFF, STARTING, ON, STOPPING}.
 *  - SOCKS port is available on the bound service instance after bootstrap
 *    (getSocksPort(), from GETINFO net/listeners/socks).
 *  - the control connection returned by getTorControlConnection() is already
 *    authenticated (cookie auth disabled by the service itself).
 */
class TorController(
    private val context: Context,
    private val scope: CoroutineScope,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    data class TorState(
        val daemon: ModuleState = ModuleState.OFF,
        val bootstrapProgress: Int = 0,
        val socksPort: Int = -1,
        val log: List<String> = emptyList()
    ) {
        val socksReady get() = socksPort > 0
    }

    private val _state = MutableStateFlow(TorState())
    val state: StateFlow<TorState> = _state.asStateFlow()

    private var torService: TorService? = null
    private var iptController: Controller? = null
    private var bound = false
    private val logBuf = ArrayDeque<String>()
    private var config: TorConfig = TorConfig()

    private val connection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            torService = (service as TorService.LocalBinder).service
            bound = true
            scope.launch { watchSocksPort() }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            torService = null
            bound = false
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(ctx: Context?, intent: Intent?) {
            intent ?: return
            when (intent.action) {
                TorService.ACTION_STATUS -> {
                    val status = intent.getStringExtra(TorService.EXTRA_STATUS) ?: return
                    appendLog("status: $status")
                    _state.value = _state.value.copy(
                        daemon = when (status) {
                            TorService.STATUS_ON -> ModuleState.ACTIVE
                            TorService.STATUS_STARTING -> ModuleState.STARTING
                            TorService.STATUS_STOPPING -> ModuleState.STOPPING
                            else -> ModuleState.OFF
                        }
                    )
                    if (status == TorService.STATUS_ON) {
                        scope.launch { pollSocksPortOnce() }
                    }
                    if (status == TorService.STATUS_OFF) {
                        _state.value = _state.value.copy(socksPort = -1, bootstrapProgress = 0)
                    }
                }
                TorService.ACTION_ERROR -> {
                    val err = intent.getStringExtra(Intent.EXTRA_TEXT) ?: "unknown error"
                    appendLog("ERROR: $err")
                    _state.value = _state.value.copy(daemon = ModuleState.ERROR)
                }
            }
        }
    }

    private val bootstrapListener = RawEventListener { keyword, data ->
        if (keyword == TorControlCommands.EVENT_STATUS_CLIENT && data != null) {
            // STATUS_CLIENT BOOTSTRAP PROGRESS=45 ...
            if (data.contains("BOOTSTRAP")) {
                val m = Regex("PROGRESS=(\\d+)").find(data)
                m?.groupValues?.get(1)?.toIntOrNull()?.let { p ->
                    _state.value = _state.value.copy(bootstrapProgress = p)
                }
            }
            appendLog("tor: $data")
        }
    }

    fun start(cfg: TorConfig) {
        if (_state.value.daemon == ModuleState.STARTING || _state.value.daemon == ModuleState.ACTIVE) return
        config = cfg
        try {
            writeTorrc(cfg)
            registerReceivers()
            context.bindService(
                Intent(context, TorService::class.java), connection, Context.BIND_AUTO_CREATE
            )
            // TorService is not a foreground service; it must be started from a
            // foreground context (our VPN service) so plain startService is fine.
            val i = Intent(context, TorService::class.java).setAction(TorService.ACTION_START)
            context.startService(i)
            _state.value = _state.value.copy(daemon = ModuleState.STARTING)
        } catch (e: Exception) {
            appendLog("start failed: ${e.message}")
            _state.value = _state.value.copy(daemon = ModuleState.ERROR)
        }
    }

    fun stop() {
        stopTransports()
        runCatching { context.unbindService(connection) }
        context.stopService(Intent(context, TorService::class.java))
        _state.value = TorState(daemon = ModuleState.STOPPING, log = logBuf.toList())
    }

    fun newIdentity(): Boolean {
        val conn = torControlConnection() ?: return false
        return runCatching {
            conn.signal(TorControlCommands.SIGNAL_NEWNYM)
            appendLog("signal NEWNYM sent")
            true
        }.getOrDefault(false)
    }

    fun torControlConnection(): TorControlConnection? = torService?.torControlConnection

    fun isSocksReachable(): Boolean {
        val s = _state.value
        return s.daemon == ModuleState.ACTIVE && s.socksReady
    }

    /** Daemon alive (starting or active) — reuse on tunnel restart instead of killing it. */
    fun isAlive(): Boolean =
        _state.value.daemon == ModuleState.ACTIVE || _state.value.daemon == ModuleState.STARTING

    fun socksPort(): Int = _state.value.socksPort

    // --- internals ---

    private fun registerReceivers() {
        val lbm = LocalBroadcastManager.getInstance(context)
        val f = IntentFilter().apply {
            addAction(TorService.ACTION_STATUS)
            addAction(TorService.ACTION_ERROR)
        }
        lbm.registerReceiver(statusReceiver, f)
    }

    private fun unregisterReceivers() {
        runCatching { LocalBroadcastManager.getInstance(context).unregisterReceiver(statusReceiver) }
    }

    private suspend fun watchSocksPort() {
        while (scope.isActive && bound) {
            pollSocksPortOnce()
            if (_state.value.socksReady) {
                attachBootstrapListener()
                break
            }
            delay(500)
        }
    }

    private suspend fun pollSocksPortOnce() {
        val svc = torService ?: return
        repeat(20) {
            val p = runCatching { svc.socksPort }.getOrDefault(-1)
            if (p > 0) {
                if (_state.value.socksPort != p) appendLog("SOCKS port: $p")
                _state.value = _state.value.copy(socksPort = p)
                return
            }
            delay(300)
        }
    }

    private fun attachBootstrapListener() {
        val conn = torControlConnection() ?: return
        runCatching {
            conn.addRawEventListener(bootstrapListener)
            // Keep STATUS_CLIENT (TorService depends on it) and add NOTICE for logs.
            conn.setEvents(listOf(TorControlCommands.EVENT_STATUS_CLIENT, TorControlCommands.EVENT_NOTICE_MSG))
        }
    }

    /**
     * Build torrc. TorService itself sets SOCKSPort (9050/auto) in its
     * torrc-defaults, so we must not touch port options here.
     */
    private fun writeTorrc(cfg: TorConfig) {
        val lines = mutableListOf(
            "ClientOnly 1",
            "AvoidDiskWrites 1"
        )

        if (cfg.useBridges && cfg.bridges.any { it.enabled }) {
            lines += "UseBridges 1"
            val needed = mutableSetOf<String>()
            cfg.bridges.filter { it.enabled }.forEach { b ->
                val line = b.line.trim()
                if (line.isNotEmpty()) {
                    lines += "Bridge $line"
                    needed += line.split("\\s+".toRegex()).firstOrNull()?.lowercase() ?: "obfs4"
                }
            }
            startTransports(needed)
        } else {
            stopTransports()
        }

        // Allow-listed extra options from advanced users.
        cfg.extraTorrc.forEach { raw ->
            val l = raw.trim()
            if (l.isEmpty() || l.startsWith("#")) return@forEach
            val key = l.split("\\s+".toRegex(), limit = 2)[0]
            if (key in ALLOWED_EXTRA_KEYS) lines += l
        }

        val torrc = TorService.getTorrc(context)
        torrc.parentFile?.mkdirs()
        torrc.writeText(lines.joinToString("\n", postfix = "\n"))
    }

    /** Start needed pluggable transports via IPtProxy and add ClientTransportPlugin lines. */
    private fun startTransports(needed: Set<String>) {
        val stateDir = File(context.cacheDir, "pt_state").apply { mkdirs() }
        val c = iptController ?: Controller(
            stateDir.absolutePath,
            true,   // enableLogging
            false,  // unsafeLogging
            "INFO",
            object : OnTransportEvents {
                override fun connected(name: String?) { appendLog("PT $name connected") }
                override fun error(name: String?, error: java.lang.Exception?) {
                    appendLog("PT $name error: ${error?.message}")
                }
                override fun stopped(name: String?, error: java.lang.Exception?) {
                    appendLog("PT $name stopped${error?.let { ": ${it.message}" } ?: ""}")
                }
            }
        ).also { iptController = it }
        IPtProxy.IPtProxy.touch()
        val ports = StringBuilder()
        needed.forEach { transport ->
            if (transport in SUPPORTED_TRANSPORTS) {
                runCatching { c.start(transport, "") }
                    .onFailure { appendLog("PT $transport failed to start: ${it.message}") }
                    .onSuccess {
                        val port = c.port(transport)
                        if (port > 0) ports.append("\nClientTransportPlugin $transport socks5 127.0.0.1:$port")
                    }
            }
        }
        if (ports.isNotEmpty()) {
            val torrc = TorService.getTorrc(context)
            torrc.appendText(ports.toString() + "\n")
        }
    }

    private fun stopTransports() {
        iptController?.let { c ->
            SUPPORTED_TRANSPORTS.forEach { t -> runCatching { c.stop(t) } }
        }
    }

    private fun appendLog(s: String) {
        synchronized(logBuf) {
            logBuf.addLast("${clock()} $s")
            while (logBuf.size > MAX_LOG) logBuf.removeFirst()
        }
        _state.value = _state.value.copy(log = logBuf.toList())
    }

    companion object {
        const val MAX_LOG = 400
        val SUPPORTED_TRANSPORTS =
            setOf("obfs2", "obfs3", "obfs4", "scramblesuit", "meek_lite", "snowflake", "webtunnel", "dnstt")
        val ALLOWED_EXTRA_KEYS = setOf(
            "ExitNodes", "EntryNodes", "ExcludeNodes", "StrictNodes", "NumEntryGuards",
            "MaxCircuitDirtiness", "CircuitStreamTimeout", "ConnectionPadding",
            "ReducedConnectionPadding", "ReducedCircuitPadding", "UseIPv4", "UseIPv6"
        )
    }
}
