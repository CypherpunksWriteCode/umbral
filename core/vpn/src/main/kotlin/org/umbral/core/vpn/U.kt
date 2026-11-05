package org.umbral.core.vpn

import android.content.Context
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.preferencesDataStoreFile
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import org.umbral.core.config.ConfigRepository
import org.umbral.core.dns.DnsEngine
import org.umbral.core.model.ConnectionEvent
import org.umbral.core.net.socks.SocksRelayServer
import java.util.concurrent.ConcurrentLinkedDeque


/**
 * Process-wide kernel: config repository + in-memory diagnostics hub.
 * No DI framework on purpose — fewer dependencies, less attack surface; the
 * object graph is tiny and fully explicit.
 */
class U private constructor(context: Context) {

    val configRepo: ConfigRepository
    val diagnostics = Diagnostics()

    /** Live TorController while the tunnel runs; set by PrivacyVpnService. */
    @Volatile var tor: org.umbral.core.tor.TorController? = null

    init {
        val appCtx = context.applicationContext
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val store: androidx.datastore.core.DataStore<Preferences> =
            PreferenceDataStoreFactory.create(scope = scope) {
                appCtx.preferencesDataStoreFile("umbral_config")
            }
        configRepo = ConfigRepository(store)
    }

    /** Ring-buffer diagnostics. Kept in memory only; never written to disk. */
    class Diagnostics {
        private val events = ConcurrentLinkedDeque<ConnectionEvent>()
        private val dnsLog = ConcurrentLinkedDeque<DnsEngine.QueryLog>()
        private val torLog = ConcurrentLinkedDeque<String>()

        private val _eventsFlow = MutableSharedFlow<ConnectionEvent>(extraBufferCapacity = 256)
        val eventsFlow: SharedFlow<ConnectionEvent> = _eventsFlow.asSharedFlow()

        private val _vpnState = MutableStateFlow(false)
        val vpnState: StateFlow<Boolean> = _vpnState.asStateFlow()

        private val _vpnError = MutableStateFlow<String?>(null)
        val vpnError: StateFlow<String?> = _vpnError.asStateFlow()

        @Volatile var torDaemon: String = "OFF"
            private set
        @Volatile var torBootstrap: Int = 0
            private set
        @Volatile var torSocksPort: Int = -1
            private set

        fun onConnection(e: ConnectionEvent) {
            events.addFirst(e)
            while (events.size > 500) events.removeLast()
            _eventsFlow.tryEmit(e)
        }

        fun onDnsQuery(l: DnsEngine.QueryLog) {
            dnsLog.addFirst(l)
            while (dnsLog.size > 500) dnsLog.removeLast()
        }

        fun onRelayEvent(e: SocksRelayServer.RelayEvent) {
            when (e) {
                is SocksRelayServer.RelayEvent.Connected -> onConnection(
                    ConnectionEvent(
                        System.currentTimeMillis(), -1, "TCP", "tun", "${e.host}:${e.port}",
                        e.action, false, e.detail
                    )
                )
                is SocksRelayServer.RelayEvent.Refused -> onConnection(
                    ConnectionEvent(
                        System.currentTimeMillis(), -1, "TCP", "tun", "${e.host}:${e.port}",
                        e.action, true, e.reason
                    )
                )
                is SocksRelayServer.RelayEvent.Closed -> Unit
            }
        }

        fun onTorState(daemon: String, bootstrap: Int, socksPort: Int) {
            torDaemon = daemon
            torBootstrap = bootstrap
            torSocksPort = socksPort
            torLog.addFirst("$daemon boot=$bootstrap socks=$socksPort")
            while (torLog.size > 200) torLog.removeLast()
        }

        fun onVpnState(active: Boolean) { _vpnState.value = active }
        fun onVpnError(msg: String) { _vpnError.value = msg }

        fun recentConnections(): List<ConnectionEvent> = events.toList()
        fun recentDns(): List<DnsEngine.QueryLog> = dnsLog.toList()
        fun recentTorLog(): List<String> = torLog.toList()
        fun clear() { events.clear(); dnsLog.clear(); torLog.clear() }
    }

    companion object {
        @Volatile private var instance: U? = null

        fun mgr(context: Context): U =
            instance ?: synchronized(this) {
                instance ?: U(context.applicationContext).also { instance = it }
            }
    }
}
