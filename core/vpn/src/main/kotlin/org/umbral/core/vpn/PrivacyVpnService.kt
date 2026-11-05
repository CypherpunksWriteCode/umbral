package org.umbral.core.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.system.Os
import android.system.OsConstants
import androidx.core.app.NotificationCompat
import androidx.core.app.ServiceCompat
import hev.htproxy.TProxyService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.umbral.core.config.ConfigRepository
import org.umbral.core.dns.DnsCodec
import org.umbral.core.dns.DnsEngine
import org.umbral.core.model.ConnectionEvent
import org.umbral.core.model.ModuleState
import org.umbral.core.model.NetKind
import org.umbral.core.model.RouteAction
import org.umbral.core.model.RoutingPolicy
import org.umbral.core.model.UmbralConfig
import org.umbral.core.net.filter.FilterContext
import org.umbral.core.net.filter.PacketFilter
import org.umbral.core.net.filter.Verdict
import org.umbral.core.net.pkt.IpCodec
import org.umbral.core.net.socks.Socks5Client
import org.umbral.core.net.socks.SocksRelayServer
import org.umbral.core.net.uid.ProcNet
import org.umbral.core.tor.TorController
import java.io.File
import java.io.FileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The one real VPN session. Packet path:
 *
 *   TUN fd ──pump──► PacketFilter ──UDP:53──► DnsEngine (DoH/DoT) ─► TUN
 *                        │
 *                      pass ─► socketpair(SOCK_SEQPACKET) ─► hev tun2socks
 *                                                              │ SOCKS5 loopback
 *                        SocksRelayServer ◄────────────────────┘
 *                              │ RoutingPolicy (global route + strict fallback)
 *                        DIRECT (resolve via DoH first, then connect)
 *                        TOR    (Socks5Client → TorService SOCKS, remote DNS)
 *                        PROXY  (Socks5Client → user proxy, remote DNS)
 *                        BLOCK  (refuse; NEVER a silent fallback to direct)
 *
 * Per-app granularity in v1 (verified against hev-socks5-core source: outbound
 * sockets are not bound to original source ports, so per-connection UID
 * attribution inside the relay is impossible):
 *   - BLOCK  per app, at packet level (drop + RST)
 *   - BYPASS per app, via VpnService allow/disallow lists
 *   - DIRECT/TOR/PROXY is the GLOBAL tunnel route for all tunnelled apps
 */
class PrivacyVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val ioScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var tun: ParcelFileDescriptor? = null
    private var tunIn: FileInputStream? = null
    private var tunOut: FileOutputStream? = null
    private var hevOut: FileOutputStream? = null
    private var hevStarted = false
    private val pumpThreads = mutableListOf<Thread>()
    private val running = AtomicBoolean(false)

    private var relay: SocksRelayServer? = null
    private var dnsEngine: DnsEngine? = null
    private var torController: TorController? = null
    private var i2pdController: I2pdController? = null
    private var currentConfig: UmbralConfig = UmbralConfig()
    private var policy: RoutingPolicy? = null

    private val uidCache = ConcurrentHashMap<Int, Pair<Int, Long>>()

    companion object {
        const val VPN_ADDRESS_V4 = "10.111.111.114"
        const val VPN_ADDRESS_V6 = "fd00:6c69:6272:616c::1"
        const val MTU = 8500
        const val RELAY_PORT = 10808
        const val CHANNEL_ID = "umbral_vpn"
        const val NOTIFICATION_ID = 1
        const val ACTION_STOP = "org.umbral.core.vpn.STOP"
        const val ACTION_START = "org.umbral.core.vpn.START"

        @Volatile var isRunning: Boolean = false
            private set
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopTunnel()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForegroundWithType()
                serviceScope.launch { startTunnel() }
            }
        }
        return START_STICKY
    }

    override fun onRevoke() {
        // Always-on VPN revoked or another VPN took over.
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        serviceScope.cancel()
        ioScope.cancel()
        super.onDestroy()
    }

    // ------------------------------------------------------------------ start/stop

    private fun startTunnel() {
        if (!running.compareAndSet(false, true)) return
        val ctx = applicationContext
        currentConfig = U.mgr(ctx).configRepo.let { repo ->
            kotlinx.coroutines.runBlocking { repo.current() }
        }
        isRunning = true

        val engine = DnsEngine(cacheEnabled = currentConfig.dns.cache).apply {
            config = currentConfig
            onQueryCompleted = { log -> U.mgr(ctx).diagnostics.onDnsQuery(log) }
        }
        dnsEngine = engine

        val tor = if (currentConfig.tor.enabled) {
            TorController(applicationContext, ioScope).also { tc ->
                torController = tc
                U.mgr(applicationContext).tor = tc
                tc.start(currentConfig.tor)
                serviceScope.launch {
                    tc.state.collect { s ->
                        U.mgr(applicationContext).diagnostics.onTorState(s.daemon.name, s.bootstrapProgress, s.socksPort)
                    }
                }
            }
        } else null

        val i2pd = if (currentConfig.i2p.enabled) {
            I2pdController(applicationContext, ioScope).also { ic ->
                i2pdController = ic
                U.mgr(applicationContext).i2pd = ic
                ic.start(currentConfig.i2p)
                serviceScope.launch {
                    ic.state.collect { s ->
                        U.mgr(applicationContext).diagnostics.onI2pState(
                            s.router.name, s.socksReady, ic.socksPort()
                        )
                    }
                }
            }
        } else null

        val pol = RoutingPolicy(
            config = currentConfig,
            torAvailable = { tor?.isSocksReachable() == true },
            proxyAvailable = { true },
            i2pAvailable = { i2pd?.isSocksReady() == true }
        )
        policy = pol
        val filter = PacketFilter(pol) { currentConfig }

        val r = SocksRelayServer(
            port = RELAY_PORT,
            router = { _, _ -> pol.resolve(-1, netKind(), true) },
            dialer = { host, port, action -> dial(host, port, action) },
            onEvent = { ev -> U.mgr(ctx).diagnostics.onRelayEvent(ev) },
            acceptFilter = { sock -> isOwnProcessConnection(sock) }
        )
        relay = r
        r.start()

        val vpn = establishInterface(currentConfig)
        if (vpn == null) {
            stopTunnel()
            return
        }
        tun = vpn
        tunIn = FileInputStream(vpn.fileDescriptor)
        tunOut = FileOutputStream(vpn.fileDescriptor)

        val pair = createSocketPair()
        if (pair == null) {
            stopTunnel()
            return
        }
        val (mine, hev) = pair
        runCatching {
            Os.setsockoptInt(hev, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, 1 shl 21)
            Os.setsockoptInt(mine, OsConstants.SOL_SOCKET, OsConstants.SO_RCVBUF, 1 shl 21)
        }
        hevOut = FileOutputStream(mine)

        val conf = File(filesDir, "hev.yml")
        conf.writeText(
            """
            tunnel:
              name: tun0
              mtu: $MTU
              ipv4: $VPN_ADDRESS_V4
              ipv6: '$VPN_ADDRESS_V6'
            socks5:
              port: $RELAY_PORT
              address: 127.0.0.1
              udp: 'udp'
            misc:
              log-level: warn
              tcp-buffer-size: 65536
              connect-timeout: 10000
            """.trimIndent()
        )
        val hevFd = ParcelFileDescriptor.dup(hev).detachFd()
        val ok = runCatching { TProxyService.TProxyStartService(conf.absolutePath, hevFd) }
            .getOrDefault(false)
        if (!ok) {
            U.mgr(ctx).diagnostics.onVpnError("hev-socks5-tunnel failed to start")
            stopTunnel()
            return
        }
        hevStarted = true

        pumpThreads += spawnThread("umbral-tun-read") { pumpTunToHev(filter) }
        pumpThreads += spawnThread("umbral-hev-read") { pumpHevToTun(mine) }
        U.mgr(ctx).diagnostics.onVpnState(true)
    }

    private fun stopTunnel() {
        if (!running.compareAndSet(true, false)) return
        isRunning = false
        U.mgr(applicationContext).diagnostics.onVpnState(false)
        runCatching { TProxyService.TProxyStopService() }
        hevStarted = false
        pumpThreads.forEach { it.interrupt() }
        pumpThreads.clear()
        runCatching { relay?.stop() }
        relay = null
        U.mgr(applicationContext).tor = null
        torController?.stop()
        torController = null
        U.mgr(applicationContext).i2pd = null
        i2pdController?.stop()
        i2pdController = null
        dnsEngine = null
        runCatching { hevOut?.close() }
        hevOut = null
        runCatching { tunIn?.close() }
        tunIn = null
        runCatching { tunOut?.close() }
        tunOut = null
        runCatching { tun?.close() }
        tun = null
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
    }

    // ------------------------------------------------------------------ interface

    private fun establishInterface(cfg: UmbralConfig): ParcelFileDescriptor? {
        val b = Builder()
            .setSession("Umbral")
            .setMtu(MTU)
            .addAddress(VPN_ADDRESS_V4, 32)
            .addAddress(VPN_ADDRESS_V6, 128)
            .addDnsServer(VPN_ADDRESS_V4)
            .addDnsServer(VPN_ADDRESS_V6)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
        try {
            // Never tunnel ourselves: our sockets (DoH/DoT, relay, Tor upstream)
            // must leave via the real interface, outside the VPN.
            b.addDisallowedApplication(packageName)
            cfg.vpn.bypassUids.forEach { uid ->
                uidToPackages(uid).forEach { b.addDisallowedApplication(it) }
            }
            if (cfg.vpn.includeOnlyUids.isNotEmpty()) {
                cfg.vpn.includeOnlyUids.forEach { uid ->
                    uidToPackages(uid).forEach { b.addAllowedApplication(it) }
                }
            }
        } catch (e: android.content.pm.PackageManager.NameNotFoundException) {
            U.mgr(applicationContext).diagnostics.onVpnError("app package vanished: ${e.message}")
            return null
        }
        return b.establish()
    }

    private fun uidToPackages(uid: Int): List<String> =
        packageManager.getPackagesForUid(uid)?.toList() ?: emptyList()

    private fun createSocketPair(): Pair<FileDescriptor, FileDescriptor>? = try {
        val a = FileDescriptor()
        val b = FileDescriptor()
        Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_SEQPACKET, 0, a, b)
        a to b
    } catch (e: Exception) {
        U.mgr(applicationContext).diagnostics.onVpnError("socketpair failed: ${e.message}")
        null
    }

    // ------------------------------------------------------------------ pumps

    private fun pumpTunToHev(filter: PacketFilter) {
        val buf = ByteArray(MTU + 128)
        try {
            while (running.get()) {
                val n = tunIn!!.read(buf)
                if (n <= 0) break
                val pkt = buf.copyOf(n)
                val ip = try {
                    IpCodec.parse(pkt)
                } catch (e: Exception) {
                    continue
                }
                val uid = lookupUid(ip)
                val ctx = FilterContext(
                    vpnDnsIps = setOf(VPN_ADDRESS_V4, VPN_ADDRESS_V6),
                    localV4 = VPN_ADDRESS_V4,
                    localV6 = VPN_ADDRESS_V6,
                    uid = uid,
                    netKind = netKind()
                )
                when (val v = filter.decide(ip, ctx)) {
                    is Verdict.Pass -> writeHev(pkt)
                    is Verdict.Drop ->
                        if (ip.protocol == IpCodec.IPPROTO_TCP && ip.tcp != null) {
                            U.mgr(applicationContext).diagnostics.onConnection(
                                connEvent(uid, ip, blocked = true, detail = "dropped")
                            )
                        }
                    is Verdict.Reset -> {
                        IpCodec.buildRst(ip)?.let { writeTun(it) }
                        U.mgr(applicationContext).diagnostics.onConnection(
                            connEvent(uid, ip, blocked = true, detail = "blocked (reset)")
                        )
                    }
                    is Verdict.DnsLocal -> handleLocalDns(pkt, ip)
                }
            }
        } catch (e: InterruptedException) {
        } catch (e: Exception) {
            U.mgr(applicationContext).diagnostics.onVpnError("tun pump died: ${e.message}")
        }
    }

    private fun connEvent(uid: Int, ip: IpCodec.IpHeader, blocked: Boolean, detail: String) =
        ConnectionEvent(
            timestampMs = System.currentTimeMillis(),
            uid = uid,
            protocol = if (ip.protocol == IpCodec.IPPROTO_TCP) "TCP" else "UDP",
            source = "${ip.srcText}:${ip.tcp?.srcPort ?: ip.udp?.srcPort ?: 0}",
            destination = "${ip.dstText}:${ip.tcp?.dstPort ?: ip.udp?.dstPort ?: 0}",
            action = RouteAction.BLOCK,
            blocked = blocked,
            detail = detail
        )

    private fun pumpHevToTun(fd: FileDescriptor) {
        val input = FileInputStream(fd)
        val buf = ByteArray(MTU + 128)
        try {
            while (running.get()) {
                val n = input.read(buf)
                if (n <= 0) break
                writeTun(buf.copyOf(n))
            }
        } catch (e: InterruptedException) {
        } catch (e: Exception) {
            // closed during shutdown
        }
    }

    private val hevWriteLock = Any()
    private val tunWriteLock = Any()

    private fun writeHev(pkt: ByteArray) {
        synchronized(hevWriteLock) {
            val o = hevOut ?: return
            runCatching { o.write(pkt) }
        }
    }

    private fun writeTun(pkt: ByteArray) {
        synchronized(tunWriteLock) {
            val o = tunOut ?: return
            runCatching { o.write(pkt) }
        }
    }

    // ------------------------------------------------------------------ DNS

    private fun handleLocalDns(pkt: ByteArray, ip: IpCodec.IpHeader) {
        val udp = ip.udp ?: return
        val l4 = if (ip.version == 4) 20 else 40
        val dnsLen = udp.length - 8
        if (dnsLen <= 0 || l4 + 8 + dnsLen > pkt.size) return
        val query = pkt.copyOfRange(l4 + 8, l4 + 8 + dnsLen)
        val dest = InetSocketAddress(ip.dstText, udp.dstPort)
        val engine = dnsEngine ?: return
        serviceScope.launch {
            val answer = engine.handle(query, dest)
            val respPkt = try {
                if (ip.version == 4) IpCodec.buildUdp4(ip.dst, ip.src, udp.dstPort, udp.srcPort, answer)
                else IpCodec.buildUdp6(ip.dst, ip.src, udp.dstPort, udp.srcPort, answer)
            } catch (e: Exception) {
                null
            }
            if (respPkt != null) writeTun(respPkt)
        }
    }

    // ------------------------------------------------------------------ dialing

    private fun dial(host: String, port: Int, action: RouteAction): Socket {
        return when (action) {
        RouteAction.DIRECT -> {
            // Resolve through our encrypted upstream, then connect by address.
            // Using system DNS here would leak hostnames in plaintext.
            val addrs = resolveForDial(host)
            var last: Exception? = null
            for (a in addrs) {
                try {
                    val s = Socket()
                    s.tcpNoDelay = true
                    s.connect(InetSocketAddress(a, port), 10_000)
                    return s
                } catch (e: Exception) {
                    last = e
                }
            }
            throw last ?: IOException("no addresses for $host")
        }
        RouteAction.TOR -> Socks5Client.connect(
            InetSocketAddress(InetAddress.getLoopbackAddress(), torSocksPort()), host, port
        )
        RouteAction.I2P -> {
            val p = i2pdSocksPort()
            // .i2p hostnames are resolved by the router itself (remote via
            // SOCKS ATYP=domain). Clearnet hosts require an outproxy.
            Socks5Client.connect(
                InetSocketAddress(InetAddress.getLoopbackAddress(), p), host, port
            )
        }
        RouteAction.PROXY -> {
            val pc = currentConfig.proxy
            Socks5Client.connect(
                InetSocketAddress(pc.host, pc.port), host, port, pc.username, pc.password
            )
        }
        RouteAction.BLOCK -> throw IOException("blocked by policy")
        }
    }

    private fun torSocksPort(): Int =
        torController?.socksPort()?.takeIf { it > 0 } ?: DnsEngine.TOR_SOCKS_PORT

    private fun i2pdSocksPort(): Int =
        i2pdController?.socksPort()?.takeIf { it > 0 } ?: currentConfig.i2p.socksPort

    private fun resolveForDial(host: String): List<InetAddress> {
        if (isLiteralIp(host)) return listOf(InetAddress.getByName(host))
        val engine = dnsEngine ?: throw IOException("dns engine down")
        val query = DnsCodec.buildQuery(0, host, DnsCodec.TYPE_A)
        val response = kotlinx.coroutines.runBlocking { engine.handle(query) }
        val msg = try {
            DnsCodec.parse(response)
        } catch (e: Exception) {
            throw IOException("bad dns response for $host")
        }
        if (msg.rcode != DnsCodec.RCODE_NOERROR) throw IOException("dns rcode ${msg.rcode} for $host")
        val ips = msg.answers.mapNotNull { it.asA }.map { InetAddress.getByName(it) }
        if (ips.isEmpty()) throw IOException("no A record for $host")
        return ips
    }

    private fun isLiteralIp(host: String): Boolean {
        if (host.contains(':')) return true
        val parts = host.split('.')
        return parts.size == 4 && parts.all { it.isNotEmpty() && it.toIntOrNull() in 0..255 }
    }

    // ------------------------------------------------------------------ UID lookup

    private fun lookupUid(ip: IpCodec.IpHeader): Int {
        val port = portOf(ip)
        val now = SystemClock.elapsedRealtime()
        uidCache[port]?.let { (uid, ts) ->
            if (now - ts < 15_000) return uid
            uidCache.remove(port)
        }
        val uid = if (Build.VERSION.SDK_INT >= 29) lookupUidApi29(ip) else lookupUidProc(ip)
        if (uid >= 0) uidCache[port] = uid to now
        return uid
    }

    private fun lookupUidApi29(ip: IpCodec.IpHeader): Int {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return -1
        val proto = if (ip.protocol == IpCodec.IPPROTO_TCP) 6 else 17
        val local = InetSocketAddress(ip.srcText, portOf(ip))
        val remote = InetSocketAddress(ip.dstText, remotePortOf(ip))
        return runCatching { cm.getConnectionOwnerUid(proto, local, remote) }.getOrDefault(-1)
    }

    /**
     * Loopback access control for the relay: Android apps share 127.0.0.1, so
     * a malicious app could otherwise route its traffic through our relay.
     * Only connections owned by our own UID (hev runs in-process) are served.
     */
    private fun isOwnProcessConnection(sock: Socket): Boolean {
        if (Build.VERSION.SDK_INT < 29) return true // no API to check; documented limitation
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return true
        val remote = sock.remoteSocketAddress as? InetSocketAddress ?: return false
        val local = sock.localSocketAddress as? InetSocketAddress ?: return false
        val uid = runCatching {
            cm.getConnectionOwnerUid(6, local, remote)
        }.getOrDefault(-1)
        if (uid == -1) return true // cannot determine; keep compatibility
        return uid == android.os.Process.myUid()
    }

    private fun lookupUidProc(ip: IpCodec.IpHeader): Int {
        val file = when (ip.protocol) {
            IpCodec.IPPROTO_TCP -> if (ip.version == 4) "/proc/net/tcp" else "/proc/net/tcp6"
            else -> if (ip.version == 4) "/proc/net/udp" else "/proc/net/udp6"
        }
        return runCatching {
            ProcNet.parse(File(file).readText())
                .firstOrNull { it.localPort == portOf(ip) && it.remotePort == remotePortOf(ip) }
                ?.uid ?: -1
        }.getOrDefault(-1)
    }

    private fun portOf(ip: IpCodec.IpHeader) = ip.udp?.srcPort ?: ip.tcp?.srcPort ?: 0
    private fun remotePortOf(ip: IpCodec.IpHeader) = ip.udp?.dstPort ?: ip.tcp?.dstPort ?: 0

    private fun netKind(): NetKind {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return NetKind.OTHER
        val caps = cm.getNetworkCapabilities(cm.activeNetwork) ?: return NetKind.OTHER
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetKind.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetKind.MOBILE
            else -> NetKind.OTHER
        }
    }

    // ------------------------------------------------------------------ foreground plumbing

    private fun startForegroundWithType() {
        val notif = buildNotification()
        if (Build.VERSION.SDK_INT >= 34) {
            ServiceCompat.startForeground(this, NOTIFICATION_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notif)
        }
    }

    private fun buildNotification(): Notification {
        val open = PendingIntent.getActivity(
            this, 0,
            packageManager.getLaunchIntentForPackage(packageName)?.apply {
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
            },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stop = PendingIntent.getService(
            this, 1,
            Intent(this, PrivacyVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentTitle("Umbral active")
            .setContentText("Tunnel, firewall and encrypted DNS are running.")
            .setOngoing(true)
            .setContentIntent(open)
            .addAction(0, "Stop", stop)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    private fun spawnThread(name: String, body: () -> Unit): Thread =
        Thread(body, name).apply { isDaemon = true; start() }
}
