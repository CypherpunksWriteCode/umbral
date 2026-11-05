package org.umbral.core.net.socks

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.umbral.core.model.RouteAction
import org.umbral.core.model.RouteDecision
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Local SOCKS5 server that hev-socks5-tunnel uses as its single upstream.
 * Every tunnelled TCP connection lands here. We then re-originate it:
 *
 *   DIRECT -> plain socket to the destination
 *   TOR    -> Socks5Client to 127.0.0.1:<torSocksPort> (remote DNS)
 *   PROXY  -> Socks5Client to the user-configured proxy (remote DNS)
 *   BLOCK  -> connection refused immediately
 *
 * The routing decision comes from [router] which in production combines the
 * RoutingPolicy with live Tor availability. If the chosen upstream is down,
 * the connection is refused — there is NEVER a silent fallback to DIRECT.
 */
class SocksRelayServer(
    private val port: Int,
    private val router: (targetHost: String, targetPort: Int) -> RouteDecision,
    /** Resolve+connect with upstream selection; returns an established socket or throws. */
    private val dialer: (targetHost: String, targetPort: Int, action: RouteAction) -> Socket,
    private val onEvent: (RelayEvent) -> Unit = {},
    /**
     * Optional local access control: return false to reject an accepted
     * client socket. On Android, loopback is shared by all apps, so the
     * service installs a filter that only accepts connections owned by our
     * own UID (hev-socks5-tunnel runs in-process), blocking other apps from
     * pumping traffic through this relay.
     */
    private val acceptFilter: (Socket) -> Boolean = { true }
) {
    sealed class RelayEvent {
        data class Connected(
            val host: String, val port: Int, val action: RouteAction,
            val latencyMs: Long, val detail: String
        ) : RelayEvent()

        data class Refused(
            val host: String, val port: Int, val action: RouteAction, val reason: String
        ) : RelayEvent()

        data class Closed(val host: String, val port: Int, val rxBytes: Long, val txBytes: Long) : RelayEvent()
    }

    private var serverSocket: ServerSocket? = null
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val jobs = ConcurrentHashMap<Int, Job>()
    private val nextId = AtomicLong(0)
    @Volatile private var running = false

    fun start() {
        check(!running) { "already running" }
        val ss = ServerSocket()
        ss.reuseAddress = true
        // Loopback only: this endpoint must never be reachable from the network.
        ss.bind(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 128)
        serverSocket = ss
        running = true
        scope.launch {
            while (running) {
                val client = try {
                    ss.accept()
                } catch (e: Exception) {
                    if (running) onEvent(RelayEvent.Refused("<accept>", 0, RouteAction.DIRECT, e.message ?: "accept error"))
                    break
                }
                val id = nextId.incrementAndGet().toInt()
                jobs[id] = scope.launch {
                    try {
                        if (!runCatching { acceptFilter(client) }.getOrDefault(false)) {
                            close(client)
                        } else {
                            serve(client)
                        }
                    } finally {
                        jobs.remove(id)
                    }
                }
            }
        }
    }

    fun stop() {
        running = false
        runCatching { serverSocket?.close() }
        jobs.values.forEach { it.cancel() }
        jobs.clear()
    }

    val isRunning: Boolean get() = running

    private fun serve(client: Socket) {
        client.tcpNoDelay = true
        try {
            val input = client.getInputStream()
            val output = client.getOutputStream()

            // --- greeting: version, nmethods, methods...
            val v = readByte(input)
            if (v != 5) { close(client); return }
            val n = readByte(input)
            if (n < 1) { close(client); return }
            val methods = ByteArray(n)
            readFully(input, methods)
            if (methods.none { it.toInt() == 0x00 }) {
                output.write(byteArrayOf(5, 0xFF.toByte())); output.flush(); close(client); return
            }
            output.write(byteArrayOf(5, 0x00)); output.flush()

            // --- request
            if (readByte(input) != 5) { close(client); return }
            val cmd = readByte(input)
            if (cmd != 0x01) { // only CONNECT
                writeReply(output, 0x07); close(client); return
            }
            readByte(input) // RSV
            val atyp = readByte(input)
            val targetHost: String = when (atyp) {
                0x01 -> {
                    val b = ByteArray(4); readFully(input, b)
                    b.joinToString(separator = ".") { (it.toInt() and 0xff).toString() }
                }
                0x03 -> {
                    val len = readByte(input)
                    val b = ByteArray(len); readFully(input, b)
                    String(b, Charsets.UTF_8)
                }
                0x04 -> {
                    val b = ByteArray(16); readFully(input, b)
                    org.umbral.core.net.pkt.IpCodec.ip6Text(b)
                }
                else -> { writeReply(output, 0x08); close(client); return }
            }
            val pHi = readByte(input); val pLo = readByte(input)
            val targetPort = ((pHi and 0xff) shl 8) or (pLo and 0xff)

            val decision = router(targetHost, targetPort)
            if (decision.action == RouteAction.BLOCK) {
                writeReply(output, 0x02) // connection not allowed
                onEvent(RelayEvent.Refused(targetHost, targetPort, RouteAction.BLOCK, decision.reason))
                close(client)
                return
            }

            val upstream: Socket = try {
                dialer(targetHost, targetPort, decision.action)
            } catch (e: Exception) {
                writeReply(output, 0x05) // connection refused
                onEvent(
                    RelayEvent.Refused(
                        targetHost, targetPort, decision.action,
                        "upstream connect failed: ${e.message}"
                    )
                )
                close(client)
                return
            }

            writeReply(output, 0x00)
            onEvent(RelayEvent.Connected(targetHost, targetPort, decision.action, 0, decision.reason))
            pump(client, upstream, targetHost, targetPort)
        } catch (e: Exception) {
            onEvent(RelayEvent.Refused("<error>", 0, RouteAction.DIRECT, e.message ?: "serve error"))
        } finally {
            close(client)
        }
    }

    private fun pump(client: Socket, upstream: Socket, host: String, port: Int) {
        var rx = 0L; var tx = 0L
        val t1 = scope.launch {
            val ci = client.getInputStream(); val uo = upstream.getOutputStream()
            val buf = ByteArray(64 * 1024)
            try {
                while (true) {
                    val n = ci.read(buf)
                    if (n < 0) break
                    if (n > 0) { uo.write(buf, 0, n); uo.flush(); tx += n }
                }
            } catch (_: Exception) {
            } finally {
                runCatching { upstream.shutdownOutput() }
            }
        }
        val t2 = scope.launch {
            val ui = upstream.getInputStream(); val co = client.getOutputStream()
            val buf = ByteArray(64 * 1024)
            try {
                while (true) {
                    val n = ui.read(buf)
                    if (n < 0) break
                    if (n > 0) { co.write(buf, 0, n); co.flush(); rx += n }
                }
            } catch (_: Exception) {
            } finally {
                runCatching { client.shutdownOutput() }
            }
        }
        runBlocking {
            t1.join(); t2.join()
        }
        onEvent(RelayEvent.Closed(host, port, rx, tx))
        close(upstream)
    }

    private fun writeReply(output: OutputStream, code: Int) {
        // BND.ADDR 0.0.0.0, BND.PORT 0
        output.write(byteArrayOf(5, code.toByte(), 0, 0x01, 0, 0, 0, 0, 0, 0))
        output.flush()
    }

    private fun readByte(input: InputStream): Int {
        val v = input.read()
        if (v < 0) throw java.io.IOException("EOF")
        return v
    }

    private fun readFully(input: InputStream, b: ByteArray) {
        var off = 0
        while (off < b.size) {
            val n = input.read(b, off, b.size - off)
            if (n < 0) throw java.io.IOException("EOF")
            off += n
        }
    }

    private fun close(s: Socket) {
        runCatching { s.close() }
    }
}
