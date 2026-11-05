package org.umbral.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.umbral.core.model.RouteAction
import org.umbral.core.model.RouteDecision
import org.umbral.core.net.socks.Socks5Client
import org.umbral.core.net.socks.SocksRelayServer
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** Real-socket tests on loopback. No mocks: bytes on the wire. */
class SocksTest {

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }

    /** Simple line-echo TCP server. */
    private fun echoServer(): Pair<Int, Thread> {
        val ss = ServerSocket(0, 8, InetAddress.getLoopbackAddress())
        val t = Thread {
            while (!ss.isClosed) {
                try {
                    val c = ss.accept()
                    Thread {
                        c.use { s ->
                            val input = s.getInputStream()
                            val out = s.getOutputStream()
                            val buf = ByteArray(1024)
                            var n = input.read(buf)
                            if (n > 0) {
                                out.write(buf, 0, n)
                                out.flush()
                            }
                        }
                    }.start()
                } catch (_: Exception) {
                }
            }
        }.apply { isDaemon = true; start() }
        return ss.localPort to t
    }

    @Test
    fun `client sends domain atyp not resolved locally`() {
        // Fake SOCKS5 server records the request ATYP and then closes cleanly.
        val ss = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        val atyp = AtomicReference<Int>(-1)
        val host = AtomicReference<String?>(null)
        val portSeen = AtomicReference<Int>(-1)
        val done = CountDownLatch(1)
        Thread {
            ss.accept().use { c ->
                val i: InputStream = c.getInputStream()
                val o = c.getOutputStream()
                i.read(); val n = i.read(); readN(i, n)
                o.write(byteArrayOf(5, 0)); o.flush()
                i.read() // ver
                i.read() // cmd
                i.read() // rsv
                val a = i.read()
                atyp.set(a)
                when (a) {
                    0x01 -> readN(i, 4)
                    0x04 -> readN(i, 16)
                    0x03 -> {
                        val len = i.read()
                        val hb = readN(i, len)
                        host.set(String(hb, Charsets.UTF_8))
                    }
                }
                portSeen.set((i.read() shl 8) or i.read())
                o.write(byteArrayOf(5, 0, 0, 0x01, 0, 0, 0, 0, 0, 0)); o.flush()
                done.countDown()
            }
        }.apply { isDaemon = true; start() }

        val s = Socks5Client.connect(
            InetSocketAddress(InetAddress.getLoopbackAddress(), ss.localPort),
            "does-not-exist.example", 443
        )
        assertTrue(done.await(3, TimeUnit.SECONDS))
        assertEquals(0x03, atyp.get()) // DOMAINNAME: name went to the proxy
        assertEquals("does-not-exist.example", host.get())
        assertEquals(443, portSeen.get())
        s.close()
    }

    @Test
    fun `client rejects bad socks version`() {
        val ss = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
        Thread {
            ss.accept().use { c ->
                val i = c.getInputStream()
                i.read(); i.read(); readN(i, i.read())
                c.getOutputStream().write(byteArrayOf(4, 0)) // wrong version
            }
        }.apply { isDaemon = true; start() }
        var threw = false
        try {
            Socks5Client.connect(
                InetSocketAddress(InetAddress.getLoopbackAddress(), ss.localPort), "a.b", 80
            )
        } catch (e: Exception) {
            threw = true
        }
        assertTrue(threw)
    }

    @Test
    fun `relay end to end direct`() {
        val (echoPort, echoThread) = echoServer()
        val relayPort = freePort()
        val relay = SocksRelayServer(
            port = relayPort,
            router = { _, _ -> RouteDecision(RouteAction.DIRECT, "test") },
            dialer = { host, port, _ ->
                Socket(InetAddress.getLoopbackAddress(), port)
            }
        )
        relay.start()
        try {
            val s = Socks5Client.connect(
                InetSocketAddress(InetAddress.getLoopbackAddress(), relayPort),
                "localhost", echoPort
            )
            s.getOutputStream().write("ping!".toByteArray())
            s.getOutputStream().flush()
            val buf = ByteArray(16)
            val n = s.getInputStream().read(buf)
            assertEquals("ping!", String(buf, 0, n))
            s.close()
        } finally {
            relay.stop()
        }
    }

    @Test
    fun `relay refuses blocked target`() {
        val relayPort = freePort()
        val relay = SocksRelayServer(
            port = relayPort,
            router = { _, _ -> RouteDecision(RouteAction.BLOCK, "policy") },
            dialer = { _, _, _ -> throw java.io.IOException("unreachable") }
        )
        relay.start()
        try {
            val s = java.net.Socket(InetAddress.getLoopbackAddress(), relayPort)
            val i = s.getInputStream(); val o = s.getOutputStream()
            o.write(byteArrayOf(5, 1, 0)); o.flush()
            readN(i, 2) // 05 00
            o.write(byteArrayOf(5, 1, 0, 0x01, 127, 0, 0, 1, 0, 80)); o.flush()
            val ver = i.read(); val code = i.read()
            assertEquals(5, ver)
            assertEquals(0x02, code) // connection not allowed by ruleset
            s.close()
        } finally {
            relay.stop()
        }
    }

    @Test
    fun `relay refuses when upstream dial fails`() {
        val relayPort = freePort()
        val relay = SocksRelayServer(
            port = relayPort,
            router = { _, _ -> RouteDecision(RouteAction.TOR, "strict") },
            dialer = { _, _, _ -> throw java.io.IOException("tor is down") }
        )
        relay.start()
        try {
            val s = java.net.Socket(InetAddress.getLoopbackAddress(), relayPort)
            val i = s.getInputStream(); val o = s.getOutputStream()
            o.write(byteArrayOf(5, 1, 0)); o.flush()
            readN(i, 2)
            o.write(byteArrayOf(5, 1, 0, 0x01, 127, 0, 0, 1, 0x1F, 0x90.toByte())); o.flush()
            assertEquals(5, i.read())
            assertEquals(0x05, i.read()) // connection refused — NO silent fallback
            s.close()
        } finally {
            relay.stop()
        }
    }

    private fun readN(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var off = 0
        while (off < n) {
            val r = input.read(out, off, n - off)
            check(r >= 0) { "EOF" }
            off += r
        }
        return out
    }
}
