package org.umbral.core.dns

import com.sun.net.httpserver.HttpServer
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.junit.AfterClass
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.umbral.core.net.socks.Socks5Client
import java.io.InputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/**
 * Verifies on the JVM that OkHttp + Proxy(SOCKS) sends the TARGET HOSTNAME to
 * the proxy (ATYP=0x03) rather than resolving it locally. If this test ever
 * fails, DoH-via-Tor would leak DNS and the DohResolver must be changed.
 */
class DohResolverSocksTest {

    companion object {
        private var server: HttpServer? = null
        private var proxy: ServerSocket? = null
        private var proxyThread: Thread? = null
        private val proxyPort: Int = freePort()
        private val sawDomain = AtomicReference<String?>(null)
        private val latch = CountDownLatch(1)

        private fun freePort(): Int = ServerSocket(0).use { it.localPort }

        @AfterClass
        @JvmStatic
        fun tearDown() {
            server?.stop(0)
            proxy?.close()
        }

        private fun setUpOnce() {
            if (server != null) return
            // 1. Local DoH endpoint answering with a crafted A record.
            val http = HttpServer.create(InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0)
            http.createContext("/dns-query") { exchange ->
                val body = exchange.requestBody.readBytes()
                // respond with the same DNS message marked as response
                val resp = if (body.size >= 4) {
                    val m = body.copyOf()
                    m[2] = (m[2].toInt() or 0x80).toByte()
                    m
                } else ByteArray(12)
                exchange.responseHeaders.add("Content-Type", "application/dns-message")
                exchange.sendResponseHeaders(200, resp.size.toLong())
                exchange.responseBody.use { it.write(resp) }
            }
            http.start()
            server = http

            // 2. Recording SOCKS5 proxy that forwards to the DoH server.
            val ss = ServerSocket(proxyPort, 8, InetAddress.getLoopbackAddress())
            proxy = ss
            proxyThread = Thread {
                while (!ss.isClosed) {
                    try {
                        val client = ss.accept()
                        Thread {
                            client.use { c ->
                                val i: InputStream = c.getInputStream()
                                val o = c.getOutputStream()
                                i.read(); val n = i.read(); readN(i, n)
                                o.write(byteArrayOf(5, 0)); o.flush()
                                i.read(); i.read(); i.read()
                                val atyp = i.read()
                                val host = when (atyp) {
                                    0x03 -> String(readN(i, i.read()), Charsets.UTF_8)
                                    0x01 -> readN(i, 4).joinToString(".") { (it.toInt() and 0xff).toString() }
                                    else -> "?"
                                }
                                val port = (i.read() shl 8) or i.read()
                                sawDomain.set("$host:$port")
                                latch.countDown()
                                // connect to the real DoH server
                                val upstream = Socket(InetAddress.getLoopbackAddress(), http.address.port)
                                o.write(byteArrayOf(5, 0, 0, 0x01, 0, 0, 0, 0, 0, 0)); o.flush()
                                // pump both ways
                                Thread { try { i.copyTo(upstream.getOutputStream()) } catch (_: Exception) {} }.start()
                                try { upstream.getInputStream().copyTo(o) } catch (_: Exception) {}
                            }
                        }.apply { isDaemon = true }.start()
                    } catch (_: Exception) {
                    }
                }
            }.apply { isDaemon = true; start() }
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

    @Test
    fun `okhttp socks proxy resolves remotely`() {
        setUpOnce()
        val resolver = DohResolver(
            baseUrl = "https://doh.invalid.example/dns-query",
            socksProxy = InetSocketAddress(InetAddress.getLoopbackAddress(), proxyPort)
        )
        val query = DnsCodec.buildQuery(1, "example.com", DnsCodec.TYPE_A)
        try {
            kotlinx.coroutines.runBlocking { resolver.resolve(query) }
        } catch (_: Exception) {
            // TLS will fail (self-signed-free fake server) — that is fine;
            // we only care about what the SOCKS proxy observed.
        }
        assertTrue("SOCKS proxy saw no CONNECT", latch.await(5, TimeUnit.SECONDS))
        assertEquals("doh.invalid.example:443", sawDomain.get())
    }

    @Test
    fun `doh url must be https`() {
        var threw = false
        try {
            DohResolver(baseUrl = "http://plain.example/dns-query")
        } catch (e: IllegalArgumentException) {
            threw = true
        }
        assertTrue(threw)
    }
}
