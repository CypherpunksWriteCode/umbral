package org.umbral.core.net

import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okhttp3.tls.HandshakeCertificates
import okhttp3.tls.HeldCertificate
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.umbral.core.model.RouteAction
import org.umbral.core.model.RouteDecision
import org.umbral.core.net.socks.SocksRelayServer
import org.umbral.core.net.tls.TlsClientHello
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Verifies on the JVM that ClientHello fragmentation at the relay:
 *  1) does NOT break a real TLS handshake (bytes unchanged), and
 *  2) still lets us observe the SNI.
 * Real sockets, real JSSE TLS server (MockWebServer with a generated cert).
 */
class TlsFragmentationRelayTest {

    private lateinit var server: MockWebServer
    private lateinit var cert: HeldCertificate
    private val seenSni = CopyOnWriteArrayList<String>()
    private var relay: SocksRelayServer? = null

    @Before
    fun setUp() {
        cert = HeldCertificate.Builder()
            .addSubjectAlternativeName("example.test")
            .build()
        val serverHandshake = HandshakeCertificates.Builder()
            .heldCertificate(cert)
            .build()
        server = MockWebServer()
        server.useHttps(serverHandshake.sslSocketFactory(), false)
        server.start(InetAddress.getLoopbackAddress(), 0)
    }

    @After
    fun tearDown() {
        relay?.stop()
        server.shutdown()
    }

    @Test
    fun `https request succeeds through fragmenting relay and sni observed`() {
        server.enqueue(MockResponse().setBody("OK-FRAG"))
        val r = SocksRelayServer(
            port = freePort(),
            router = { _, _ -> RouteDecision(RouteAction.DIRECT, "test") },
            dialer = { _, port, _ -> Socket(InetAddress.getLoopbackAddress(), port) },
            onEvent = { ev ->
                if (ev is SocksRelayServer.RelayEvent.SniObserved) seenSni.add(ev.sni)
            },
            tlsFirstRecord = { _, _, record ->
                runCatching {
                    val p = TlsClientHello.parse(record)
                    TlsClientHello.fragmentPlan(p.recordLength, p.sniOffset, p.sniLength, 8)
                        .map { (off, len) -> record.copyOfRange(off, off + len) }
                }.getOrNull()
            }
        )
        relay = r
        r.start()

        val trust = HandshakeCertificates.Builder()
            .addTrustedCertificate(cert.certificate)
            .build()
        val http = OkHttpClient.Builder()
            .sslSocketFactory(trust.sslSocketFactory(), trust.trustManager)
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(InetAddress.getLoopbackAddress(), r.port())))
            .build()

        val url = server.url("/").newBuilder().host("example.test").build()
        val resp: Response = http.newCall(Request.Builder().url(url).build()).execute()
        assertEquals("OK-FRAG", resp.body!!.string())
        assertTrue("SNI not observed", seenSni.isNotEmpty())
        assertEquals("example.test", seenSni.first())
    }

    @Test
    fun `https also works with anti-dpi disabled (control)`() {
        val r = SocksRelayServer(
            port = freePort(),
            router = { _, _ -> RouteDecision(RouteAction.DIRECT, "test") },
            dialer = { _, port, _ -> Socket(InetAddress.getLoopbackAddress(), port) }
        )
        relay = r
        r.start()
        val trust = HandshakeCertificates.Builder()
            .addTrustedCertificate(cert.certificate)
            .build()
        server.enqueue(MockResponse().setBody("OK-PLAIN"))
        val http = OkHttpClient.Builder()
            .sslSocketFactory(trust.sslSocketFactory(), trust.trustManager)
            .proxy(Proxy(Proxy.Type.SOCKS, InetSocketAddress(InetAddress.getLoopbackAddress(), r.port())))
            .build()
        val url = server.url("/").newBuilder().host("example.test").build()
        val resp = http.newCall(Request.Builder().url(url).build()).execute()
        assertEquals("OK-PLAIN", resp.body!!.string())
    }

    private fun freePort(): Int = ServerSocket(0).use { it.localPort }
}
