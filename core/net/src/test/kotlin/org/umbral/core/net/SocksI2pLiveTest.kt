package org.umbral.core.net

import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.umbral.core.net.socks.Socks5Client
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Live test (opt-in via UMBRAL_I2PD_LIVE=1 + i2pd on PATH): boots the real
 * daemon with the same option set Umbral generates, waits for tunnels, then
 * fetches a well-known eepsite through OUR SOCKS5 client implementation.
 * Not part of the default CI run (needs network + a few minutes).
 */
class SocksI2pLiveTest {

    @Test
    fun `our socks client fetches an eepsite via real i2pd`() {
        assumeTrue(System.getenv("UMBRAL_I2PD_LIVE") == "1")
        val path = (System.getenv("PATH") ?: "").split(':')
        val bin = path.firstNotNullOfOrNull { d ->
            if (d.isBlank()) null else File(d, "i2pd").takeIf { it.canExecute() }?.absolutePath
        } ?: error("i2pd not found")
        val dir = kotlin.io.path.createTempDirectory("umbral-i2p-live").toFile()
        val port = 24447 + (0..2000).random()
        val conf = File(dir, "i2pd.conf")
        conf.writeText(
            org.umbral.core.i2p.I2pdConfigBuilder.build(
                org.umbral.core.model.I2pConfig(socksPort = port, httpProxyPort = port + 1, webconsolePort = port + 2),
                dir.absolutePath
            )
        )
        val proc = ProcessBuilder(bin, "--conf=${conf.absolutePath}", "--datadir=${dir.absolutePath}", "--service")
            .redirectErrorStream(true).start()
        try {
            val socksReady = waitPort(port, 60_000)
            assertTrue("i2pd SOCKS did not open", socksReady)
            // First lookup on a fresh router needs the addressbook subscription
            // to sync + client tunnels to build; can take several minutes.
            var last: Exception? = null
            var ok = false
            val deadline = System.currentTimeMillis() + 420_000
            while (System.currentTimeMillis() < deadline && !ok) {
                try {
                    val s = Socks5Client.connect(
                        InetSocketAddress(InetAddress.getLoopbackAddress(), port),
                        "zzz.i2p", 80, readTimeoutMs = 150_000
                    )
                    s.use { sock ->
                        sock.getOutputStream().apply {
                            write("GET / HTTP/1.0\r\nHost: zzz.i2p\r\nUser-Agent: umbral-sandbox\r\nConnection: close\r\n\r\n".toByteArray()); flush()
                        }
                        val buf = ByteArray(256)
                        val n = sock.getInputStream().read(buf)
                        assertTrue("empty response", n > 0)
                        val head = String(buf, 0, n)
                        ok = head.startsWith("HTTP/1.0 200") || head.startsWith("HTTP/1.1 200")
                        if (!ok) throw java.io.IOException("not 200: ${head.lineSequence().first()}")
                    }
                } catch (e: Exception) {
                    last = e
                    Thread.sleep(15_000)
                }
            }
            assertTrue("eepsite fetch via our SOCKS client failed: $last", ok)
        } finally {
            proc.destroy()
            Thread.sleep(200)
            proc.destroyForcibly()
            dir.deleteRecursively()
        }
    }

    private fun waitPort(port: Int, timeoutMs: Long): Boolean {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val ok = runCatching {
                java.net.Socket("127.0.0.1", port).use { s ->
                    s.soTimeout = 1500
                    s.getOutputStream().write(byteArrayOf(5, 1, 0)); s.getOutputStream().flush()
                    s.getInputStream().read() == 5
                }
            }.getOrDefault(false)
            if (ok) return true
            Thread.sleep(1000)
        }
        return false
    }
}
