package org.umbral.core.i2p

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.umbral.core.model.I2pConfig
import org.junit.Test
import java.io.File

class I2pdConfigBuilderTest {

    @Test
    fun `defaults are local-only and quiet`() {
        val conf = I2pdConfigBuilder.build(I2pConfig(), "/data/i2p")
        assertTrue(conf.contains("socksproxy.address = 127.0.0.1"))
        assertTrue(conf.contains("socksproxy.port = 4447"))
        assertTrue(conf.contains("httpproxy.port = 4448"))
        assertTrue(conf.contains("http.address = 127.0.0.1"))
        assertTrue(conf.contains("notransit = true"))
        assertTrue(conf.contains("sam.enabled = false"))
        assertTrue(conf.contains("i2cp.enabled = false"))
        assertTrue(conf.contains("ssu2.enabled = true"))
        assertTrue(conf.contains("ntcp2.enabled = true"))
        // no stray plaintext listeners
        assertTrue(!conf.contains("0.0.0.0"))
    }

    @Test
    fun `custom ports land in config`() {
        val conf = I2pdConfigBuilder.build(I2pConfig(socksPort = 14447, httpProxyPort = 14448, webconsolePort = 17070), "/d")
        assertTrue(conf.contains("socksproxy.port = 14447"))
        assertTrue(conf.contains("httpproxy.port = 14448"))
        assertTrue(conf.contains("http.port = 17070"))
    }

    @Test
    fun `transit opt-in uses share`() {
        val conf = I2pdConfigBuilder.build(I2pConfig(transitEnabled = true, sharePercent = 40), "/d")
        assertTrue(conf.contains("notransit = false"))
        assertTrue(conf.contains("share = 40"))
    }

    @Test
    fun `extra options allow-list enforced`() {
        val ok = I2pdConfigBuilder.build(
            I2pConfig(extraOptions = listOf("bandwidth = P", "# comment", "netid = 2")), "/d"
        )
        assertTrue(ok.contains("bandwidth = P"))
        assertTrue(ok.contains("netid = 2"))
        try {
            I2pdConfigBuilder.build(I2pConfig(extraOptions = listOf("log = stdout")), "/d")
            fail("dangerous option must be rejected")
        } catch (e: I2pdConfigBuilder.BadOptionException) {
            assertEquals("option not allowed: log", e.message)
        }
    }

    private fun findI2pd(): String? {
        val pathDirs = (System.getenv("PATH") ?: "").split(':')
        for (dir in pathDirs) {
            if (dir.isBlank()) continue
            val f = File(dir, "i2pd")
            if (f.canExecute()) return f.absolutePath
        }
        return null
    }

    /**
     * Sandbox integration: run the REAL i2pd daemon (nixpkgs, v2.61+) with the
     * generated config and verify the local proxies come up. Skipped silently
     * when i2pd is not on PATH; force with UMBRAL_I2PD_TEST=1.
     */
    @Test
    fun `generated config boots a real i2pd`() {
        val i2pd = findI2pd() ?: run {
            if (System.getenv("UMBRAL_I2PD_TEST") == null) return
            error("UMBRAL_I2PD_TEST set but i2pd not found")
        }
        val dir = kotlin.io.path.createTempDirectory("umbral-i2p").toFile()
        val socks = 24447 + (0..2000).random()
        val http = socks + 1
        val web = socks + 2
        val conf = File(dir, "i2pd.conf").apply {
            writeText(I2pdConfigBuilder.build(I2pConfig(socksPort = socks, httpProxyPort = http, webconsolePort = web), dir.absolutePath))
        }
        val proc = ProcessBuilder(
            i2pd, "--conf=$conf", "--datadir=${dir.absolutePath}", "--service"
        )
            .redirectErrorStream(true)
            .start()
        try {
            val log = StringBuilder()
            val reader = Thread {
                proc.inputStream.bufferedReader().forEachLine { log.appendLine(it) }
            }.apply { isDaemon = true; start() }
            var socksUp = false
            var webUp = false
            val deadline = System.currentTimeMillis() + 90_000
            while (System.currentTimeMillis() < deadline && !(socksUp && webUp)) {
                Thread.sleep(500)
                if (!socksUp) socksUp = probeTcp(socks, "\u0005\u0001\u0000") // SOCKS5 greeting
                if (!webUp) webUp = probeHttp(web)
                if (!proc.isAlive && !socksUp) {
                    // daemon died early — dump log
                    Thread.sleep(200)
                    fail("i2pd exited early:\n${log}")
                }
            }
            assertTrue("i2pd SOCKS proxy did not come up (log follows):\n$log", socksUp)
            assertTrue("i2pd webconsole did not come up (log follows):\n$log", webUp)
        } finally {
            proc.destroy()
            Thread.sleep(300)
            proc.destroyForcibly()
            dir.deleteRecursively()
        }
    }

    private fun probeTcp(port: Int, payload: String): Boolean = runCatching {
        java.net.Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 2000
            s.getOutputStream().apply { write(payload.toByteArray()); flush() }
            val r = s.getInputStream().read()
            r >= 0
        }
    }.getOrDefault(false)

    private fun probeHttp(port: Int): Boolean = runCatching {
        java.net.Socket("127.0.0.1", port).use { s ->
            s.soTimeout = 2000
            s.getOutputStream().apply {
                write("GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n".toByteArray()); flush()
            }
            val buf = ByteArray(64)
            val n = s.getInputStream().read(buf)
            n > 0 && String(buf, 0, n).startsWith("HTTP/")
        }
    }.getOrDefault(false)
}
