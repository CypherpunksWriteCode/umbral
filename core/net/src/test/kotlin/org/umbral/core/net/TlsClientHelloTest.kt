package org.umbral.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.umbral.core.net.tls.TlsClientHello

class TlsClientHelloTest {

    /** Handcrafted minimal ClientHello with a server_name extension. */
    private fun clientHello(sni: String): ByteArray {
        val name = sni.toByteArray(Charsets.US_ASCII)
        // server_name entry: type(1)=0x00 + len(2) + name
        val sniEntry = byteArrayOf(0x00) + u16(name.size) + name
        // extension data: list_len(2) + entry
        val extData = u16(sniEntry.size) + sniEntry
        val ext = u16(0x0000) + u16(extData.size) + extData

        val body = ByteArray(0)
            .plus(byteArrayOf(0x03, 0x03))                  // client_version TLS1.2
            .plus(ByteArray(32) { it.toByte() })            // random
            .plus(byteArrayOf(0x00))                        // session_id_len 0
            .plus(u16(2)).plus(byteArrayOf(0x2f.toByte(), 0x00)) // one cipher suite
            .plus(byteArrayOf(1, 0))                        // compression null
            .plus(u16(ext.size)).plus(ext)                  // extensions

        val handshake = byteArrayOf(0x01) + u24(body.size) + body
        val contentLen = handshake.size
        return byteArrayOf(0x16, 0x03, 0x01) + u16(contentLen) + handshake
    }

    private fun u16(v: Int) = byteArrayOf((v shr 8).toByte(), (v and 0xff).toByte())
    private fun u24(v: Int) = byteArrayOf((v shr 16).toByte(), ((v shr 8) and 0xff).toByte(), (v and 0xff).toByte())

    @Test
    fun `parses sni and location`() {
        val rec = clientHello("example.com")
        val p = TlsClientHello.parse(rec)
        assertEquals("example.com", p.sni)
        assertEquals(11, p.sniLength)
        assertEquals(rec.size, p.recordLength)
        // bytes at sniOffset must actually be the hostname
        assertEquals("example.com", String(rec, p.sniOffset, p.sniLength, Charsets.US_ASCII))
    }

    @Test
    fun `rejects non-handshake and non-clienthello`() {
        assertTrue(TlsClientHello.runCatching { parse(byteArrayOf(0x17, 0x03, 0x03, 0, 1, 0)) }.isFailure)
    }

    @Test
    fun `fragment plan covers all bytes exactly once and splits before sni`() {
        val rec = clientHello("example.com")
        val p = TlsClientHello.parse(rec)
        val plan = TlsClientHello.fragmentPlan(p.recordLength, p.sniOffset, p.sniLength, 8)
        // coverage: concatenation equals the record
        val rebuilt = plan.flatMap { (off, len) -> rec.copyOfRange(off, off + len).toList() }
        assertEquals(rec.toList(), rebuilt)
        // first cut happens before the SNI
        assertTrue(plan.first().second <= p.sniOffset)
        // and at least one further chunk starts at SNI
        assertTrue(plan.any { (off, _) -> off == p.sniOffset })
        // chunks after the cut respect chunk size
        plan.drop(1).forEach { (_, len) -> assertTrue(len <= 8) }
    }

    @Test
    fun `no sni still produces full-coverage plan`() {
        val plan = TlsClientHello.fragmentPlan(100, -1, 0, 16)
        assertEquals(plan.sumOf { it.second }, 100)
    }
}

class BridgeBatchTest {

    @Test
    fun `parses a pasted list with comments and junk`() {
        val text = """
            # from bridges.torproject.org
            obfs4 203.0.113.10:443 4352e58420e68f5e40bf7c74f8ccd2ca4ae7e79a cert=abc iat-mode=0
            webtunnel 203.0.113.11:8443 22b280b23e1107b62c8a2565ce262f9bb0ba3db6ec2d80023db0f6b707f1b1ce3 url=https://example.com/tunnel
            garbage line here
            obfs4 203.0.113.10:443 4352e58420e68f5e40bf7c74f8ccd2ca4ae7e79a cert=abc iat-mode=0
        """.trimIndent()
        val res = org.umbral.core.model.BridgeBatch.parse(text)
        assertEquals(2, res.bridges.size) // third is junk, fourth is a dup
        assertEquals(1, res.errors.size)
        assertTrue(res.errors[0].contains("unknown transport"))
    }

    @Test
    fun `empty and comments only`() {
        val res = org.umbral.core.model.BridgeBatch.parse("\n# nothing\n")
        assertTrue(res.bridges.isEmpty() && res.errors.isEmpty())
    }

    @Test
    fun `rejects missing fingerprint`() {
        val res = org.umbral.core.model.BridgeBatch.parse("obfs4 1.2.3.4:443")
        assertTrue(res.bridges.isEmpty())
        assertTrue(res.errors.first().contains("expected"))
    }
}
