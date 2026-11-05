package org.umbral.core.dns

import org.junit.Assert.assertEquals
import org.umbral.core.net.pkt.BytePacketWriter
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsCodecTest {

    @Test
    fun `query wire format matches rfc1035 layout`() {
        val q = DnsCodec.buildQuery(0x1234, "example.com", DnsCodec.TYPE_A)
        // header
        assertEquals(0x12, q[0].toInt() and 0xff)
        assertEquals(0x34, q[1].toInt() and 0xff)
        assertEquals(0x01, q[2].toInt() and 0xff) // QR=0 RD=1
        assertEquals(0x00, q[3].toInt() and 0xff)
        // counts
        val qdcount = ((q[4].toInt() and 0xff) shl 8) or (q[5].toInt() and 0xff)
        assertEquals(1, qdcount)
        // QNAME: 7example 3com 0
        val expectedName = byteArrayOf(7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0)
        val name = q.copyOfRange(12, 12 + expectedName.size)
        assertTrue(expectedName.contentEquals(name))
        // QTYPE A, QCLASS IN
        val tail = q.copyOfRange(q.size - 4, q.size)
        assertEquals(0, tail[0].toInt()); assertEquals(1, tail[1].toInt())
        assertEquals(0, tail[2].toInt()); assertEquals(1, tail[3].toInt())
    }

    @Test
    fun `parse response with compressed name pointer`() {
        // Handcrafted: question example.com A; answer example.com A 10.0.0.1 with name = C00C
        val w = BytePacketWriter(64)
        w.u16(0xdead)
        w.u16(0x8180)
        w.u16(1); w.u16(1); w.u16(0); w.u16(0)
        w.bytes(DnsCodec.encodeName("example.com"))
        w.u16(DnsCodec.TYPE_A); w.u16(DnsCodec.CLASS_IN)
        w.bytes(byteArrayOf(0xC0.toByte(), 0x0C))
        w.u16(DnsCodec.TYPE_A); w.u16(DnsCodec.CLASS_IN); w.u32(300)
        w.u16(4); w.bytes(byteArrayOf(10, 0, 0, 1))
        val msg = DnsCodec.parse(w.toByteArray())

        assertTrue(msg.response)
        assertEquals(0xdead, msg.id)
        assertEquals(1, msg.questions.size)
        assertEquals("example.com", msg.questions[0].name)
        assertEquals(1, msg.answers.size)
        assertEquals("example.com", msg.answers[0].name)
        assertEquals(300, msg.answers[0].ttl)
        assertEquals("10.0.0.1", msg.answers[0].asA)
        assertNull(msg.answers[0].asAAAA)
    }

    @Test
    fun `aaaa record renders rfc5952`() {
        // 2606:2800:220:1:248:1893:25c8:1946 → no zero run
        val r = DnsCodec.Record("x", DnsCodec.TYPE_AAAA, DnsCodec.CLASS_IN, 60, byteArrayOf(
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
            0x02, 0x48, 0x18, 0x93.toByte(), 0x25, 0xc8.toByte(), 0x19, 0x46
        ))
        assertEquals("2606:2800:220:1:248:1893:25c8:1946", r.asAAAA)
    }

    @Test
    fun `aaaa with zero run compresses`() {
        // 2001:db8::1
        val r = DnsCodec.Record("x", DnsCodec.TYPE_AAAA, DnsCodec.CLASS_IN, 60, byteArrayOf(
            0x20, 0x01, 0x0d, 0xb8.toByte(), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ))
        assertEquals("2001:db8::1", r.asAAAA)
    }

    @Test
    fun `all zeros renders as empty v6`() {
        val r = DnsCodec.Record("x", DnsCodec.TYPE_AAAA, DnsCodec.CLASS_IN, 60, ByteArray(16))
        assertEquals("::", r.asAAAA)
    }

    @Test(expected = DnsCodec.DnsException::class)
    fun `compression loop is detected`() {
        // pointer to itself
        val w = BytePacketWriter(32)
        w.u16(1); w.u16(0x8180); w.u16(1); w.u16(0); w.u16(0); w.u16(0)
        w.bytes(byteArrayOf(0xC0.toByte(), 0x0C)) // name pointing at itself
        w.u16(DnsCodec.TYPE_A); w.u16(DnsCodec.CLASS_IN)
        DnsCodec.parse(w.toByteArray())
    }

    @Test
    fun `engine serves cached answer without upstream`() {
        val engine = DnsEngine(cacheEnabled = true)
        engine.config = org.umbral.core.model.UmbralConfig()
        var upstreamCalls = 0
        engine.upstreamFactory = { _ ->
            object : DnsUpstream {
                override suspend fun resolve(query: ByteArray): ResolveResult {
                    upstreamCalls++
                    return ResolveResult(listOf("93.184.216.34"), 120, 0, null)
                }
                override fun describe() = "fake"
            }
        }
        val q = DnsCodec.buildQuery(7, "example.com", DnsCodec.TYPE_A)
        val r1 = kotlinx.coroutines.runBlocking { engine.handle(q) }
        val m1 = DnsCodec.parse(r1)
        assertEquals(7, m1.id)
        assertEquals("93.184.216.34", m1.answers.first().asA)
        val r2 = kotlinx.coroutines.runBlocking { engine.handle(q) }
        val m2 = DnsCodec.parse(r2)
        assertEquals("93.184.216.34", m2.answers.first().asA)
        assertEquals(1, upstreamCalls) // second answered from cache
    }

    @Test
    fun `servfail on upstream failure`() {
        val engine = DnsEngine(cacheEnabled = true)
        engine.upstreamFactory = { _ ->
            object : DnsUpstream {
                override suspend fun resolve(query: ByteArray): ResolveResult =
                    throw ResolveException("boom")
                override fun describe() = "broken"
            }
        }
        val q = DnsCodec.buildQuery(9, "example.com", DnsCodec.TYPE_A)
        val r = kotlinx.coroutines.runBlocking { engine.handle(q) }
        assertEquals(DnsCodec.RCODE_SERVFAIL, DnsCodec.parse(r).rcode)
    }

    @Test
    fun `malformed query gets formerr with same id`() {
        val engine = DnsEngine()
        val r = kotlinx.coroutines.runBlocking { engine.handle(byteArrayOf(0x11, 0x22, 0x00)) }
        val m = DnsCodec.parse(r)
        assertEquals(0x1122, m.id)
        assertEquals(DnsCodec.RCODE_FORMAT, m.rcode)
    }
}
