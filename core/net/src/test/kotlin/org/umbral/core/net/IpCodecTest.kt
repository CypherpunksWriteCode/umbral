package org.umbral.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.umbral.core.net.pkt.IpCodec

class IpCodecTest {

    private fun v4(vararg b: Int) = b.map { it.toByte() }.toByteArray()

    @Test
    fun `buildUdp4 packet parses back and checksums verify`() {
        val src = v4(10, 111, 111, 114)
        val dst = v4(10, 111, 111, 100)
        val payload = "hello-dns".toByteArray()
        val pkt = IpCodec.buildUdp4(src, dst, 40000, 53, payload)
        val parsed = IpCodec.parse(pkt)
        assertEquals(4, parsed.version)
        assertEquals(17, parsed.protocol)
        assertEquals("10.111.111.114", parsed.srcText)
        assertEquals("10.111.111.100", parsed.dstText)
        assertEquals(40000, parsed.udp?.srcPort)
        assertEquals(53, parsed.udp?.dstPort)
        // verify checksums recomputed over the packet are valid (result 0 means ok)
        val v4c = IpCodec.checksum(pkt, 0, 20)
        assertEquals(0, v4c)
        val l4Off = 20
        val l4Len = parsed.totalLength - l4Off
        val pseudo = 0
        var sum = pseudo
        // UDP checksum verification: recompute including pseudo-header
        sum = 0
        for (i in src.indices step 2)
            sum += ((src[i].toInt() and 0xff) shl 8) or (src[i + 1].toInt() and 0xff)
        for (i in dst.indices step 2)
            sum += ((dst[i].toInt() and 0xff) shl 8) or (dst[i + 1].toInt() and 0xff)
        sum += 17 + l4Len
        var i = l4Off
        val end = l4Off + l4Len
        while (i < end - 1) {
            sum += ((pkt[i].toInt() and 0xff) shl 8) or (pkt[i + 1].toInt() and 0xff); i += 2
        }
        if (i < end) sum += (pkt[i].toInt() and 0xff) shl 8
        assertEquals("UDP checksum must verify", 0, IpCodec.internetChecksum(sum))
    }

    @Test
    fun `buildUdp6 checksum is mandatory and verifies`() {
        val src = ByteArray(16) { (it + 1).toByte() }
        val dst = ByteArray(16) { (it + 17).toByte() }
        val pkt = IpCodec.buildUdp6(src, dst, 5353, 53, byteArrayOf(1, 2, 3))
        val parsed = IpCodec.parse(pkt)
        assertEquals(6, parsed.version)
        assertEquals(17, parsed.protocol)
        assertEquals(53, parsed.udp?.dstPort)
        val l4Off = 40
        val l4Len = parsed.totalLength - l4Off
        var sum = 0
        for (i in src.indices step 2)
            sum += ((src[i].toInt() and 0xff) shl 8) or (src[i + 1].toInt() and 0xff)
        for (i in dst.indices step 2)
            sum += ((dst[i].toInt() and 0xff) shl 8) or (dst[i + 1].toInt() and 0xff)
        sum += 17 + l4Len
        var i = l4Off
        val end = l4Off + l4Len
        while (i < end - 1) {
            sum += ((pkt[i].toInt() and 0xff) shl 8) or (pkt[i + 1].toInt() and 0xff); i += 2
        }
        if (i < end) sum += (pkt[i].toInt() and 0xff) shl 8
        assertEquals(0, IpCodec.internetChecksum(sum))
    }

    @Test
    fun `rst builder inverts addresses for a syn`() {
        // Build a minimal SYN IPv4 packet.
        val src = v4(10, 0, 0, 1)
        val dst = v4(93, 184, 216, 34)
        val w = org.umbral.core.net.pkt.BytePacketWriter(64)
        w.u8(0x45); w.u8(0)
        w.u16(40); w.u16(0); w.u16(0x4000)
        w.u8(64); w.u8(6); w.u16(0)
        w.bytes(src); w.bytes(dst)
        w.u16(12345); w.u16(443)
        w.u32(1000); w.u32(0)
        w.u8(0x50); w.u8(0x02) // SYN
        w.u16(8192); w.u16(0); w.u16(0); w.u16(0)
        val syn = w.toByteArray()
        // fix v4 checksum
        val c = IpCodec.checksum(syn, 0, 20)
        syn[10] = (c shr 8).toByte(); syn[11] = (c and 0xff).toByte()

        val parsed = IpCodec.parse(syn)
        assertTrue(parsed.tcp!!.isSyn)
        val rst = IpCodec.buildRst(parsed)!!
        val rp = IpCodec.parse(rst)
        assertEquals("93.184.216.34", rp.srcText)
        assertEquals("10.0.0.1", rp.dstText)
        assertEquals(443, rp.tcp!!.srcPort)
        assertEquals(12345, rp.tcp!!.dstPort)
        assertTrue(rp.tcp!!.isRst)
        // RST checksum verifies
        var sum = 0
        for (i in src.indices step 2) sum += ((rst[12 + i].toInt() and 0xff) shl 8) or (rst[13 + i].toInt() and 0xff)
        for (i in dst.indices step 2) sum += ((rst[16 + i].toInt() and 0xff) shl 8) or (rst[17 + i].toInt() and 0xff)
        sum += 6 + (rst.size - 20)
        var i = 20
        while (i < rst.size - 1) {
            sum += ((rst[i].toInt() and 0xff) shl 8) or (rst[i + 1].toInt() and 0xff); i += 2
        }
        assertEquals(0, IpCodec.internetChecksum(sum))
    }

    @Test(expected = IpCodec.PacketFormatException::class)
    fun `truncated packet rejected`() {
        IpCodec.parse(ByteArray(5))
    }

    @Test
    fun `ip6 text formatting`() {
        assertEquals("::1", IpCodec.ip6Text(ByteArray(16).also { it[15] = 1 }))
        assertEquals("2001:db8::1", IpCodec.ip6Text(ByteArray(16).also {
            it[0] = 0x20; it[1] = 0x01; it[2] = 0x0d; it[3] = 0xb8.toByte(); it[15] = 1
        }))
    }
}
