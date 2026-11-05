package org.umbral.core.net

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.umbral.core.model.AppRule
import org.umbral.core.model.NetKind
import org.umbral.core.model.RouteAction
import org.umbral.core.model.RoutingPolicy
import org.umbral.core.model.UmbralConfig
import org.umbral.core.net.filter.FilterContext
import org.umbral.core.net.filter.PacketFilter
import org.umbral.core.net.filter.Verdict
import org.umbral.core.net.pkt.IpCodec
import org.umbral.core.net.uid.ProcNet

class PacketFilterTest {

    private fun tcpSynV4(src: String, dst: String, srcPort: Int, dstPort: Int): ByteArray {
        val s = src.split(".").map { it.toInt().toByte() }.toByteArray()
        val d = dst.split(".").map { it.toInt().toByte() }.toByteArray()
        val w = org.umbral.core.net.pkt.BytePacketWriter(64)
        w.u8(0x45); w.u8(0); w.u16(40); w.u16(0); w.u16(0x4000)
        w.u8(64); w.u8(6); w.u16(0)
        w.bytes(s); w.bytes(d)
        w.u16(srcPort); w.u16(dstPort)
        w.u32(1); w.u32(0)
        w.u8(0x50); w.u8(0x02); w.u16(8192); w.u16(0); w.u16(0); w.u16(0)
        val pkt = w.toByteArray()
        val c = IpCodec.checksum(pkt, 0, 20)
        pkt[10] = (c shr 8).toByte(); pkt[11] = (c and 0xff).toByte()
        return pkt
    }

    private fun udpV4(dstPort: Int): ByteArray {
        val s = byteArrayOf(10, 111, 111, 114)
        val d = byteArrayOf(10, 111, 111, 1)
        return IpCodec.buildUdp4(s, d, 44444, dstPort, byteArrayOf(0x00, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0)
        )
    }

    private fun ctx(uid: Int) = FilterContext(
        vpnDnsIps = setOf("10.111.111.114", "fd00:6c69:6272:616c::1"),
        localV4 = "10.111.111.114",
        localV6 = "fd00:6c69:6272:616c::1",
        uid = uid,
        netKind = NetKind.WIFI
    )

    @Test
    fun `udp53 is always intercepted locally`() {
        val f = PacketFilter(RoutingPolicy(UmbralConfig(), { true }, { true })) { UmbralConfig() }
        val v = f.decide(IpCodec.parse(udpV4(53)), ctx(1000))
        assertTrue(v is Verdict.DnsLocal)
    }

    @Test
    fun `non-dns udp dropped by default policy`() {
        val f = PacketFilter(RoutingPolicy(UmbralConfig(), { true }, { true })) { UmbralConfig() }
        val v = f.decide(IpCodec.parse(udpV4(443)), ctx(1000))
        assertTrue(v is Verdict.Drop)
    }

    @Test
    fun `non-dns udp passes when user allows it`() {
        val cfg = UmbralConfig(dns = UmbralConfig().dns.copy(blockNonDnsUdp = false))
        val f = PacketFilter(RoutingPolicy(cfg, { true }, { true })) { cfg }
        val v = f.decide(IpCodec.parse(udpV4(443)), ctx(1000))
        assertTrue(v is Verdict.Pass)
    }

    @Test
    fun `blocked uid syn gets reset`() {
        val cfg = UmbralConfig(
            appRules = mapOf("x" to AppRule(1000, wifi = RouteAction.BLOCK, mobile = RouteAction.BLOCK))
        )
        val f = PacketFilter(RoutingPolicy(cfg, { true }, { true })) { cfg }
        val v = f.decide(IpCodec.parse(tcpSynV4("10.111.111.114", "93.184.216.34", 50000, 443)), ctx(1000))
        assertTrue(v is Verdict.Reset)
    }

    @Test
    fun `normal tcp passes`() {
        val f = PacketFilter(RoutingPolicy(UmbralConfig(), { true }, { true })) { UmbralConfig() }
        val v = f.decide(IpCodec.parse(tcpSynV4("10.111.111.114", "93.184.216.34", 50000, 443)), ctx(1000))
        assertTrue(v is Verdict.Pass)
    }
}

class ProcNetTest {

    @Test
    fun `parses kernel table`() {
        val sample = """
   sl: local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
     0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000   10150        0 12345 1 0000000000000000 100 0 0 10 0
     1: 6F0B6F0A:C350 5FD8B85D:01BB 01 00000000:00000000 00:00000000 00000000   10213        0 54321 1 0000000000000000 20 4 30 10 -1
        """.trimIndent()
        val conns = ProcNet.parse(sample)
        assertEquals(2, conns.size)
        assertEquals(ProcNet.Conn(0x1F90, 0, 10150), conns[0])
        assertEquals(ProcNet.Conn(0xC350, 0x01BB, 10213), conns[1])
    }

    @Test
    fun `empty and header only`() {
        assertEquals(0, ProcNet.parse("sl local rem\n").size)
    }
}
