package org.umbral.core.net.pkt

/**
 * IP/TCP/UDP wire codec for the tunnel packet filter.
 * Parses IPv4 (RFC 791) and IPv6 (RFC 8200) base headers; builds IPv4/IPv6
 * UDP responses and TCP RSTs with correct checksums.
 *
 * Only what the filter needs: no fragmentation reassembly, no TCP parsing
 * beyond the fixed header. Everything here is pure and unit tested.
 */
object IpCodec {
    const val IPPROTO_ICMP = 1
    const val IPPROTO_TCP = 6
    const val IPPROTO_UDP = 17
    const val IPPROTO_ICMPV6 = 58

    class PacketFormatException(message: String) : Exception(message)

    data class IpHeader(
        val version: Int,
        /** Raw source address bytes (4 or 16). */
        val src: ByteArray,
        val dst: ByteArray,
        val protocol: Int,
        /** Offset of L4 payload within the packet. */
        val payloadOffset: Int,
        val totalLength: Int,
        val srcText: String,
        val dstText: String,
        val tcp: TcpHeader?,
        val udp: UdpHeader?
    )

    data class TcpHeader(
        val srcPort: Int,
        val dstPort: Int,
        val seq: Long,
        val ack: Long,
        val flags: Int,
        val headerLength: Int
    ) {
        val isSyn get() = flags and 0x02 != 0
        val isAck get() = flags and 0x10 != 0
        val isFin get() = flags and 0x01 != 0
        val isRst get() = flags and 0x04 != 0
    }

    data class UdpHeader(val srcPort: Int, val dstPort: Int, val length: Int)

    fun parse(packet: ByteArray): IpHeader {
        if (packet.size < 1) throw PacketFormatException("empty packet")
        val version = (packet[0].toInt() ushr 4) and 0xF
        return when (version) {
            4 -> parseV4(packet)
            6 -> parseV6(packet)
            else -> throw PacketFormatException("unknown IP version $version")
        }
    }

    private fun parseV4(p: ByteArray): IpHeader {
        if (p.size < 20) throw PacketFormatException("IPv4 too short (${p.size})")
        val ihl = (p[0].toInt() and 0x0F) * 4
        if (ihl < 20) throw PacketFormatException("bad IHL $ihl")
        val totalLen = u16(p, 2)
        if (totalLen < ihl || totalLen > p.size) throw PacketFormatException("bad total length $totalLen (buffer ${p.size})")
        val proto = p[9].toInt() and 0xff
        val src = p.copyOfRange(12, 16)
        val dst = p.copyOfRange(16, 20)
        var tcp: TcpHeader? = null
        var udp: UdpHeader? = null
        if (proto == IPPROTO_TCP && totalLen >= ihl + 20) {
            tcp = TcpHeader(
                srcPort = u16(p, ihl),
                dstPort = u16(p, ihl + 2),
                seq = u32(p, ihl + 4),
                ack = u32(p, ihl + 8),
                flags = p[ihl + 13].toInt() and 0xFF,
                headerLength = ((p[ihl + 12].toInt() and 0xF0) ushr 4) * 4
            )
        } else if (proto == IPPROTO_UDP && totalLen >= ihl + 8) {
            udp = UdpHeader(u16(p, ihl), u16(p, ihl + 2), u16(p, ihl + 4))
        }
        return IpHeader(4, src, dst, proto, ihl, totalLen, ip4Text(src), ip4Text(dst), tcp, udp)
    }

    private fun parseV6(p: ByteArray): IpHeader {
        if (p.size < 40) throw PacketFormatException("IPv6 too short (${p.size})")
        val totalLen = 40 + u16(p, 4)
        if (totalLen > p.size) throw PacketFormatException("IPv6 payload overruns buffer")
        val proto = p[6].toInt() and 0xff
        val src = p.copyOfRange(8, 24)
        val dst = p.copyOfRange(24, 40)
        var tcp: TcpHeader? = null
        var udp: UdpHeader? = null
        if (proto == IPPROTO_TCP && totalLen >= 60) {
            tcp = TcpHeader(
                srcPort = u16(p, 40),
                dstPort = u16(p, 42),
                seq = u32(p, 44),
                ack = u32(p, 48),
                flags = p[53].toInt() and 0xFF,
                headerLength = ((p[52].toInt() and 0xF0) ushr 4) * 4
            )
        } else if (proto == IPPROTO_UDP && totalLen >= 48) {
            udp = UdpHeader(u16(p, 40), u16(p, 42), u16(p, 44))
        }
        return IpHeader(6, src, dst, proto, 40, totalLen, ip6Text(src), ip6Text(dst), tcp, udp)
    }

    /**
     * Build an IPv4 UDP packet. IPv4 UDP checksum is legal as 0 (RFC 768),
     * but we compute it anyway to be a good citizen.
     */
    fun buildUdp4(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        require(srcIp.size == 4 && dstIp.size == 4)
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val out = ByteArray(totalLen)
        out[0] = 0x45
        out[1] = 0
        out[2] = (totalLen shr 8).toByte(); out[3] = (totalLen and 0xff).toByte()
        out[4] = 0; out[5] = 0 // id
        out[6] = 0x40; out[7] = 0 // DF
        out[8] = 64
        out[9] = IPPROTO_UDP.toByte()
        srcIp.copyInto(out, 12); dstIp.copyInto(out, 16)
        out[20] = (srcPort shr 8).toByte(); out[21] = (srcPort and 0xff).toByte()
        out[22] = (dstPort shr 8).toByte(); out[23] = (dstPort and 0xff).toByte()
        out[24] = (udpLen shr 8).toByte(); out[25] = (udpLen and 0xff).toByte()
        payload.copyInto(out, 28)
        val v4c = checksum(out, 0, 20)
        out[10] = (v4c shr 8).toByte(); out[11] = (v4c and 0xff).toByte()
        val uc = udpChecksum(srcIp, dstIp, out, 20, udpLen)
        out[26] = (uc shr 8).toByte(); out[27] = (uc and 0xff).toByte()
        return out
    }

    /** Build an IPv6 UDP packet (checksum is mandatory). */
    fun buildUdp6(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        require(srcIp.size == 16 && dstIp.size == 16)
        val udpLen = 8 + payload.size
        val out = ByteArray(40 + udpLen)
        out[0] = 0x60
        out[4] = (udpLen shr 8).toByte(); out[5] = (udpLen and 0xff).toByte()
        out[6] = IPPROTO_UDP.toByte(); out[7] = 64
        srcIp.copyInto(out, 8); dstIp.copyInto(out, 24)
        out[40] = (srcPort shr 8).toByte(); out[41] = (srcPort and 0xff).toByte()
        out[42] = (dstPort shr 8).toByte(); out[43] = (dstPort and 0xff).toByte()
        out[44] = (udpLen shr 8).toByte(); out[45] = (udpLen and 0xff).toByte()
        payload.copyInto(out, 48)
        val uc = udpChecksum(srcIp, dstIp, out, 40, udpLen)
        out[46] = (uc shr 8).toByte(); out[47] = (uc and 0xff).toByte()
        return out
    }

    /** Build a TCP RST (or RST+ACK) answering [incoming] — used to fail blocked connections fast. */
    fun buildRst(incoming: IpHeader): ByteArray? {
        val tcp = incoming.tcp ?: return null
        val seq = if (tcp.isSyn) (tcp.seq + 1) and 0xFFFFFFFFL else tcp.ack
        return when (incoming.version) {
            4 -> buildTcp4(incoming.dst, incoming.src, tcp.dstPort, tcp.srcPort, seq, 0, 0x04)
            6 -> buildTcp6(incoming.dst, incoming.src, tcp.dstPort, tcp.srcPort, seq, 0, 0x04)
            else -> null
        }
    }

    private fun buildTcp4(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int, seq: Long, ack: Long, flags: Int): ByteArray {
        val totalLen = 20 + 20
        val out = ByteArray(totalLen)
        out[0] = 0x45
        out[2] = (totalLen shr 8).toByte(); out[3] = (totalLen and 0xff).toByte()
        out[6] = 0x40
        out[8] = 64; out[9] = IPPROTO_TCP.toByte()
        srcIp.copyInto(out, 12); dstIp.copyInto(out, 16)
        out[20] = (srcPort shr 8).toByte(); out[21] = (srcPort and 0xff).toByte()
        out[22] = (dstPort shr 8).toByte(); out[23] = (dstPort and 0xff).toByte()
        put32(out, 24, seq); put32(out, 28, ack)
        out[32] = 0x50 // data offset 20 bytes
        out[33] = flags.toByte()
        put16(out, 38, 8192) // window
        val c = tcpChecksum4(srcIp, dstIp, out, 20)
        put16(out, 36, c)
        val v4c = checksum(out, 0, 20)
        out[10] = (v4c shr 8).toByte(); out[11] = (v4c and 0xff).toByte()
        return out
    }

    private fun buildTcp6(srcIp: ByteArray, dstIp: ByteArray, srcPort: Int, dstPort: Int, seq: Long, ack: Long, flags: Int): ByteArray {
        val totalLen = 40 + 20
        val out = ByteArray(totalLen)
        out[0] = 0x60
        put16(out, 4, 20)
        out[6] = IPPROTO_TCP.toByte(); out[7] = 64
        srcIp.copyInto(out, 8); dstIp.copyInto(out, 24)
        out[40] = (srcPort shr 8).toByte(); out[41] = (srcPort and 0xff).toByte()
        out[42] = (dstPort shr 8).toByte(); out[43] = (dstPort and 0xff).toByte()
        put32(out, 44, seq); put32(out, 48, ack)
        out[52] = 0x50
        out[53] = flags.toByte()
        put16(out, 58, 8192) // window
        val c = tcpChecksum6(srcIp, dstIp, out, 40)
        put16(out, 56, c)
        return out
    }

    // --- helpers ---

    fun ip4Text(b: ByteArray): String = "${b[0].toInt() and 0xff}.${b[1].toInt() and 0xff}.${b[2].toInt() and 0xff}.${b[3].toInt() and 0xff}"

    fun ip6Text(b: ByteArray): String {
        val h = IntArray(8) { ((b[it * 2].toInt() and 0xff) shl 8) or (b[it * 2 + 1].toInt() and 0xff) }
        var bestStart = -1; var bestLen = 0; var i = 0
        while (i < 8) {
            if (h[i] == 0) {
                val s = i
                while (i < 8 && h[i] == 0) i++
                if (i - s > bestLen) { bestLen = i - s; bestStart = s }
            } else i++
        }
        return if (bestLen >= 2) {
            val left = h.copyOfRange(0, bestStart).joinToString(":") { String.format("%x", it) }
            val right = h.copyOfRange(bestStart + bestLen, 8).joinToString(":") { String.format("%x", it) }
            when {
                left.isEmpty() && right.isEmpty() -> "::"
                left.isEmpty() -> "::$right"
                right.isEmpty() -> "$left::"
                else -> "$left::$right"
            }
        } else h.joinToString(":") { String.format("%x", it) }
    }

    fun internetChecksum(sum: Int): Int {
        var s = sum
        while (s shr 16 != 0) s = (s and 0xFFFF) + (s shr 16)
        return s.inv() and 0xFFFF
    }

    fun checksum(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        var end = off + len
        while (i < end - 1) {
            sum += ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (b[i].toInt() and 0xff) shl 8
        return internetChecksum(sum)
    }

    private fun pseudoSum(src: ByteArray, dst: ByteArray, proto: Int, len: Int): Int {
        var sum = 0
        for (i in src.indices step 2) sum += ((src[i].toInt() and 0xff) shl 8) or (src[i + 1].toInt() and 0xff)
        for (i in dst.indices step 2) sum += ((dst[i].toInt() and 0xff) shl 8) or (dst[i + 1].toInt() and 0xff)
        sum += proto
        sum += len
        return sum
    }

    fun udpChecksum(src: ByteArray, dst: ByteArray, packet: ByteArray, l4Off: Int, l4Len: Int): Int {
        val sum = pseudoSum(src, dst, IPPROTO_UDP, l4Len) + sumBytes(packet, l4Off, l4Len)
        return internetChecksum(sum).let { if (it == 0) 0xFFFF else it }
    }

    fun tcpChecksum4(src: ByteArray, dst: ByteArray, packet: ByteArray, l4Off: Int): Int =
        internetChecksum(pseudoSum(src, dst, IPPROTO_TCP, packet.size - l4Off) + sumBytes(packet, l4Off, packet.size - l4Off))

    fun tcpChecksum6(src: ByteArray, dst: ByteArray, packet: ByteArray, l4Off: Int): Int =
        internetChecksum(pseudoSum(src, dst, IPPROTO_TCP, packet.size - l4Off) + sumBytes(packet, l4Off, packet.size - l4Off))

    private fun sumBytes(b: ByteArray, off: Int, len: Int): Int {
        var sum = 0
        var i = off
        val end = off + len
        while (i < end - 1) {
            sum += ((b[i].toInt() and 0xff) shl 8) or (b[i + 1].toInt() and 0xff)
            i += 2
        }
        if (i < end) sum += (b[i].toInt() and 0xff) shl 8
        return sum
    }

    fun u16(b: ByteArray, off: Int): Int =
        ((b[off].toInt() and 0xff) shl 8) or (b[off + 1].toInt() and 0xff)

    fun u32(b: ByteArray, off: Int): Long =
        ((b[off].toLong() and 0xff) shl 24) or ((b[off + 1].toLong() and 0xff) shl 16) or
            ((b[off + 2].toLong() and 0xff) shl 8) or (b[off + 3].toLong() and 0xff)

    private fun put16(b: ByteArray, off: Int, v: Int) {
        b[off] = (v shr 8).toByte(); b[off + 1] = (v and 0xff).toByte()
    }

    private fun put32(b: ByteArray, off: Int, v: Long) {
        b[off] = ((v shr 24) and 0xff).toByte()
        b[off + 1] = ((v shr 16) and 0xff).toByte()
        b[off + 2] = ((v shr 8) and 0xff).toByte()
        b[off + 3] = (v and 0xff).toByte()
    }
}
