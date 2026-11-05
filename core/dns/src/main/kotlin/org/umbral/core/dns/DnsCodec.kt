package org.umbral.core.dns

import org.umbral.core.net.pkt.BytePacketWriter



/**
 * Minimal RFC 1035 wire-format codec: enough to build A/AAAA queries and parse
 * responses, including name decompression. Written against the RFC, unit tested
 * against hand-crafted bytes and live capture samples.
 */
object DnsCodec {
    const val TYPE_A = 1
    const val TYPE_NS = 2
    const val TYPE_CNAME = 5
    const val TYPE_SOA = 6
    const val TYPE_PTR = 12
    const val TYPE_MX = 15
    const val TYPE_TXT = 16
    const val TYPE_AAAA = 28
    const val TYPE_SRV = 33
    const val TYPE_OPT = 41

    const val CLASS_IN = 1

    const val RCODE_NOERROR = 0
    const val RCODE_FORMAT = 1
    const val RCODE_SERVFAIL = 2
    const val RCODE_NXDOMAIN = 3
    const val RCODE_NOTIMP = 4
    const val RCODE_REFUSED = 5

    class DnsException(message: String) : Exception(message)

    data class Question(val name: String, val type: Int, val qClass: Int)
    data class Record(
        val name: String,
        val type: Int,
        val qClass: Int,
        val ttl: Long,
        /** Raw RDATA bytes. */
        val rdata: ByteArray
    ) {
        val asA: String? get() = if (type == TYPE_A && rdata.size == 4)
            "${rdata[0].toInt() and 0xff}.${rdata[1].toInt() and 0xff}.${rdata[2].toInt() and 0xff}.${rdata[3].toInt() and 0xff}" else null
        val asAAAA: String? get() = if (type == TYPE_AAAA && rdata.size == 16) {
            val h = IntArray(8) { ((rdata[it * 2].toInt() and 0xff) shl 8) or (rdata[it * 2 + 1].toInt() and 0xff) }
            // RFC 5952: compress the longest zero run of length >= 2
            var bestStart = -1; var bestLen = 0; var i = 0
            while (i < 8) {
                if (h[i] == 0) {
                    val s = i
                    while (i < 8 && h[i] == 0) i++
                    if (i - s > bestLen) { bestLen = i - s; bestStart = s }
                } else i++
            }
            if (bestLen >= 2) {
                val left = h.copyOfRange(0, bestStart).joinToString(":") { String.format("%x", it) }
                val right = h.copyOfRange(bestStart + bestLen, 8).joinToString(":") { String.format("%x", it) }
                when {
                    left.isEmpty() && right.isEmpty() -> "::"
                    left.isEmpty() -> "::$right"
                    right.isEmpty() -> "$left::"
                    else -> "$left::$right"
                }
            } else h.joinToString(":") { String.format("%x", it) }
        } else null
    }

    data class Message(
        val id: Int,
        val response: Boolean,
        val opcode: Int,
        val authoritative: Boolean,
        val truncated: Boolean,
        val recursionDesired: Boolean,
        val recursionAvailable: Boolean,
        val rcode: Int,
        val questions: List<Question>,
        val answers: List<Record>,
        val authority: List<Record>,
        val additional: List<Record>
    )

    /** Build a recursion-desired query for one question. */
    fun buildQuery(id: Int, name: String, type: Int): ByteArray {
        val labels = encodeName(name)
        val out = BytePacketWriter(12 + labels.size + 4)
        out.u16(id)
        out.u16(0x0100) // QR=0, OPCODE=0, AA=0, TC=0, RD=1
        out.u16(1)      // QDCOUNT
        out.u16(0)      // ANCOUNT
        out.u16(0)      // NSCOUNT
        out.u16(0)      // ARCOUNT
        out.bytes(labels)
        out.u16(type)
        out.u16(CLASS_IN)
        return out.toByteArray()
    }

    fun parse(data: ByteArray): Message {
        if (data.size < 12) throw DnsException("short DNS message (${data.size} bytes)")
        val r = BytePacketReader(data)
        val id = r.u16()
        val flags = r.u16()
        val response = (flags shr 15) and 1 == 1
        val opcode = (flags shr 11) and 0xF
        val authoritative = (flags shr 10) and 1 == 1
        val truncated = (flags shr 9) and 1 == 1
        val rd = (flags shr 8) and 1 == 1
        val ra = (flags shr 7) and 1 == 1
        val rcode = flags and 0xF
        val qd = r.u16(); val an = r.u16(); val ns = r.u16(); val ar = r.u16()
        val questions = (0 until qd).map { Question(r.name(), r.u16(), r.u16()) }
        fun records(n: Int) = (0 until n).map {
            val name = r.name()
            val type = r.u16(); val cls = r.u16(); val ttl = r.u32()
            val rdlen = r.u16()
            val rdata = r.bytes(rdlen)
            Record(name, type, cls, ttl, rdata)
        }
        val answers = records(an)
        val authority = records(ns)
        val additional = records(ar)
        return Message(
            id, response, opcode, authoritative, truncated, rd, ra, rcode,
            questions, answers, authority, additional
        )
    }

    /** Encode a dotted name into wire labels without compression (queries). */
    fun encodeName(name: String): ByteArray {
        val n = name.trimEnd('.').ifEmpty { throw DnsException("empty name") }
        val parts = n.split('.')
        var size = 1
        for (p in parts) {
            require(p.isNotEmpty()) { "empty label in $name" }
            require(p.length <= 63) { "label too long in $name" }
            size += p.length + 1
        }
        require(size <= 255) { "name too long: $name" }
        val out = ByteArray(size)
        var i = 0
        for (p in parts) {
            out[i++] = p.length.toByte()
            for (c in p.toByteArray(Charsets.UTF_8)) out[i++] = c
        }
        out[i] = 0
        return out
    }

    /** Read a possibly-compressed name starting at the current offset. */
    fun readName(data: ByteArray, offset: Int): Pair<String, Int> {
        val labels = StringBuilder()
        var pos = offset
        var jumped = false
        var end = -1
        var jumps = 0
        var total = 0
        while (true) {
            if (pos >= data.size) throw DnsException("name runs off packet")
            val len = data[pos].toInt() and 0xff
            when {
                len == 0 -> {
                    if (!jumped) end = pos + 1
                    break
                }
                len and 0xC0 == 0xC0 -> {
                    if (pos + 1 >= data.size) throw DnsException("truncated pointer")
                    if (!jumped) end = pos + 2
                    val ptr = ((len and 0x3F) shl 8) or (data[pos + 1].toInt() and 0xff)
                    if (jumps++ > 64) throw DnsException("compression loop")
                    pos = ptr
                    jumped = true
                }
                len and 0xC0 != 0 -> throw DnsException("bad label type $len")
                else -> {
                    pos++
                    if (pos + len > data.size) throw DnsException("truncated label")
                    if (labels.isNotEmpty()) labels.append('.')
                    val bs = data.copyOfRange(pos, pos + len)
                    labels.append(bs.toString(Charsets.UTF_8))
                    total += len + 1
                    if (total > 255) throw DnsException("decompressed name too long")
                    pos += len
                }
            }
        }
        return labels.toString() to (if (end >= 0) end else offset)
    }
}

class BytePacketReader(private val data: ByteArray) {
    var offset = 0
        private set

    fun u8(): Int {
        check(offset < data.size) { "read past end" }
        return data[offset++].toInt() and 0xff
    }

    fun u16(): Int = (u8() shl 8) or u8()

    fun u32(): Long = (u16().toLong() shl 16) or u16().toLong()

    fun bytes(n: Int): ByteArray {
        check(offset + n <= data.size) { "read past end ($offset+$n > ${data.size})" }
        val out = data.copyOfRange(offset, offset + n)
        offset += n
        return out
    }

    fun name(): String {
        val (n, next) = DnsCodec.readName(data, offset)
        offset = next
        return n
    }

    fun remaining() = data.size - offset
}
