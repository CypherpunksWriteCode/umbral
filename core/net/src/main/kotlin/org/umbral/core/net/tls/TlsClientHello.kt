package org.umbral.core.net.tls

/**
 * Minimal TLS ClientHello reader (RFC 5246 §7.4.1.2 / RFC 8446 §4.1.2) and
 * anti-DPI writer strategy. Pure functions over byte arrays — fully tested.
 *
 * Why only fragmentation (no in-place SNI rewriting): the TLS handshake
 * transcript hash (and thus the Finished MAC) covers the ClientHello bytes
 * the client sent. If we modify the SNI on the wire, the server's transcript
 * diverges and the handshake dies with bad_record_mac. Real SNI rewriting
 * requires MITM (terminate TLS locally, re-originate) — PowerTunnel's SNI
 * tricks work exactly that way (LittleProxy-MITM). Splitting the ClientHello
 * across TCP segments changes nothing on the wire bytes, but many DPI boxes
 * fail to reassemble — the same trick as GoodbyeDPI/zapret, at userspace.
 */
object TlsClientHello {

    class ParseException(message: String) : Exception(message)

    data class Parsed(
        /** SNI hostname if present (first entry of type host_name). */
        val sni: String?,
        /** Offset of the SNI hostname bytes inside the ClientHello record, or -1. */
        val sniOffset: Int,
        val sniLength: Int,
        /** Total TLS record length (content + 5 byte header). */
        val recordLength: Int
    )

    /**
     * Parse a full ClientHello record (starting with the 5-byte TLS record
     * header). Returns SNI location or null-sni when the record is a
     * ClientHello without a server_name extension (or not a ClientHello at
     * all — callers use that to leave the stream untouched).
     */
    fun parse(record: ByteArray): Parsed {
        if (record.size < 5) throw ParseException("short")
        val type = record[0].toInt() and 0xff
        if (type != 0x16) throw ParseException("not a handshake record")
        val len = ((record[3].toInt() and 0xff) shl 8) or (record[4].toInt() and 0xff)
        val end = 5 + len
        if (end > record.size) throw ParseException("record truncated: need $end have ${record.size}")

        // handshake header
        var i = 5
        if (i >= end) throw ParseException("no handshake header")
        val hsType = record[i].toInt() and 0xff
        if (hsType != 0x01) throw ParseException("not a ClientHello")
        val hsLen = ((record[i + 1].toInt() and 0xff) shl 16) or
            ((record[i + 2].toInt() and 0xff) shl 8) or (record[i + 3].toInt() and 0xff)
        i += 4
        val hsEnd = i + hsLen
        if (hsEnd > end) throw ParseException("handshake length mismatch")

        // client_version(2) random(32)
        i += 2 + 32
        // session_id
        i += 1 + (record[i].toInt() and 0xff)
        // cipher_suites
        i += 2 + (((record[i].toInt() and 0xff) shl 8) or (record[i + 1].toInt() and 0xff))
        // compression_methods
        i += 1 + (record[i].toInt() and 0xff)
        if (i + 2 > hsEnd) return Parsed(null, -1, 0, end) // TLS 1.2-style empty extensions
        val extLen = (((record[i].toInt() and 0xff) shl 8) or (record[i + 1].toInt() and 0xff))
        i += 2
        val extEnd = i + extLen
        if (extEnd > hsEnd) throw ParseException("extensions overrun")

        while (i + 4 <= extEnd) {
            val eType = (((record[i].toInt() and 0xff) shl 8) or (record[i + 1].toInt() and 0xff))
            val eLen = (((record[i + 2].toInt() and 0xff) shl 8) or (record[i + 3].toInt() and 0xff))
            val eStart = i + 4
            if (eType == 0x0000) {
                // server_name extension: list_len(2) name_type(1) name_len(2) name
                var j = eStart
                j += 2 // server_name_list length
                if (j + 1 > eStart + eLen) return Parsed(null, -1, 0, end)
                if ((record[j].toInt() and 0xff) != 0) return Parsed(null, -1, 0, end) // not host_name
                val nLen = (((record[j + 1].toInt() and 0xff) shl 8) or (record[j + 2].toInt() and 0xff))
                val nStart = j + 3
                if (nStart + nLen > eStart + eLen) throw ParseException("sni overrun")
                val sni = String(record, nStart, nLen, Charsets.US_ASCII)
                return Parsed(sni, nStart, nLen, end)
            }
            i = eStart + eLen
        }
        return Parsed(null, -1, 0, end)
    }

    /**
     * Split points for anti-DPI fragmentation: we cut the record so that the
     * SNI hostname (or the middle of a small record) starts in the second
     * segment. Bytes are unchanged — only TCP write boundaries move.
     *
     * @return list of (offset, length) chunks covering [0, recordLength)
     */
    fun fragmentPlan(recordLength: Int, sniOffset: Int, sniLength: Int, chunkSize: Int): List<Pair<Int, Int>> {
        require(recordLength > 0) { "empty record" }
        val chunk = chunkSize.coerceIn(1, 64)
        if (sniOffset > 5 && sniOffset < recordLength) {
            // cut right before the SNI, and keep remaining pieces small
            val out = ArrayList<Pair<Int, Int>>()
            var off = 0
            val cut = sniOffset // first chunk = header .. before SNI
            out.add(0 to (cut - 0))
            off = cut
            while (off < recordLength) {
                val n = minOf(chunk, recordLength - off)
                out.add(off to n)
                off += n
            }
            return out
        }
        // no SNI found: generic small chunks
        val out = ArrayList<Pair<Int, Int>>()
        var off = 0
        while (off < recordLength) {
            val n = minOf(chunk, recordLength - off)
            out.add(off to n)
            off += n
        }
        return out
    }
}
