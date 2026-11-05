package org.umbral.core.net.uid

/**
 * Parser for /proc/net/tcp, tcp6, udp, udp6. Used for UID attribution on
 * Android 8.x–9 (API 26–28); on API 29+ the public
 * ConnectivityManager.getConnectionOwnerUid() is used instead.
 *
 * Format (kernelDocumentation networking/proc_net_tcp):
 * sl local_address rem_address st ... uid ...
 * Addresses are hex without separators; IPv6 is big-endian 32 hex chars.
 */
object ProcNet {
    data class Conn(val localPort: Int, val remotePort: Int, val uid: Int)

    fun parse(text: String): List<Conn> {
        val out = ArrayList<Conn>()
        val lines = text.lineSequence().iterator()
        if (!lines.hasNext()) return out
        lines.next() // header
        while (lines.hasNext()) {
            val cols = lines.next().trim().split(Regex("\\s+"))
            if (cols.size < 8) continue
            val local = cols[1].split(":")
            val remote = cols[2].split(":")
            if (local.size != 2 || remote.size != 2) continue
            val localPort = local[1].toIntOrNull(16) ?: continue
            val remotePort = remote[1].toIntOrNull(16) ?: continue
            val uid = cols[7].toIntOrNull() ?: continue
            out.add(Conn(localPort, remotePort, uid))
        }
        return out
    }
}
