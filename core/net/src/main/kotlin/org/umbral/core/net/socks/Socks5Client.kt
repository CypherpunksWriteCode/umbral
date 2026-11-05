package org.umbral.core.net.socks

import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket

/**
 * SOCKS5 client (RFC 1928) for CONNECT with NO-AUTH and optional USER/PASS
 * (RFC 1929). Target hostnames are sent as ATYP=0x03 (DOMAINNAME) so the
 * proxy — e.g. Tor — resolves them remotely. Local resolution would leak DNS.
 */
object Socks5Client {

    class SocksException(message: String) : IOException(message)

    const val METHOD_NO_AUTH = 0x00
    const val METHOD_USER_PASS = 0x02
    const val CMD_CONNECT = 0x01

    /**
     * Connect through the SOCKS5 proxy at [proxy] to [targetHost]:[targetPort].
     * [targetHost] may be a hostname or a literal IP. Returns the established socket.
     */
    fun connect(
        proxy: InetSocketAddress,
        targetHost: String,
        targetPort: Int,
        username: String? = null,
        password: String? = null,
        connectTimeoutMs: Int = 10_000,
        readTimeoutMs: Int = 30_000
    ): Socket {
        val useAuth = !username.isNullOrEmpty()
        val sock = Socket()
        sock.tcpNoDelay = true
        sock.soTimeout = readTimeoutMs
        sock.connect(proxy, connectTimeoutMs)
        try {
            val input: InputStream = sock.getInputStream()
            val output: OutputStream = sock.getOutputStream()

            // greeting
            val methods = if (useAuth)
                byteArrayOf(5, 2, METHOD_NO_AUTH.toByte(), METHOD_USER_PASS.toByte())
            else byteArrayOf(5, 1, METHOD_NO_AUTH.toByte())
            output.write(methods); output.flush()
            val gv = readN(input, 2)
            if (gv[0].toInt() != 5) throw SocksException("bad SOCKS version ${gv[0]}")
            val method = gv[1].toInt() and 0xff
            if (method == 0xFF) throw SocksException("no acceptable auth method")
            if (useAuth && method == METHOD_USER_PASS) {
                val u = username!!.toByteArray(Charsets.UTF_8)
                val p = (password ?: "").toByteArray(Charsets.UTF_8)
                require(u.size <= 255 && p.size <= 255) { "user/pass too long" }
                val auth = ByteArray(3 + u.size + p.size)
                auth[0] = 1
                auth[1] = u.size.toByte(); u.copyInto(auth, 2)
                auth[2 + u.size] = p.size.toByte(); p.copyInto(auth, 3 + u.size)
                output.write(auth); output.flush()
                val ar = readN(input, 2)
                if (ar[1].toInt() != 0) throw SocksException("SOCKS auth failed")
            } else if (method != METHOD_NO_AUTH) {
                throw SocksException("proxy chose unsupported method $method")
            }

            // request
            val hostBytes = targetHost.toByteArray(Charsets.UTF_8)
            require(hostBytes.size in 1..255) { "target host too long" }
            val isLiteral = isLiteralAddress(targetHost)
            val addr: InetAddress? = if (isLiteral) InetAddress.getByName(targetHost) else null
            val addrBytes: ByteArray = when {
                addr?.address?.size == 4 -> addr.address
                addr?.address?.size == 16 -> addr.address
                else -> null
            } ?: hostBytes // domain
            val req = ByteArray(6 + (if (addrBytes === hostBytes) 1 + hostBytes.size else addrBytes.size))
            var i = 0
            req[i++] = 5; req[i++] = CMD_CONNECT.toByte(); req[i++] = 0
            if (addrBytes === hostBytes) {
                req[i++] = 0x03
                req[i++] = hostBytes.size.toByte()
            } else {
                req[i++] = if (addrBytes.size == 4) 0x01 else 0x04
            }
            addrBytes.copyInto(req, i); i += addrBytes.size
            req[i++] = (targetPort shr 8).toByte(); req[i] = (targetPort and 0xff).toByte()
            output.write(req); output.flush()

            // reply
            val rh = readN(input, 4)
            if (rh[1].toInt() and 0xff != 0) {
                throw SocksException("SOCKS CONNECT failed, code ${rh[1].toInt() and 0xff}")
            }
            val atyp = rh[3].toInt() and 0xff
            when (atyp) {
                0x01 -> readN(input, 4)
                0x04 -> readN(input, 16)
                0x03 -> {
                    val len = input.read()
                    if (len < 0) throw SocksException("truncated BND.ADDR")
                    readN(input, len)
                }
                else -> throw SocksException("bad ATYP $atyp")
            }
            readN(input, 2)
            sock.soTimeout = readTimeoutMs
            return sock
        } catch (e: Exception) {
            try { sock.close() } catch (_: Exception) {}
            throw e
        }
    }

    private fun isLiteralAddress(host: String): Boolean =
        host.contains(':') || host.split('.').size == 4 && host.split('.').all {
            it.isNotEmpty() && it.toIntOrNull() in 0..255
        }

    private fun readN(input: InputStream, n: Int): ByteArray {
        val out = ByteArray(n)
        var read = 0
        while (read < n) {
            val r = input.read(out, read, n - read)
            if (r < 0) throw SocksException("EOF reading $n bytes at $read")
            read += r
        }
        return out
    }
}
