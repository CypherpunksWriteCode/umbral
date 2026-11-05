package org.umbral.core.dns

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.concurrent.TimeUnit
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Result of one upstream resolution. */
data class ResolveResult(
    val answers: List<String>,
    val ttlSeconds: Long,
    val rcode: Int,
    val response: DnsCodec.Message?
)

class ResolveException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * DNS-over-HTTPS (RFC 8484) via OkHttp. Supports routing the HTTPS connection
 * itself through a SOCKS5 proxy (e.g. local Tor). Whether the proxy performs
 * remote name resolution is verified by a unit test with a recording fake
 * SOCKS server (see DohResolverSocksTest).
 */
class DohResolver(
    baseUrl: String,
    socksProxy: InetSocketAddress? = null,
    connectTimeoutMs: Long = 10_000,
    callTimeoutMs: Long = 15_000
) : DnsUpstream {
    private val mediaType = "application/dns-message".toMediaType()
    private val client: OkHttpClient
    private val url: String = baseUrl.trimEnd('/')

    init {
        require(url.startsWith("https://")) { "DoH URL must be https: $baseUrl" }
        val b = OkHttpClient.Builder()
            .connectTimeout(connectTimeoutMs, TimeUnit.MILLISECONDS)
            .callTimeout(callTimeoutMs, TimeUnit.MILLISECONDS)
            .readTimeout(callTimeoutMs, TimeUnit.MILLISECONDS)
        if (socksProxy != null) {
            b.proxy(Proxy(Proxy.Type.SOCKS, socksProxy))
        }
        client = b.build()
    }

    override suspend fun resolve(query: ByteArray): ResolveResult = withContext(Dispatchers.IO) {
        val req = Request.Builder()
            .url(url)
            .post(query.toRequestBody(mediaType))
            .header("Accept", "application/dns-message")
            .header("User-Agent", "umbral/1")
            .build()
        client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) throw ResolveException("DoH HTTP ${resp.code}")
            val body = resp.body?.bytes() ?: throw ResolveException("DoH empty body")
            val msg = DnsCodec.parse(body)
            if (!msg.response) throw ResolveException("DoH returned a query, not a response")
            ResolveResult(collectIps(msg), minTtl(msg), msg.rcode, msg)
        }
    }

    override fun describe() = "DoH $url" + (if (client.proxy != null) " (via SOCKS)" else "")
}

/**
 * DNS-over-TLS (RFC 7858). Raw TLS socket to provider:853, 2-byte
 * length-prefixed TCP DNS framing per RFC 7766.
 *
 * @param socksConnect optional factory that returns an established, plain
 * TCP socket to the DoT host through a SOCKS5 proxy (e.g. Tor). The factory
 * MUST forward the hostname to the proxy rather than resolve it locally;
 * core:net Socks5Client implements exactly that contract.
 */
class DotResolver(
    private val host: String,
    private val port: Int = 853,
    private val socksConnect: (suspend (host: String, port: Int) -> Socket)? = null,
    private val connectTimeoutMs: Int = 10_000,
    private val readTimeoutMs: Int = 15_000
) : DnsUpstream {

    override suspend fun resolve(query: ByteArray): ResolveResult = withContext(Dispatchers.IO) {
        val sock: Socket = if (socksConnect != null) {
            socksConnect.invoke(host, port)
        } else {
            Socket().also { it.tcpNoDelay = true }
        }
        sock.soTimeout = readTimeoutMs
        try {
            val factory = defaultSslSocketFactory()
            val tls = factory.createSocket(sock, host, port, true) as SSLSocket
            tls.startHandshake()
            val out = tls.getOutputStream()
            out.write(byteArrayOf(((query.size shr 8) and 0xff).toByte(), (query.size and 0xff).toByte()))
            out.write(query)
            out.flush()
            val input = tls.getInputStream()
            val lenHi = input.read()
            if (lenHi < 0) throw ResolveException("DoT: connection closed")
            val lenLo = input.read()
            if (lenLo < 0) throw ResolveException("DoT: connection closed")
            val len = (lenHi shl 8) or lenLo
            if (len <= 0 || len > 65535) throw ResolveException("DoT: bad length $len")
            val body = ByteArray(len)
            var read = 0
            while (read < len) {
                val n = input.read(body, read, len - read)
                if (n < 0) throw ResolveException("DoT: truncated response")
                read += n
            }
            val msg = DnsCodec.parse(body)
            if (!msg.response) throw ResolveException("DoT returned a query")
            ResolveResult(collectIps(msg), minTtl(msg), msg.rcode, msg)
        } finally {
            try { sock.close() } catch (_: Exception) {}
        }
    }

    override fun describe() = "DoT $host:$port" + (if (socksConnect != null) " (via SOCKS)" else "")

    companion object {
        @Volatile private var cachedFactory: SSLSocketFactory? = null

        /** Default JVM trust store TLS factory (system CAs). */
        fun defaultSslSocketFactory(): SSLSocketFactory {
            cachedFactory?.let { return it }
            val tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
            tmf.init(null as java.security.KeyStore?)
            val tm = tmf.trustManagers.filterIsInstance<X509TrustManager>().firstOrNull()
                ?: throw IllegalStateException("no X509TrustManager")
            val ctx = SSLContext.getInstance("TLS")
            ctx.init(null, arrayOf(tm), SecureRandom())
            val f = ctx.socketFactory
            cachedFactory = f
            return f
        }
    }
}

/** Plain UDP forwarding of the original datagram to the original resolver — zero privacy, compatibility mode. */
class PassthroughUdpResolver : DnsUpstream {
    override suspend fun resolve(query: ByteArray): ResolveResult =
        throw UnsupportedOperationException("passthrough is handled by DnsEngine directly")

    override fun describe() = "passthrough (unencrypted)"
}

interface DnsUpstream {
    suspend fun resolve(query: ByteArray): ResolveResult
    fun describe(): String
}

internal fun collectIps(msg: DnsCodec.Message): List<String> =
    msg.answers.mapNotNull { it.asA ?: it.asAAAA }

internal fun minTtl(msg: DnsCodec.Message): Long =
    msg.answers.filter { it.type == DnsCodec.TYPE_A || it.type == DnsCodec.TYPE_AAAA }
        .minOfOrNull { it.ttl } ?: 0L
