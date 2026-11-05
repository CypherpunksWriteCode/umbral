package org.umbral.core.dns

import org.umbral.core.net.pkt.BytePacketWriter

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.umbral.core.model.DnsMode
import org.umbral.core.model.DnsProviders
import org.umbral.core.model.UmbralConfig
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicLong

/**
 * The local DNS brain. Receives raw DNS query datagrams (captured from the
 * tunnel), resolves them via the configured upstream, and produces raw
 * response datagrams ready to be sent back into the tunnel.
 *
 * All state is local. Queries are reported only to the in-memory diagnostics
 * hook if installed by the app; nothing leaves the device by itself.
 */
class DnsEngine(
    private val cacheEnabled: Boolean = true,
    private val clock: () -> Long = { System.currentTimeMillis() },
    /** Test hook: replaces the upstream entirely when set. */
    private val upstreamOverride: DnsUpstream? = null
) {
    private val cache = DnsCache(clock)
    private val queryCounter = AtomicLong()
    private val failCounter = AtomicLong()

    data class QueryLog(
        val name: String,
        val type: Int,
        val rcode: Int,
        val cached: Boolean,
        val latencyMs: Long,
        val upstream: String
    )

    var onQueryCompleted: ((QueryLog) -> Unit)? = null

    /** Injection point for tests; production uses [Companion.buildUpstream]. */
    var upstreamFactory: (org.umbral.core.model.UmbralConfig) -> DnsUpstream = { buildUpstream(it) }

    @Volatile
    var config: UmbralConfig = UmbralConfig()

    fun stats(): Triple<Long, Long, Int> = Triple(queryCounter.get(), failCounter.get(), cache.size())

    /**
     * Handle one DNS query datagram, returns the response datagram.
     *
     * @param query raw DNS message bytes as sent by the client
     * @param passthroughDest original destination resolver of the query;
     * used only in SYSTEM_PASSTHROUGH mode.
     */
    suspend fun handle(query: ByteArray, passthroughDest: InetSocketAddress? = null): ByteArray {
        val parsed = try {
            DnsCodec.parse(query)
        } catch (e: Exception) {
            val id = if (query.size >= 2)
                ((query[0].toInt() and 0xff) shl 8) or (query[1].toInt() and 0xff) else 0
            return errorResponse(id, DnsCodec.RCODE_FORMAT)
        }
        val q = parsed.questions.firstOrNull()
            ?: return errorResponse(parsed.id, DnsCodec.RCODE_FORMAT)

        if (config.dns.mode == DnsMode.SYSTEM_PASSTHROUGH) {
            queryCounter.incrementAndGet()
            return passthrough(query, passthroughDest, parsed.id)
        }

        queryCounter.incrementAndGet()
        val started = clock()
        var cached = false
        val upstream = upstreamOverride ?: upstreamFactory(config)
        try {
            val result: ResolveResult
            val reverse = q.name.endsWith(".in-addr.arpa") || q.name.endsWith(".ip6.arpa")
            if (cacheEnabled && !reverse) {
                val hit = cache.get(q.name, q.type)
                if (hit != null) {
                    cached = true
                    result = ResolveResult(hit, 30, DnsCodec.RCODE_NOERROR, null)
                } else {
                    result = upstream.resolve(DnsCodec.buildQuery(0x0000, q.name, q.type))
                    if (result.rcode == DnsCodec.RCODE_NOERROR && result.answers.isNotEmpty()) {
                        cache.put(q.name, q.type, result.answers, result.ttlSeconds)
                    }
                }
            } else {
                result = upstream.resolve(DnsCodec.buildQuery(0x0000, q.name, q.type))
            }
            val resp = buildResponse(parsed.id, q, result)
            onQueryCompleted?.invoke(
                QueryLog(q.name, q.type, result.rcode, cached, clock() - started, upstream.describe())
            )
            return resp
        } catch (e: Exception) {
            failCounter.incrementAndGet()
            onQueryCompleted?.invoke(
                QueryLog(q.name, q.type, -1, cached, clock() - started, upstream.describe() + " ERROR: ${e.message}")
            )
            return errorResponse(parsed.id, DnsCodec.RCODE_SERVFAIL)
        }
    }

    private fun passthrough(query: ByteArray, dest: InetSocketAddress?, queryId: Int): ByteArray =
        runCatching {
            val target = dest ?: InetSocketAddress(InetAddress.getByName("8.8.8.8"), 53)
            DatagramSocket().use { s ->
                s.soTimeout = 8000
                s.send(DatagramPacket(query, query.size, target))
                val buf = ByteArray(4096)
                val pkt = DatagramPacket(buf, buf.size)
                s.receive(pkt)
                buf.copyOf(pkt.length)
            }
        }.getOrElse {
            failCounter.incrementAndGet()
            errorResponse(queryId, DnsCodec.RCODE_SERVFAIL)
        }

    /** Rebuild a wire response for [id] from the upstream result. */
    internal fun buildResponse(id: Int, q: DnsCodec.Question, result: ResolveResult): ByteArray {
        val w = BytePacketWriter(256)
        w.u16(id)
        w.u16(0x8180) // QR=1, AA=0, TC=0, RD=1, RA=1; rcode patched at the end
        w.u16(1)
        val records = result.response?.answers
            ?.filter { it.type == q.type || it.type == DnsCodec.TYPE_CNAME }
            ?: result.answers.map { ip ->
                val addr = InetAddress.getByName(ip).address
                DnsCodec.Record(
                    q.name, if (addr.size == 4) DnsCodec.TYPE_A else DnsCodec.TYPE_AAAA,
                    DnsCodec.CLASS_IN, 30, addr
                )
            }
        w.u16(records.size.coerceAtMost(8))
        w.u16(0); w.u16(0)
        w.bytes(DnsCodec.encodeName(q.name))
        w.u16(q.type); w.u16(DnsCodec.CLASS_IN)
        records.take(8).forEach { rec ->
            val rdata: ByteArray = when {
                rec.type == DnsCodec.TYPE_CNAME -> rec.rdata
                rec.asA != null || rec.asAAAA != null -> rec.rdata
                else -> return@forEach
            }
            w.bytes(byteArrayOf(0xC0.toByte(), 0x0C)) // pointer to question name
            w.u16(rec.type); w.u16(DnsCodec.CLASS_IN)
            w.u32(rec.ttl.coerceIn(0, 86_400))
            w.u16(rdata.size); w.bytes(rdata)
        }
        val bytes = w.toByteArray()
        // patch rcode into the flags half-byte
        bytes[3] = ((bytes[3].toInt() and 0xF0) or (result.rcode and 0x0F)).toByte()
        return bytes
    }

    private fun errorResponse(id: Int, rcode: Int): ByteArray {
        val w = BytePacketWriter(12)
        w.u16(id)
        w.u16(0x8180 or (rcode and 0xF))
        w.u16(0); w.u16(0); w.u16(0); w.u16(0)
        return w.toByteArray()
    }

    fun clearCache() = cache.clear()

    companion object {
        /** Default Tor SOCKS port (127.0.0.1). TorService's actual port is read at runtime. */
        const val TOR_SOCKS_PORT = 9050

        fun buildUpstream(cfg: UmbralConfig): DnsUpstream {
            val provider = DnsProviders.resolve(cfg.dns)
            val torAddr: InetSocketAddress? =
                if (cfg.dns.viaTor && cfg.tor.enabled)
                    InetSocketAddress(InetAddress.getLoopbackAddress(), TOR_SOCKS_PORT)
                else null
            return when (cfg.dns.mode) {
                DnsMode.DOH -> DohResolver(
                    baseUrl = if (cfg.dns.isCustom) cfg.dns.customDohUrl
                    else provider.dohUrl ?: "https://cloudflare-dns.com/dns-query",
                    socksProxy = torAddr
                )
                DnsMode.DOT -> DotResolver(
                    host = if (cfg.dns.isCustom) cfg.dns.customDotHost
                    else provider.dotHost ?: "one.one.one.one",
                    socksConnect = torAddr?.let { addr ->
                        { h, p -> org.umbral.core.net.socks.Socks5Client.connect(addr, h, p) }
                    }
                )
                DnsMode.SYSTEM_PASSTHROUGH -> PassthroughUdpResolver()
            }
        }
    }
}
