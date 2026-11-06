package org.umbral.core.model

import kotlinx.serialization.Serializable

/** What happens to a connection whose app is routed through the VPN tunnel. */
enum class RouteAction { DIRECT, TOR, I2P, PROXY, BLOCK }

/** Network the device is currently attached to. */
enum class NetKind { WIFI, MOBILE, OTHER }

/** Routing decision for a single connection attempt. */
data class RouteDecision(
    val action: RouteAction,
    val reason: String,
    /** UID the rule matched, or -1 when only the default rule applied. */
    val matchedUid: Int = -1
)

/** Per-application routing/firewall rule. UIDs are stable per install. */
@Serializable
data class AppRule(
    val uid: Int,
    /** Route when on Wi-Fi. null means "use defaultRoute". */
    val wifi: RouteAction? = null,
    /** Route when on mobile data. null means "use defaultRoute". */
    val mobile: RouteAction? = null
) {
    fun forNetwork(kind: NetKind): RouteAction? = when (kind) {
        NetKind.WIFI -> wifi
        NetKind.MOBILE -> mobile
        NetKind.OTHER -> wifi ?: mobile
    }
}

/** Mode selection for the DNS privacy module. */
enum class DnsMode { SYSTEM_PASSTHROUGH, DOH, DOT }

/** A DNS provider definition. Presets are shipped in code, custom allowed. */
@Serializable
data class DnsProvider(
    val id: String,
    val label: String,
    /** HTTPS URL for DoH (RFC 8484). */
    val dohUrl: String? = null,
    /** Host for DoT (port 853 assumed). */
    val dotHost: String? = null,
    /** Documentation URL shown to the user. */
    val docsUrl: String? = null,
    val supportsDnssec: Boolean = false,
    /** True if the provider filters (blocks) some domains. */
    val filters: Boolean = false
)

@Serializable
data class DnsConfig(
    val mode: DnsMode = DnsMode.DOH,
    val providerId: String = "cloudflare",
    /** Custom endpoints, used when providerId == "custom". */
    val customDohUrl: String = "",
    val customDotHost: String = "",
    /** Resolve DNS upstream through Tor (only meaningful with the Tor module on). */
    val viaTor: Boolean = false,
    /** Cache DNS answers locally. */
    val cache: Boolean = true,
    /** Block queries for new non-DNS UDP (QUIC etc.) — privacy default. */
    val blockNonDnsUdp: Boolean = true
) {
    val isCustom get() = providerId == "custom"
}

@Serializable
data class BridgeLine(
    /** Raw tor bridge line, e.g. "obfs4 1.2.3.4:443 cert=... iat-mode=0". */
    val line: String,
    val enabled: Boolean = true
)

@Serializable
data class TorConfig(
    /** Bundle Tor daemon and route the tunnel through it. */
    val enabled: Boolean = false,
    val bridges: List<BridgeLine> = emptyList(),
    val useBridges: Boolean = false,
    /** Selected built-in bridge set id (see BuiltinBridges), "" = custom list only. */
    val builtinBridgeSet: String = "",
    /** Extra raw torrc lines, validated against a safe allow-list. */
    val extraTorrc: List<String> = emptyList()
)

/**
 * Built-in public bridge lists (same distribution list Orbot ships, sourced
 * from Tor Project / Guardian Project). The JSON asset lives in the app;
 * parsing is pure and tested.
 */
object BuiltinBridges {
    val SETS = listOf(
        Set("snowflake", "Snowflake (built-in)", "WebRTC-domain-fronted; hardest to block, needs no invite"),
        Set("obfs4", "obfs4 (built-in)", "Public obfs4 bridges; moderate censorship resistance"),
        Set("meek", "meek_lite (built-in)", "CDN-fronted; slow, works in harsh networks")
    )

    data class Set(val id: String, val label: String, val description: String)

    /** Parses the builtin-bridges.json asset; returns id -> bridge lines. */
    fun parse(jsonText: String): Map<String, List<String>> {
        val obj = kotlinx.serialization.json.Json.parseToJsonElement(jsonText).let { it as kotlinx.serialization.json.JsonObject }
        val out = LinkedHashMap<String, List<String>>()
        for ((k, v) in obj) {
            val arr = (v as? kotlinx.serialization.json.JsonArray) ?: continue
            out[k] = arr.mapNotNull { (it as? kotlinx.serialization.json.JsonPrimitive)?.content }
        }
        return out
    }
}

/** Upstream for non-Tor tunnelled traffic. */
@Serializable
data class ProxyConfig(
    val host: String = "",
    val port: Int = 0,
    val username: String? = null,
    val password: String? = null
) {
    val isValid get() = host.isNotBlank() && port in 1..65535
}

@Serializable
data class VpnConfig(
    /** Apps that bypass the VPN entirely (unfiltered direct access). */
    val bypassUids: Set<Int> = emptySet(),
    /** Only route these UIDs through the tunnel; empty = all apps. */
    val includeOnlyUids: Set<Int> = emptySet(),
    /** Refuse connections instead of falling back to direct when upstream is down. */
    val strictNoFallback: Boolean = true
)

@Serializable
data class I2pConfig(
    /** Bundle and run the i2pd router (Purple I2P, BSD-3) and route through it. */
    val enabled: Boolean = false,
    /** Local SOCKS5 proxy of i2pd (serves *.i2p destinations). */
    val socksPort: Int = 4447,
    /** Local HTTP proxy of i2pd. */
    val httpProxyPort: Int = 4448,
    /** Local web console port (loopback only). */
    val webconsolePort: Int = 7070,
    /** SAM bridges (for apps speaking SAM). Off by default. */
    val samEnabled: Boolean = false,
    /** Accept tunnels (be a transit node). Off by default: least participation, least traffic. */
    val transitEnabled: Boolean = false,
    /** Share percentage when transit is enabled. */
    val sharePercent: Int = 25,
    /** Outproxy for clearnet hosts reached via I2P SOCKS (rarely available). */
    val outproxyUrl: String = "",
    /** Allow-listed extra i2pd.conf lines. */
    val extraOptions: List<String> = emptyList()
) {
    init {
        require(socksPort in 1..65535) { "socksPort" }
        require(httpProxyPort in 1..65535) { "httpProxyPort" }
        require(webconsolePort in 1..65535) { "webconsolePort" }
        require(sharePercent in 0..100) { "sharePercent" }
    }
}

@Serializable
data class AntiDpiConfig(
    /** Fragment TLS ClientHello across TCP writes (anti-DPI, handshake-safe). */
    val enabled: Boolean = false,
    /** Bytes per fragment (small = harder for DPI, slower). */
    val chunkSize: Int = 8
) {
    init { require(chunkSize in 1..64) { "chunkSize" } }
}

@Serializable
data class UmbralConfig(
    val defaultRoute: RouteAction = RouteAction.DIRECT,
    val appRules: Map<String, AppRule> = emptyMap(),
    val dns: DnsConfig = DnsConfig(),
    val tor: TorConfig = TorConfig(),
    val i2p: I2pConfig = I2pConfig(),
    val proxy: ProxyConfig = ProxyConfig(),
    val antiDpi: AntiDpiConfig = AntiDpiConfig(),
    val vpn: VpnConfig = VpnConfig(),
    val autoStartOnBoot: Boolean = false,
    val advancedMode: Boolean = false
)

/** Parse a pasted batch of bridge lines. Returns good lines + per-line errors. */
object BridgeBatch {
    val KNOWN = setOf("obfs2", "obfs3", "obfs4", "scramblesuit", "meek_lite", "snowflake", "webtunnel", "dnstt")

    data class Result(val bridges: List<BridgeLine>, val errors: List<String>)

    /** host:port forms: 1.2.3.4:9001, [2001:db8::1]:9001, example.com:9001 */
    private fun looksLikeAddressPort(s: String): Boolean {
        if (']' in s) return Regex("^\\[[0-9a-fA-F:.]+]:\\d+$").matches(s)
        if (s.count { it == ':' } != 1) return false
        val (host, port) = s.substringBeforeLast(':') to s.substringAfterLast(':')
        return port.toIntOrNull() in 1..65535 && host.isNotEmpty()
    }

    fun parse(text: String): Result {
        val bridges = ArrayList<BridgeLine>()
        val errors = ArrayList<String>()
        text.lineSequence().forEachIndexed { idx, raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEachIndexed
            val tokens = line.split(Regex("\\s+"))
            // Vanilla bridges: no pluggable transport — tor dials them directly.
            // Accepted shapes (what BridgesDB / bridges.torproject.org give):
            //   1.2.3.4:9001 4352E58420E68F5E40BF7C74F8CCD2CA4AE7E79A
            //   vanilla 1.2.3.4:9001 4352E... (explicit prefix, stripped)
            if (looksLikeAddressPort(tokens[0])) {
                if (tokens.size < 2) {
                    errors.add("line ${idx + 1}: vanilla bridge needs '<ip:port> <fingerprint>'")
                    return@forEachIndexed
                }
                bridges.add(BridgeLine(tokens.joinToString(" ")))
                return@forEachIndexed
            }
            if (tokens[0].equals("vanilla", ignoreCase = true)) {
                if (tokens.size < 3 || !looksLikeAddressPort(tokens[1])) {
                    errors.add("line ${idx + 1}: 'vanilla <ip:port> <fingerprint>' expected")
                    return@forEachIndexed
                }
                bridges.add(BridgeLine(tokens.drop(1).joinToString(" ")))
                return@forEachIndexed
            }
            val transport = tokens[0].lowercase()
            if (transport !in KNOWN) {
                errors.add("line ${idx + 1}: unknown transport '$transport' (need ${KNOWN.joinToString("/")} or a plain 'ip:port fingerprint' vanilla bridge)")
                return@forEachIndexed
            }
            if (tokens.size < 3) {
                errors.add("line ${idx + 1}: expected '<transport> <address[:port]> <fingerprint> [args]'")
                return@forEachIndexed
            }
            bridges.add(BridgeLine(line = line))
        }
        // dedupe
        val seen = HashSet<String>()
        val unique = bridges.filter { seen.add(it.line) }
        return Result(unique, errors)
    }
}

/** Preset profiles offered in the UI. Each is a full config transformation. */
enum class PresetId { PRIVACY_FIRST, TOR_ROUTING, I2P_ROUTING, DNS_FIREWALL, CUSTOM }

object Presets {
    fun apply(preset: PresetId, base: UmbralConfig): UmbralConfig = when (preset) {
        PresetId.PRIVACY_FIRST -> base.copy(
            defaultRoute = RouteAction.DIRECT,
            dns = base.dns.copy(mode = DnsMode.DOH, viaTor = false),
            tor = base.tor.copy(enabled = false),
            i2p = base.i2p.copy(enabled = false)
        )
        PresetId.TOR_ROUTING -> base.copy(
            defaultRoute = RouteAction.TOR,
            dns = base.dns.copy(mode = DnsMode.DOH, viaTor = true),
            tor = base.tor.copy(enabled = true),
            i2p = base.i2p.copy(enabled = false)
        )
        PresetId.I2P_ROUTING -> base.copy(
            defaultRoute = RouteAction.I2P,
            tor = base.tor.copy(enabled = false),
            i2p = base.i2p.copy(enabled = true)
        )
        PresetId.DNS_FIREWALL -> base.copy(
            defaultRoute = RouteAction.DIRECT,
            dns = base.dns.copy(mode = DnsMode.DOH),
            tor = base.tor.copy(enabled = false),
            i2p = base.i2p.copy(enabled = false)
        )
        PresetId.CUSTOM -> base
    }
}

/** Shipped DNS provider catalogue (facts verifiable at the provider docs). */
object DnsProviders {
    val ALL: List<DnsProvider> = listOf(
        DnsProvider(
            id = "cloudflare", label = "Cloudflare (1.1.1.1)",
            dohUrl = "https://cloudflare-dns.com/dns-query", dotHost = "one.one.one.one",
            docsUrl = "https://developers.cloudflare.com/1.1.1.1/privacy/", supportsDnssec = true
        ),
        DnsProvider(
            id = "quad9", label = "Quad9 (filtered, DNSSEC)",
            dohUrl = "https://dns.quad9.net/dns-query", dotHost = "dns.quad9.net",
            docsUrl = "https://quad9.net/privacy/", supportsDnssec = true, filters = true
        ),
        DnsProvider(
            id = "adguard", label = "AdGuard DNS (ad-blocking)",
            dohUrl = "https://dns.adguard-dns.com/dns-query", dotHost = "dns.adguard-dns.com",
            docsUrl = "https://adguard-dns.com/en/privacy.html", filters = true
        ),
        DnsProvider(
            id = "dnsforge", label = "DNSforge (Germany, no logging)",
            dohUrl = "https://dnsforge.de/dns-query", dotHost = "dnsforge.de",
            docsUrl = "https://dnsforge.de/#datenschutz"
        ),
        DnsProvider(
            id = "mullvad", label = "Mullvad (no logging)",
            dohUrl = "https://dns.mullvad.net/dns-query", dotHost = "dns.mullvad.net",
            docsUrl = "https://mullvad.net/help/no-logging-dns-server/"
        ),
        DnsProvider(id = "custom", label = "Custom…")
    )

    fun byId(id: String): DnsProvider? = ALL.firstOrNull { it.id == id }

    fun resolve(cfg: DnsConfig): DnsProvider = byId(cfg.providerId) ?: DnsProvider(
        id = "custom", label = "Custom…"
    )
}

/** One observed connection attempt, for the diagnostics screen. */
data class ConnectionEvent(
    val timestampMs: Long,
    val uid: Int,
    val protocol: String,
    val source: String,
    val destination: String,
    val action: RouteAction?,
    val blocked: Boolean,
    val detail: String = ""
)

/** High level module states surfaced on the dashboard. */
enum class ModuleState { OFF, STARTING, ACTIVE, ERROR, STOPPING }
