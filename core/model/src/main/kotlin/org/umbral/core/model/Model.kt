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
    /** Extra raw torrc lines, validated against a safe allow-list. */
    val extraTorrc: List<String> = emptyList()
)

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
data class UmbralConfig(
    val defaultRoute: RouteAction = RouteAction.DIRECT,
    val appRules: Map<String, AppRule> = emptyMap(),
    val dns: DnsConfig = DnsConfig(),
    val tor: TorConfig = TorConfig(),
    val i2p: I2pConfig = I2pConfig(),
    val proxy: ProxyConfig = ProxyConfig(),
    val vpn: VpnConfig = VpnConfig(),
    val autoStartOnBoot: Boolean = false,
    val advancedMode: Boolean = false
)

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
