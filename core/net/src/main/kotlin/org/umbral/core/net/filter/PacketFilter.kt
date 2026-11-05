package org.umbral.core.net.filter

import org.umbral.core.model.RoutingPolicy
import org.umbral.core.net.pkt.IpCodec

/**
 * Pure packet filtering brain, fed with parsed IP packets by the VPN pump.
 *
 * Verdicts:
 *  - PASS            forward packet to the tun2socks engine (hev)
 *  - DROP            discard silently (blocked app / non-DNS UDP policy)
 *  - DNS_LOCAL       hand payload to the local DNS engine; the pump writes the
 *                    generated response back to the TUN fd
 *  - RESET           blocked TCP SYN: emit a TCP RST so the app fails fast
 *                    instead of hanging on a silent timeout
 */
sealed class Verdict {
    data object Pass : Verdict()
    data object Drop : Verdict()
    data object DnsLocal : Verdict()
    data object Reset : Verdict()
}

data class FilterContext(
    /** DNS server addresses configured on the VPN (queries to these are intercepted). */
    val vpnDnsIps: Set<String>,
    val localV4: String,
    val localV6: String,
    /** UID of the app owning the connection, or -1 when unknown. */
    val uid: Int,
    /** Current network kind for rule resolution. */
    val netKind: org.umbral.core.model.NetKind
)

class PacketFilter(private val policy: RoutingPolicy, private val config: () -> org.umbral.core.model.UmbralConfig) {

    fun decide(pkt: IpCodec.IpHeader, ctx: FilterContext): Verdict {
        val cfg = config()
        // Non-TCP/UDP (ICMP etc.): drop; hev optionally answers ping itself.
        if (pkt.protocol != IpCodec.IPPROTO_TCP && pkt.protocol != IpCodec.IPPROTO_UDP) {
            return Verdict.Drop
        }

        if (pkt.protocol == IpCodec.IPPROTO_UDP) {
            val udp = pkt.udp ?: return Verdict.Drop
            return when {
                // Any plaintext :53 inside the tunnel is intercepted locally:
                // this covers the VPN resolver address and prevents leaks to
                // resolvers the network tried to push on the device.
                udp.dstPort == 53 -> Verdict.DnsLocal
                cfg.dns.blockNonDnsUdp -> Verdict.Drop
                else -> Verdict.Pass
            }
        }

        // TCP
        val tunneled = policy.isTunneled(ctx.uid)
        val decision = policy.resolve(ctx.uid, ctx.netKind, tunneled)
        return when (decision.action) {
            org.umbral.core.model.RouteAction.BLOCK ->
                if (pkt.tcp?.isSyn == true) Verdict.Reset else Verdict.Drop
            else -> Verdict.Pass
        }
    }
}
