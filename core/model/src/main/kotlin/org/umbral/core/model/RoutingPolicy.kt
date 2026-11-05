package org.umbral.core.model

/**
 * Pure routing policy. All inputs are explicit so this is fully unit-testable.
 *
 * Semantics:
 *  - An app in [VpnConfig.bypassUids] never reaches the tunnel; enforcement is
 *    done by VpnService allow/disallow lists before this engine runs.
 *  - If includeOnlyUids is non-empty, only those UIDs are tunneled.
 *  - App-specific rule (per network kind) wins over the default route.
 *  - Unknown UIDs get the default route.
 *  - [RouteAction.TOR] when Tor is not running and strictNoFallback is set
 *    degrades to BLOCK, never to DIRECT. This is the single most important
 *    safety property of the engine.
 */
class RoutingPolicy(
    private val config: UmbralConfig,
    private val torAvailable: () -> Boolean,
    private val proxyAvailable: () -> Boolean
) {
    fun resolve(uid: Int, net: NetKind, tunneled: Boolean): RouteDecision {
        if (!tunneled) {
            // Outside the tunnel the app already has direct, unfiltered access.
            return RouteDecision(RouteAction.DIRECT, "bypass VPN", uid)
        }
        val rule = config.appRules.values.firstOrNull { it.uid == uid }
        var action = rule?.forNetwork(net) ?: config.defaultRoute
        var reason = if (rule == null) "default route" else "app rule (${net.name.lowercase()})"
        if (action == RouteAction.TOR && !torAvailable()) {
            action = if (config.vpn.strictNoFallback) RouteAction.BLOCK
            else RouteAction.DIRECT
            reason += "; Tor unavailable -> " +
                (if (config.vpn.strictNoFallback) "blocked (strict, no fallback)" else "FELL BACK TO DIRECT (strict mode off)")
        }
        if (action == RouteAction.PROXY) {
            if (!config.proxy.isValid) {
                action = if (config.vpn.strictNoFallback) RouteAction.BLOCK else RouteAction.DIRECT
                reason += "; proxy invalid -> " +
                    (if (config.vpn.strictNoFallback) "blocked" else "direct fallback")
            } else if (!proxyAvailable()) {
                action = if (config.vpn.strictNoFallback) RouteAction.BLOCK else RouteAction.DIRECT
                reason += "; proxy unreachable -> " +
                    (if (config.vpn.strictNoFallback) "blocked" else "direct fallback")
            }
        }
        return RouteDecision(action, reason, if (rule != null) uid else -1)
    }

    fun isTunneled(uid: Int): Boolean {
        if (config.vpn.bypassUids.contains(uid)) return false
        if (config.vpn.includeOnlyUids.isNotEmpty() && !config.vpn.includeOnlyUids.contains(uid)) return false
        return true
    }
}
