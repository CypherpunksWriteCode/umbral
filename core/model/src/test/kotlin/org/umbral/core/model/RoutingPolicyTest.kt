package org.umbral.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RoutingPolicyTest {

    private fun config(
        default: RouteAction = RouteAction.DIRECT,
        rules: Map<String, AppRule> = emptyMap(),
        strict: Boolean = true,
        bypass: Set<Int> = emptySet(),
        includeOnly: Set<Int> = emptySet(),
        proxyValid: Boolean = false
    ) = UmbralConfig(
        defaultRoute = default,
        appRules = rules,
        vpn = VpnConfig(bypassUids = bypass, includeOnlyUids = includeOnly, strictNoFallback = strict),
        proxy = if (proxyValid) ProxyConfig("127.0.0.1", 1080) else ProxyConfig()
    )

    @Test
    fun `default route applies to unknown apps`() {
        val p = RoutingPolicy(config(default = RouteAction.TOR), { true }, { true })
        assertEquals(RouteAction.TOR, p.resolve(10432, NetKind.WIFI, true).action)
    }

    @Test
    fun `per-app rule beats default`() {
        val rules = mapOf("com.x" to AppRule(uid = 1000, wifi = RouteAction.BLOCK))
        val p = RoutingPolicy(config(default = RouteAction.DIRECT, rules = rules), { true }, { true })
        assertEquals(RouteAction.BLOCK, p.resolve(1000, NetKind.WIFI, true).action)
        assertEquals(RouteAction.DIRECT, p.resolve(1000, NetKind.MOBILE, true).action)
        assertEquals(RouteAction.DIRECT, p.resolve(1001, NetKind.WIFI, true).action)
    }

    @Test
    fun `tor unavailable with strict blocks instead of direct`() {
        val p = RoutingPolicy(config(default = RouteAction.TOR), { false }, { true })
        val d = p.resolve(1000, NetKind.WIFI, true)
        assertEquals(RouteAction.BLOCK, d.action)
        assertTrue(d.reason.contains("strict"))
    }

    @Test
    fun `tor unavailable without strict falls back to direct with warning`() {
        val p = RoutingPolicy(config(default = RouteAction.TOR, strict = false), { false }, { true })
        val d = p.resolve(1000, NetKind.WIFI, true)
        assertEquals(RouteAction.DIRECT, d.action)
        assertTrue(d.reason.contains("FELL BACK"))
    }

    @Test
    fun `invalid proxy config blocks in strict mode`() {
        val p = RoutingPolicy(config(default = RouteAction.PROXY, proxyValid = false), { true }, { true })
        assertEquals(RouteAction.BLOCK, p.resolve(1000, NetKind.WIFI, true).action)
    }

    @Test
    fun `valid proxy config routes to proxy`() {
        val p = RoutingPolicy(config(default = RouteAction.PROXY, proxyValid = true), { true }, { true })
        assertEquals(RouteAction.PROXY, p.resolve(1000, NetKind.WIFI, true).action)
    }

    @Test
    fun `bypass uid is not tunneled`() {
        val p = RoutingPolicy(config(bypass = setOf(1010)), { true }, { true })
        assertFalse(p.isTunneled(1010))
        assertTrue(p.isTunneled(1011))
    }

    @Test
    fun `includeOnly restricts tunnel membership`() {
        val p = RoutingPolicy(config(includeOnly = setOf(1010)), { true }, { true })
        assertTrue(p.isTunneled(1010))
        assertFalse(p.isTunneled(1011))
    }

    @Test
    fun `untunneled traffic is reported as direct`() {
        val p = RoutingPolicy(config(default = RouteAction.TOR), { true }, { true })
        val d = p.resolve(1000, NetKind.WIFI, false)
        assertEquals(RouteAction.DIRECT, d.action)
    }

    @Test
    fun `presets produce consistent configs`() {
        val base = UmbralConfig()
        val tor = Presets.apply(PresetId.TOR_ROUTING, base)
        assertEquals(RouteAction.TOR, tor.defaultRoute)
        assertTrue(tor.tor.enabled)
        assertTrue(tor.dns.viaTor)
    }
}
