package org.umbral.core.model

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class BuiltinBridgesTest {

    private val sample = """
        {
          "meek": ["meek_lite 192.0.2.20:80 url=https://example.com front=example.net"],
          "obfs4": [
            "obfs4 212.83.43.74:443 39562501228A4D5E27FCA4C0C81A01EE23AE3EE4 cert=PBwr iat-mode=1",
            "obfs4 146.57.248.225:22 10A6CD36A537FCE513A322361547444B393989F0 cert=K1gDtDAIcUfeLqbstggjIw2rtgIKqdIhUlHp82XRqNSq iat-mode=0"
          ],
          "snowflake": ["snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/"]
        }
    """.trimIndent()

    @Test
    fun `parses sets and lines`() {
        val sets = BuiltinBridges.parse(sample)
        assertEquals(setOf("meek", "obfs4", "snowflake"), sets.keys)
        assertEquals(2, sets["obfs4"]!!.size)
        assertTrue(sets["snowflake"]!!.first().startsWith("snowflake "))
    }

    @Test
    fun `all builtin lines pass batch validation`() {
        // every shipped builtin line must be valid for BridgeBatch/torrc
        val sets = BuiltinBridges.parse(sample)
        sets.values.flatten().forEach { line ->
            val transport = line.substringBefore(' ')
            assertTrue("unknown transport $transport", transport in BridgeBatch.KNOWN)
        }
    }

    @Test
    fun `empty json yields empty map`() {
        assertEquals(emptyMap<String, List<String>>(), BuiltinBridges.parse("{}"))
    }
}
