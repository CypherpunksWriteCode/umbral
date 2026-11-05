package org.umbral.core.config

import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.umbral.core.model.AppRule
import org.umbral.core.model.DnsMode
import org.umbral.core.model.RouteAction
import org.umbral.core.model.UmbralConfig

class ConfigRepositoryTest {

    @get:Rule val tmp = TemporaryFolder()
    private lateinit var scope: CoroutineScope
    private lateinit var repo: ConfigRepository

    @Before
    fun setUp() {
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val file = tmp.newFile("test.preferences_pb")
        val store = PreferenceDataStoreFactory.create(scope = scope) { file }
        repo = ConfigRepository(store)
    }

    @After
    fun tearDown() {
        scope.cancel()
    }

    @Test
    fun `defaults on empty store`() = runBlocking {
        assertEquals(UmbralConfig(), repo.current())
    }

    @Test
    fun `update persists and flows`() = runBlocking {
        repo.update { it.copy(defaultRoute = RouteAction.TOR, advancedMode = true) }
        assertEquals(RouteAction.TOR, repo.config.first().defaultRoute)
        assertTrue(repo.current().advancedMode)
    }

    @Test
    fun `export import roundtrip preserves rules`() = runBlocking {
        val cfg = UmbralConfig(
            dns = UmbralConfig().dns.copy(mode = DnsMode.DOT, providerId = "quad9"),
            appRules = mapOf("a.b.c" to AppRule(10222, wifi = RouteAction.BLOCK)),
            vpn = UmbralConfig().vpn.copy(bypassUids = setOf(10222))
        )
        val text = repo.export(cfg)
        val parsed = repo.import(text)
        assertEquals(cfg, parsed)
    }

    @Test(expected = ConfigException::class)
    fun `import rejects garbage`() {
        repo.import("this is not json {{{")
    }

    @Test(expected = ConfigException::class)
    fun `import rejects wrong schema`() {
        repo.import("""{"hello":"world"}""")
    }
}

class ConfigVaultTest {

    @Test
    fun `encrypt decrypt roundtrip`() {
        val blob = ConfigVault.encrypt("""{"defaultRoute":"TOR"}""", "correct horse".toCharArray())
        assertTrue(blob.startsWith("UMBRAL1:"))
        assertEquals("""{"defaultRoute":"TOR"}""", ConfigVault.decrypt(blob, "correct horse".toCharArray()))
    }

    @Test(expected = Exception::class)
    fun `wrong passphrase fails`() {
        val blob = ConfigVault.encrypt("secret", "right".toCharArray())
        ConfigVault.decrypt(blob, "wrong".toCharArray())
    }

    @Test
    fun `same plaintext different ciphertext`() {
        val a = ConfigVault.encrypt("data", "pw".toCharArray())
        val b = ConfigVault.encrypt("data", "pw".toCharArray())
        assertTrue(a != b) // random salt+iv
    }

    @Test(expected = IllegalArgumentException::class)
    fun `empty passphrase rejected`() {
        ConfigVault.encrypt("data", CharArray(0))
    }
}
