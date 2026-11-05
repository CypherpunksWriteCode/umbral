package org.umbral.core.config

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.umbral.core.model.UmbralConfig
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey

/**
 * Single source of truth for user configuration.
 * Storage is local only (DataStore file in app-private storage); nothing here
 * ever leaves the device unless the user explicitly exports it.
 */
class ConfigRepository(
    private val store: DataStore<Preferences>,
    private val clock: () -> Long = { System.currentTimeMillis() }
) {
    private val json = Json {
        ignoreUnknownKeys = false
        encodeDefaults = true
        prettyPrint = false
    }
    private val key = stringPreferencesKey("umbral_config_json")

    val config: Flow<UmbralConfig> = store.data.map { p ->
        p[key]?.let { decode(it) } ?: UmbralConfig()
    }

    suspend fun current(): UmbralConfig =
        store.data.first()[key]?.let { decode(it) } ?: UmbralConfig()

    suspend fun update(transform: (UmbralConfig) -> UmbralConfig) {
        store.edit { p ->
            val cur = p[key]?.let { decode(it) } ?: UmbralConfig()
            p[key] = json.encodeToString(transform(cur))
        }
    }

    suspend fun replace(config: UmbralConfig) {
        store.edit { p -> p[key] = json.encodeToString(config) }
    }

    fun export(config: UmbralConfig): String = json.encodeToString(config)

    /** Parses and validates an exported configuration. Throws on malformed input. */
    fun import(text: String): UmbralConfig {
        val trimmed = text.trim()
        require(trimmed.isNotEmpty()) { "empty configuration" }
        return decode(trimmed)
    }

    private fun decode(s: String): UmbralConfig = try {
        json.decodeFromString(s)
    } catch (e: IllegalArgumentException) {
        throw ConfigException("configuration is not valid Umbral JSON: ${e.message}", e)
    }
}

class ConfigException(message: String, cause: Throwable? = null) : Exception(message, cause)
