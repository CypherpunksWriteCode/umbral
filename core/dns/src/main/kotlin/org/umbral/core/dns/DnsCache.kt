package org.umbral.core.dns

import java.util.concurrent.ConcurrentHashMap

/** TTL-aware answer cache keyed by (name,type). */
class DnsCache(private val clock: () -> Long = { System.currentTimeMillis() }) {
    private data class Entry(val ips: List<String>, val expiresAtMs: Long, val ttlSeconds: Long)

    private val map = ConcurrentHashMap<String, Entry>()

    fun get(name: String, type: Int): List<String>? {
        val e = map[key(name, type)] ?: return null
        if (clock() >= e.expiresAtMs) {
            map.remove(key(name, type), e)
            return null
        }
        return e.ips
    }

    fun put(name: String, type: Int, ips: List<String>, ttlSeconds: Long) {
        if (ips.isEmpty() || ttlSeconds <= 0) return
        map[key(name, type)] = Entry(ips, clock() + ttlSeconds * 1000, ttlSeconds)
    }

    fun size() = map.size

    fun clear() = map.clear()

    private fun key(name: String, type: Int) = "$type|$${name.lowercase()}"
}
