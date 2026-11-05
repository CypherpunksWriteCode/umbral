package org.umbral.core.config

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Passphrase-based encryption for exported configurations.
 * AES-256-GCM with a PBKDF2-HMAC-SHA256 derived key, random 128-bit salt and
 * 96-bit IV per export. Only standard JCA algorithms — no custom crypto.
 *
 * Format: UMBRAL1:<base64(salt)>:<base64(iv)>:<base64(ciphertext+tag)>
 */
object ConfigVault {
    private const val FORMAT = "UMBRAL1"
    private const val SALT_BYTES = 16
    private const val IV_BYTES = 12
    private const val KEY_BITS = 256
    private const val TAG_BITS = 128
    private const val PBKDF2_ITERATIONS = 210_000 // OWASP 2023 guidance for PBKDF2-HMAC-SHA256

    fun encrypt(plaintext: String, passphrase: CharArray): String {
        require(passphrase.isNotEmpty()) { "empty passphrase" }
        val rnd = SecureRandom()
        val salt = ByteArray(SALT_BYTES).also { rnd.nextBytes(it) }
        val iv = ByteArray(IV_BYTES).also { rnd.nextBytes(it) }
        val key = deriveKey(passphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
        return listOf(
            FORMAT,
            b64(salt), b64(iv), b64(ct)
        ).joinToString(":")
    }

    fun decrypt(blob: String, passphrase: CharArray): String {
        val parts = blob.trim().split(":")
        require(parts.size == 4 && parts[0] == FORMAT) { "not an encrypted Umbral export" }
        val salt = unb64(parts[1])
        val iv = unb64(parts[2])
        val ct = unb64(parts[3])
        require(salt.size == SALT_BYTES) { "bad salt" }
        require(iv.size == IV_BYTES) { "bad iv" }
        val key = deriveKey(passphrase, salt)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, iv))
        return String(cipher.doFinal(ct), Charsets.UTF_8)
    }

    fun isEncryptedExport(text: String): Boolean =
        text.trim().startsWith("$FORMAT:")

    private fun deriveKey(passphrase: CharArray, salt: ByteArray): SecretKeySpec {
        val spec = PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEY_BITS)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val key = factory.generateSecret(spec).encoded
        spec.clearPassword()
        return SecretKeySpec(key, "AES")
    }

    private fun b64(b: ByteArray) = java.util.Base64.getEncoder().encodeToString(b)
    private fun unb64(s: String) = java.util.Base64.getDecoder().decode(s)
}
