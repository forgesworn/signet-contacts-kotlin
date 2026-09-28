package dev.forgesworn.signet.contacts.nostr

import dev.forgesworn.signet.contacts.nostr.internal.ChaCha20
import dev.forgesworn.signet.contacts.nostr.internal.hmacSha256
import dev.forgesworn.signet.contacts.nostr.internal.utf8
import fr.acinq.secp256k1.Secp256k1
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * NIP-44 v2, as nostr-tools implements it: ECDH x-coordinate, HKDF-extract
 * with salt `nip44-v2` for the conversation key, HKDF-expand per message into
 * a ChaCha20 key and nonce and an HMAC key, power-of-two padding, and
 * `base64(0x02 || nonce || ciphertext || mac)`.
 */
public object Nip44 {
    private val rng = SecureRandom()
    private const val MIN_PLAINTEXT = 1
    private const val MAX_PLAINTEXT = 65535

    /** The 32-byte conversation key between [secretKey] and x-only [peerPubkey]. The caller zeroises it. */
    public fun conversationKey(secretKey: ByteArray, peerPubkey: String): ByteArray {
        val point = Secp256k1.get().pubKeyTweakMul(Secp256k1.get().pubkeyParse(byteArrayOf(2) + NostrKeys.unhex(peerPubkey)), secretKey)
        val sharedX = point.copyOfRange(1, 33)
        try {
            return hmacSha256(utf8("nip44-v2"), sharedX) // HKDF-extract
        } finally {
            sharedX.fill(0)
        }
    }

    private fun messageKeys(conversationKey: ByteArray, nonce: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        require(conversationKey.size == 32) { "invalid conversation key length" }
        require(nonce.size == 32) { "invalid nonce length" }
        // HKDF-expand to 76 bytes: three HMAC blocks.
        val okm = ByteArray(96)
        var previous = ByteArray(0)
        for (i in 1..3) {
            previous = hmacSha256(conversationKey, previous, nonce, byteArrayOf(i.toByte()))
            previous.copyInto(okm, (i - 1) * 32)
        }
        val keys = Triple(okm.copyOfRange(0, 32), okm.copyOfRange(32, 44), okm.copyOfRange(44, 76))
        okm.fill(0)
        previous.fill(0)
        return keys
    }

    internal fun paddedLength(unpadded: Int): Int {
        if (unpadded <= 32) return 32
        val nextPower = 1 shl (32 - Integer.numberOfLeadingZeros(unpadded - 1))
        val chunk = if (nextPower <= 256) 32 else nextPower / 8
        return chunk * ((unpadded - 1) / chunk + 1)
    }

    private fun pad(plaintext: String): ByteArray {
        val bytes = utf8(plaintext)
        require(bytes.size in MIN_PLAINTEXT..MAX_PLAINTEXT) { "invalid plaintext size: must be between 1 and 65535 bytes" }
        val out = ByteArray(2 + paddedLength(bytes.size))
        out[0] = (bytes.size ushr 8).toByte()
        out[1] = bytes.size.toByte()
        bytes.copyInto(out, 2)
        bytes.fill(0)
        return out
    }

    private fun unpad(padded: ByteArray): String {
        val length = ((padded[0].toInt() and 0xff) shl 8) or (padded[1].toInt() and 0xff)
        require(length in MIN_PLAINTEXT..MAX_PLAINTEXT && padded.size == 2 + paddedLength(length)) { "invalid padding" }
        return String(padded, 2, length, Charsets.UTF_8)
    }

    /** Encrypt [plaintext]. [nonce] is injectable for test vectors only. */
    public fun encrypt(plaintext: String, conversationKey: ByteArray, nonce: ByteArray = ByteArray(32).also(rng::nextBytes)): String {
        val (chachaKey, chachaNonce, hmacKey) = messageKeys(conversationKey, nonce)
        val padded = pad(plaintext)
        try {
            val ciphertext = ChaCha20.xor(chachaKey, chachaNonce, padded)
            val mac = hmacSha256(hmacKey, nonce, ciphertext)
            return Base64.getEncoder().encodeToString(byteArrayOf(2) + nonce + ciphertext + mac)
        } finally {
            chachaKey.fill(0); hmacKey.fill(0); padded.fill(0)
        }
    }

    /** Decrypt a NIP-44 v2 payload; throws [IllegalArgumentException] on anything invalid. */
    public fun decrypt(payload: String, conversationKey: ByteArray): String {
        require(payload.isNotEmpty() && payload[0] != '#') { "unknown encryption version" }
        require(payload.length in 132..87472) { "invalid payload length: ${payload.length}" }
        val data = try {
            Base64.getDecoder().decode(payload)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("invalid base64")
        }
        require(data.size in 99..65603) { "invalid data length: ${data.size}" }
        require(data[0].toInt() == 2) { "unknown encryption version ${data[0]}" }
        val nonce = data.copyOfRange(1, 33)
        val ciphertext = data.copyOfRange(33, data.size - 32)
        val mac = data.copyOfRange(data.size - 32, data.size)
        val (chachaKey, chachaNonce, hmacKey) = messageKeys(conversationKey, nonce)
        try {
            val expected = hmacSha256(hmacKey, nonce, ciphertext)
            require(MessageDigest.isEqual(expected, mac)) { "invalid MAC" }
            val padded = ChaCha20.xor(chachaKey, chachaNonce, ciphertext)
            try {
                return unpad(padded)
            } finally {
                padded.fill(0)
            }
        } finally {
            chachaKey.fill(0); hmacKey.fill(0)
        }
    }
}
