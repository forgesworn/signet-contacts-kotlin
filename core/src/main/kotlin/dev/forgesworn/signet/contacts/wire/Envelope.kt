package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.internal.Js
import dev.forgesworn.signet.contacts.internal.Random
import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonNumber
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.isNumber
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.str
import dev.forgesworn.signet.contacts.json.toJson
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.coroutines.cancellation.CancellationException

/**
 * Vault envelope v2, format-mirrored byte for byte from signet-app (R-4).
 * `content` is the JSON `{v:2,k,iv,ct,b}`: `k` is the NIP-44 ciphertext of the
 * base64 AES-256-GCM content key, `iv`/`ct` are base64, and `b` is the bucket
 * the plaintext was padded to (4-byte big-endian length prefix, UTF-8 body,
 * zero fill). There is no legacy fallback: anything else opens to null.
 */

public val BUCKETS: List<Int> = listOf(4096, 8192, 16384, 32768, 65536)
public val TOP_BUCKET: Int = BUCKETS.last()
public const val LENGTH_PREFIX_BYTES: Int = 4

/** Hard cap on the `content` string this SDK will even attempt to parse. */
public const val MAX_ENVELOPE_CHARS: Int = 100_000

private const val IV_LENGTH = 12
private const val GCM_TAG_BITS = 128
private val LOWERCASE_HEX_64 = Regex("^[0-9a-f]{64}$")

public data class VaultEnvelope(val k: String, val iv: String, val ct: String, val b: Int) {
    public val v: Int get() = 2

    public fun toJson(): JsonObject = jsonObject(
        "v" to 2.toJson(), "k" to k.toJson(), "iv" to iv.toJson(), "ct" to ct.toJson(), "b" to b.toJson(),
    )
}

/** What [sealVaultPayload] needs from a signer. */
public fun interface SealEnvelopeBackend {
    public suspend fun nip44Encrypt(peerPubkey: String, plaintext: String): String
}

/** What [openVaultPayload] needs from a signer. */
public fun interface OpenEnvelopeBackend {
    public suspend fun nip44Decrypt(peerPubkey: String, ciphertext: String): String
}

/**
 * Length-prefix [plaintext] and zero-pad it to the smallest bucket that fits,
 * or null when it does not fit [maxBucket]. Never truncates.
 */
public fun padToBucket(plaintext: String, maxBucket: Int = TOP_BUCKET): ByteArray? {
    val body = Js.utf8(plaintext)
    val needed = LENGTH_PREFIX_BYTES + body.size
    val bucket = BUCKETS.firstOrNull { it >= needed && it <= maxBucket } ?: return null
    val out = ByteArray(bucket)
    val n = body.size
    out[0] = (n ushr 24).toByte()
    out[1] = (n ushr 16).toByte()
    out[2] = (n ushr 8).toByte()
    out[3] = n.toByte()
    System.arraycopy(body, 0, out, LENGTH_PREFIX_BYTES, n)
    body.fill(0)
    return out
}

/** Reverse [padToBucket]; null for a malformed or truncated buffer. */
public fun unpad(padded: ByteArray): String? {
    if (padded.size < LENGTH_PREFIX_BYTES) return null
    val length = ((padded[0].toLong() and 0xff) shl 24) or ((padded[1].toLong() and 0xff) shl 16) or
        ((padded[2].toLong() and 0xff) shl 8) or (padded[3].toLong() and 0xff)
    if (length > padded.size - LENGTH_PREFIX_BYTES) return null
    return Js.utf8Decode(padded, LENGTH_PREFIX_BYTES, length.toInt())
}

/** Shape-check a `content` string as a v2 envelope. The size cap is checked
 *  BEFORE parsing. */
public fun parseVaultEnvelope(content: String): VaultEnvelope? {
    if (content.length > MAX_ENVELOPE_CHARS) return null
    val e = Json.parseOrNull(content) as? JsonObject ?: return null
    if (!e["v"].isNumber(2)) return null
    val k = e["k"].str() ?: return null
    val iv = e["iv"].str() ?: return null
    val ct = e["ct"].str() ?: return null
    val b = (e["b"] as? JsonNumber)?.value ?: return null
    val bucket = BUCKETS.firstOrNull { it.toDouble() == b } ?: return null
    return VaultEnvelope(k, iv, ct, bucket)
}

private fun aesGcm(mode: Int, key: ByteArray, iv: ByteArray, input: ByteArray): ByteArray {
    require(key.size == 32) { "signet-contacts: invalid AES key length" }
    val spec = SecretKeySpec(key, "AES")
    return Cipher.getInstance("AES/GCM/NoPadding").run {
        init(mode, spec, GCMParameterSpec(GCM_TAG_BITS, iv))
        doFinal(input)
    }
}

/**
 * Seal [plaintext] into a v2 envelope string, or null when it exceeds the top
 * bucket (or [maxBucket]), [recipientPubkey] is not strict lowercase 64-hex,
 * or anything fails. [random] is injectable for frozen vectors; production
 * callers omit it. The raw key and padded body are zeroed on every path.
 */
public suspend fun sealVaultPayload(
    plaintext: String,
    backend: SealEnvelopeBackend,
    recipientPubkey: String,
    maxBucket: Int = TOP_BUCKET,
    random: (Int) -> ByteArray = Random::bytes,
): String? {
    if (!LOWERCASE_HEX_64.matches(recipientPubkey)) return null
    val padded = padToBucket(plaintext, maxBucket) ?: return null
    val rawKey = random(32)
    try {
        if (rawKey.size != 32) return null
        val iv = random(IV_LENGTH)
        if (iv.size != IV_LENGTH) return null
        val ciphertext = aesGcm(Cipher.ENCRYPT_MODE, rawKey, iv, padded)
        val wrapped = backend.nip44Encrypt(recipientPubkey, Js.base64(rawKey))
        return VaultEnvelope(wrapped, Js.base64(iv), Js.base64(ciphertext), padded.size).toJson().stringify()
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        return null
    } finally {
        rawKey.fill(0)
        padded.fill(0)
    }
}

/**
 * Open a v2 envelope. Null on ANY failure: tampered ciphertext, wrong key,
 * malformed padding, a relabelled bucket, a backend that threw or returned
 * rubbish, or a `content` that is not a v2 envelope at all.
 */
public suspend fun openVaultPayload(content: String, backend: OpenEnvelopeBackend, senderPubkey: String): String? {
    val envelope = parseVaultEnvelope(content) ?: return null
    var rawKey: ByteArray? = null
    var padded: ByteArray? = null
    try {
        val wrappedKeyPlaintext = backend.nip44Decrypt(senderPubkey, envelope.k)
        rawKey = Js.forgivingBase64(wrappedKeyPlaintext) ?: return null
        if (rawKey.size != 32) return null
        val iv = Js.forgivingBase64(envelope.iv) ?: return null
        val ct = Js.forgivingBase64(envelope.ct) ?: return null
        if (iv.isEmpty()) return null
        padded = aesGcm(Cipher.DECRYPT_MODE, rawKey, iv, ct)
        // A bucket that does not match what came out was relabelled: a rewrite, not a read.
        if (padded.size != envelope.b) return null
        return unpad(padded)
    } catch (e: CancellationException) {
        throw e
    } catch (_: Exception) {
        return null
    } finally {
        rawKey?.fill(0)
        padded?.fill(0)
    }
}
