package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.toJson
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private val SENDER = "a".repeat(64)
private val RECIPIENT = "b".repeat(64)

/**
 * A fake, reversible NIP-44: the envelope treats `k`'s ciphertext as opaque and
 * never itself checks who a peer argument names. Records calls the way the
 * TypeScript reference's `vi.fn` mock does, so a test can assert on them.
 */
private class FakeBackend(
    private val encryptImpl: suspend (String, String) -> String = { _, plaintext ->
        java.util.Base64.getEncoder().encodeToString(plaintext.toByteArray(Charsets.UTF_8))
    },
    private val decryptImpl: suspend (String, String) -> String = { _, ciphertext ->
        String(java.util.Base64.getDecoder().decode(ciphertext), Charsets.UTF_8)
    },
) : SealEnvelopeBackend, OpenEnvelopeBackend {
    val encryptCalls = mutableListOf<Pair<String, String>>()
    val decryptCalls = mutableListOf<Pair<String, String>>()

    override suspend fun nip44Encrypt(peerPubkey: String, plaintext: String): String {
        encryptCalls.add(peerPubkey to plaintext)
        return encryptImpl(peerPubkey, plaintext)
    }

    override suspend fun nip44Decrypt(peerPubkey: String, ciphertext: String): String {
        decryptCalls.add(peerPubkey to ciphertext)
        return decryptImpl(peerPubkey, ciphertext)
    }
}

private fun flipBase64Byte(b64: String): String {
    val bytes = java.util.Base64.getDecoder().decode(b64)
    bytes[0] = (bytes[0].toInt() xor 0x01).toByte()
    return java.util.Base64.getEncoder().encodeToString(bytes)
}

class EnvelopeTest {
    @Test
    fun `BUCKETS is the power-of-two ladder from 4 KiB to 64 KiB`() {
        assertEquals(listOf(4096, 8192, 16384, 32768, 65536), BUCKETS)
        assertEquals(65536, TOP_BUCKET)
        assertEquals(4, LENGTH_PREFIX_BYTES)
        assertEquals(100_000, MAX_ENVELOPE_CHARS)
    }

    @Test
    fun `padToBucket-unpad round-trips every bucket, including the top`() {
        for (bucket in BUCKETS) {
            val body = "x".repeat(bucket - LENGTH_PREFIX_BYTES)
            val padded = padToBucket(body)!!
            assertEquals(bucket, padded.size)
            assertEquals(body, unpad(padded))
        }
    }

    @Test
    fun `padToBucket returns null above the top bucket rather than truncating`() {
        assertNotNull(padToBucket("x".repeat(TOP_BUCKET - LENGTH_PREFIX_BYTES)))
        assertNull(padToBucket("x".repeat(TOP_BUCKET - LENGTH_PREFIX_BYTES + 1)))
    }

    @Test
    fun `unpad rejects a truncated buffer and a length prefix past the end`() {
        assertNull(unpad(ByteArray(3)))
        val bad = ByteArray(16)
        bad[2] = (999 ushr 8).toByte()
        bad[3] = (999 and 0xff).toByte()
        assertNull(unpad(bad))
    }

    @Test
    fun `parseVaultEnvelope accepts a well-formed envelope`() {
        val raw = """{"v":2,"k":"a","iv":"b","ct":"c","b":4096}"""
        assertEquals(VaultEnvelope("a", "b", "c", 4096), parseVaultEnvelope(raw))
    }

    @Test
    fun `parseVaultEnvelope rejects malformed shapes`() {
        assertNull(parseVaultEnvelope("not json"))
        assertNull(parseVaultEnvelope("[]"))
        assertNull(parseVaultEnvelope("""{"v":1,"k":"a","iv":"b","ct":"c","b":4096}"""))
        assertNull(parseVaultEnvelope("""{"v":2,"k":1,"iv":"b","ct":"c","b":4096}"""))
        assertNull(parseVaultEnvelope("""{"v":2,"k":"a","iv":"b","ct":"c","b":5000}"""))
    }

    // C1: the cap is checked BEFORE parsing - a hostile relay must not be able
    // to buy a large parse with an oversized `content` string.
    @Test
    fun `parseVaultEnvelope refuses an oversized content string before parsing it`() {
        val huge = """{"v":2,"k":"${"a".repeat(MAX_ENVELOPE_CHARS)}","iv":"b","ct":"c","b":4096}"""
        assertTrue(huge.length > MAX_ENVELOPE_CHARS)
        assertNull(parseVaultEnvelope(huge))
    }

    @Test
    fun `round-trips a small payload and wraps only the 32-byte key`() = runTest {
        val backend = FakeBackend()
        val sealed = sealVaultPayload("""{"hello":"world"}""", backend, RECIPIENT)!!
        val envelope = parseVaultEnvelope(sealed)!!
        assertEquals(2, envelope.v)
        assertEquals(4096, envelope.b)
        val wrappedArg = backend.encryptCalls[0].second
        assertEquals(32, java.util.Base64.getDecoder().decode(wrappedArg).size)
        assertEquals(RECIPIENT, backend.encryptCalls[0].first)
        assertEquals("""{"hello":"world"}""", openVaultPayload(sealed, backend, SENDER))
    }

    @Test
    fun `round-trips at every bucket boundary, including the top`() = runTest {
        val backend = FakeBackend()
        for (bucket in BUCKETS) {
            val body = "y".repeat(bucket - LENGTH_PREFIX_BYTES)
            val sealed = sealVaultPayload(body, backend, RECIPIENT)!!
            assertEquals(bucket, parseVaultEnvelope(sealed)!!.b)
            assertEquals(body, openVaultPayload(sealed, backend, SENDER))
        }
    }

    @Test
    fun `returns null above the top bucket rather than truncating, without touching the backend`() = runTest {
        val backend = FakeBackend()
        assertNull(sealVaultPayload("z".repeat(TOP_BUCKET), backend, RECIPIENT))
        assertEquals(0, backend.encryptCalls.size)
    }

    @Test
    fun `honours an explicit lower ceiling`() = runTest {
        val backend = FakeBackend()
        assertNull(sealVaultPayload("z".repeat(5000), backend, RECIPIENT, maxBucket = 4096))
        assertNotNull(sealVaultPayload("z".repeat(100), backend, RECIPIENT, maxBucket = 4096))
    }

    // Residuals fix #4, matching the app's Task 23 `activePublicKeyHex` guard.
    @Test
    fun `refuses a recipientPubkey that is not strict lowercase 64-hex, without touching the backend`() = runTest {
        for (bad in listOf("", "a".repeat(63), "a".repeat(65), "A".repeat(64), "z".repeat(64), "nostr:npub1x")) {
            val backend = FakeBackend()
            assertNull(sealVaultPayload("refuse me", backend, bad))
            assertEquals(0, backend.encryptCalls.size)
        }
    }

    @Test
    fun `uses fresh content key material and IV per seal`() = runTest {
        val backend = FakeBackend()
        val first = parseVaultEnvelope(sealVaultPayload("same", backend, RECIPIENT)!!)!!
        val second = parseVaultEnvelope(sealVaultPayload("same", backend, RECIPIENT)!!)!!
        assertNotEquals(first.k, second.k)
        assertNotEquals(first.iv, second.iv)
        assertNotEquals(first.ct, second.ct)
    }

    @Test
    fun `accepts injected randomness for a deterministic seal (vector generation)`() = runTest {
        val backend = FakeBackend()
        val fixed: (Int) -> ByteArray = { n -> ByteArray(n) { 7 } }
        val a = sealVaultPayload("deterministic", backend, RECIPIENT, random = fixed)
        val b = sealVaultPayload("deterministic", backend, RECIPIENT, random = fixed)
        assertEquals(a, b)
    }

    // C2 / no-throw-on-garbage.
    @Test
    fun `never throws on garbage content, returning null instead`() = runTest {
        val backend = FakeBackend()
        for (garbage in listOf("", "not json", "{}", "[]", "null", "\"x\"", "12345", "{\"v\":2}")) {
            assertNull(openVaultPayload(garbage, backend, SENDER))
        }
    }

    @Test
    fun `refuses an oversized content string before ever calling the backend`() = runTest {
        val backend = FakeBackend()
        val huge = "z".repeat(MAX_ENVELOPE_CHARS + 1)
        assertNull(openVaultPayload(huge, backend, SENDER))
        assertEquals(0, backend.decryptCalls.size)
    }

    private suspend fun sealedEnvelope(backend: FakeBackend): VaultEnvelope =
        parseVaultEnvelope(sealVaultPayload("tamper target", backend, RECIPIENT)!!)!!

    @Test
    fun `tamper rejection - rejects a flipped ciphertext byte`() = runTest {
        val backend = FakeBackend()
        val e = sealedEnvelope(backend)
        val tampered = e.copy(ct = flipBase64Byte(e.ct)).toJson().stringify()
        assertNull(openVaultPayload(tampered, backend, SENDER))
    }

    @Test
    fun `tamper rejection - rejects a flipped IV byte`() = runTest {
        val backend = FakeBackend()
        val e = sealedEnvelope(backend)
        val tampered = e.copy(iv = flipBase64Byte(e.iv)).toJson().stringify()
        assertNull(openVaultPayload(tampered, backend, SENDER))
    }

    @Test
    fun `tamper rejection - rejects a swapped wrapped key (k) from a different envelope`() = runTest {
        val backend = FakeBackend()
        val mine = sealedEnvelope(backend)
        val theirsSealed = sealVaultPayload("theirs", backend, RECIPIENT)!!
        val theirs = parseVaultEnvelope(theirsSealed)!!
        val tampered = mine.copy(k = theirs.k).toJson().stringify()
        assertNull(openVaultPayload(tampered, backend, SENDER))
    }

    @Test
    fun `tamper rejection - rejects a version bump`() = runTest {
        val backend = FakeBackend()
        val e = sealedEnvelope(backend)
        val fields = LinkedHashMap(e.toJson().fields)
        fields["v"] = 3.toJson()
        assertNull(openVaultPayload(JsonObject(fields).stringify(), backend, SENDER))
    }

    @Test
    fun `tamper rejection - rejects a relabelled bucket (b), even though it is a legal ladder value`() = runTest {
        val backend = FakeBackend()
        val e = sealedEnvelope(backend)
        val otherLadderBucket = BUCKETS.first { it != e.b }
        val tampered = e.copy(b = otherLadderBucket).toJson().stringify()
        assertNull(openVaultPayload(tampered, backend, SENDER))
    }

    @Test
    fun `tamper rejection - rejects a wrong-length content key`() = runTest {
        val sealed = sealVaultPayload("anything", FakeBackend(), RECIPIENT)!!
        val liar = FakeBackend(decryptImpl = { _, _ -> java.util.Base64.getEncoder().encodeToString("short".toByteArray()) })
        assertNull(openVaultPayload(sealed, liar, SENDER))
    }

    // "returns null, never throws, when the backend hands back non-string
    // rubbish" does not port: OpenEnvelopeBackend.nip44Decrypt returns a
    // non-nullable String, so there is no way to hand back an object, array,
    // number, null or boolean in the first place.

    @Test
    fun `tamper rejection - returns null when the backend throws`() = runTest {
        val sealed = sealVaultPayload("anything", FakeBackend(), RECIPIENT)!!
        val thrower = FakeBackend(decryptImpl = { _, _ -> throw RuntimeException("nope") })
        assertNull(openVaultPayload(sealed, thrower, SENDER))
    }

    // key-material hygiene: only the content-key wipe on the seal path ports.
    // `random` is a caller-supplied callback, so capturing the exact ByteArray
    // it returns and checking it afterwards observes the library zeroing that
    // very instance in its `finally` block. The padded-body wipe (an internal
    // `padToBucket` result) and the open-path wipes (an internal `aesGcm`
    // result and a base64-decoded key) are not observable this way, and there
    // is no spy/mock framework in this project's dependencies to intercept the
    // JVM crypto calls the way the TypeScript reference spies on
    // `crypto.subtle` and `Uint8Array.from`.
    @Test
    fun `key-material hygiene - wipes the content key after a seal`() = runTest {
        var capturedKey: ByteArray? = null
        val random: (Int) -> ByteArray = { n ->
            val arr = ByteArray(n) { (it + 1).toByte() }
            if (n == 32) capturedKey = arr
            arr
        }
        val backend = FakeBackend()
        assertNotNull(sealVaultPayload("wipe me", backend, RECIPIENT, random = random))
        assertNotNull(capturedKey)
        assertTrue(capturedKey!!.all { it == 0.toByte() })
    }
}
