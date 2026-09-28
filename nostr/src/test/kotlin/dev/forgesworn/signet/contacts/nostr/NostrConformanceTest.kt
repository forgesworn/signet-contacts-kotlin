package dev.forgesworn.signet.contacts.nostr

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonArray
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonString
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.wire.ContactAcceptance
import dev.forgesworn.signet.contacts.wire.ContactRequest
import dev.forgesworn.signet.contacts.wire.OpenEnvelopeBackend
import dev.forgesworn.signet.contacts.wire.SealEnvelopeBackend
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.deriveContactMailboxSecret
import dev.forgesworn.signet.contacts.wire.openVaultPayload
import dev.forgesworn.signet.contacts.wire.parseContactExchangeMessage
import dev.forgesworn.signet.contacts.wire.sealVaultPayload
import kotlinx.coroutines.test.runTest
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

private fun load(name: String): JsonObject {
    val dir = System.getProperty("signetContacts.vectors") ?: fail("signetContacts.vectors is not set; run through Gradle")
    val file = File(dir, name)
    if (!file.isFile) fail("missing conformance vector $file: check out signet-contacts-conformance or pass -PsignetContactsVectors")
    return Json.parse(file.readText()) as JsonObject
}

private operator fun JsonValue?.get(key: String): JsonValue? = (this as? JsonObject)?.get(key)
private val JsonValue?.s: String get() = (this as JsonString).value
private val JsonValue?.items: List<JsonValue> get() = (this as JsonArray).items
private fun hex(b: ByteArray) = b.joinToString("") { "%02x".format(it) }

class NostrConformanceTest {
    private val nostr = load("cases/nostr.json")

    @Test
    fun `public keys`() {
        assertEquals(nostr["publicKeys"]["pk1"].s, NostrKeys.getPublicKey(NostrKeys.unhex(nostr["secretKeys"]["sk1"].s)))
        assertEquals(nostr["publicKeys"]["pk2"].s, NostrKeys.getPublicKey(NostrKeys.unhex(nostr["secretKeys"]["sk2"].s)))
    }

    @Test
    fun `event ids and signatures`() {
        for (raw in nostr["events"].items) {
            val event = SignedNostrEvent.fromJson(raw)!!
            assertEquals(event.id, NostrEvents.eventId(event.pubkey, event.createdAt, event.kind, event.tags, event.content))
            assertTrue(NostrEvents.verify(event), event.content)
            assertFalse(NostrEvents.verify(event.copy(content = event.content + " ")))
            assertFalse(NostrEvents.verify(event.copy(sig = "0".repeat(128))))
        }
    }

    @Test
    fun `nip44 v2 payloads`() {
        val sk1 = NostrKeys.unhex(nostr["secretKeys"]["sk1"].s)
        val sk2 = NostrKeys.unhex(nostr["secretKeys"]["sk2"].s)
        val n = nostr["nip44"]
        val key = Nip44.conversationKey(sk1, nostr["publicKeys"]["pk2"].s)
        assertEquals(n["conversationKey"].s, hex(key))
        assertEquals(n["conversationKey"].s, hex(Nip44.conversationKey(sk2, nostr["publicKeys"]["pk1"].s)))
        val nonce = NostrKeys.unhex(n["nonce"].s)
        for (p in n["payloads"].items + listOf(n["unicode"]!!)) {
            assertEquals(p["payload"].s, Nip44.encrypt(p["plaintext"].s, key, nonce), "length ${p["length"]}")
            assertEquals(p["plaintext"].s, Nip44.decrypt(p["payload"].s, key))
        }
        val first = n["payloads"].items.first()["payload"].s
        val tampered = first.substring(0, 60) + (if (first[60] == 'A') 'B' else 'A') + first.substring(61)
        kotlin.test.assertFails { Nip44.decrypt(tampered, key) }
    }

    @Test
    fun `envelope v2 with real nip44`() = runTest {
        val v = load("envelope.v2.json")
        val rail = NostrKeys.unhex(v["railSecretKey"].s)
        val app = NostrKeys.unhex(v["appSecretKey"].s)
        assertEquals(v["railPubkey"].s, NostrKeys.getPublicKey(rail))
        assertEquals(v["appPubkey"].s, NostrKeys.getPublicKey(app))
        val fixedNonce = ByteArray(32) { 0x11 }
        val seal = SealEnvelopeBackend { peer, plaintext ->
            val ck = Nip44.conversationKey(rail, peer)
            Nip44.encrypt(plaintext, ck, fixedNonce)
        }
        // The reference's xorshift32 stream, from its fixed seed.
        fun deterministic(seed: Int): (Int) -> ByteArray {
            var state = seed
            return { n ->
                ByteArray(n) {
                    state = state xor (state shl 13)
                    state = state xor (state ushr 17)
                    state = state xor (state shl 5)
                    (state and 0xff).toByte()
                }
            }
        }
        val sealed = sealVaultPayload(v["plaintext"].s, seal, v["appPubkey"].s, random = deterministic(0x5e17ed42))
        assertEquals(v["sealed"].s, sealed)
        val open = OpenEnvelopeBackend { peer, ciphertext -> Nip44.decrypt(ciphertext, Nip44.conversationKey(app, peer)) }
        assertEquals(v["plaintext"].s, openVaultPayload(v["sealed"].s, open, v["railPubkey"].s))
        LocalKeySigner(app).use { signer -> assertEquals(v["plaintext"].s, openVaultPayload(v["sealed"].s, signer, v["railPubkey"].s)) }
    }

    @Test
    fun `invite mailbox round trip`() = runTest {
        val v = load("contact-invite-v1.json")
        val mailboxKey = deriveContactMailboxSecret(v["inviteSecret"].s)
        assertEquals(v["mailboxPrivateKey"].s, hex(mailboxKey))
        val alice = NostrKeys.generateSecretKey()
        val bob = NostrKeys.generateSecretKey()
        val aliceSigner = LocalIdentitySigner(alice)
        val bobSigner = LocalIdentitySigner(bob)
        val nonce = "3".repeat(64)
        val request = dev.forgesworn.signet.contacts.wire.createContactRequest(
            "4".repeat(32), aliceSigner.publicKey, bobSigner.publicKey, nonce,
            dev.forgesworn.signet.contacts.wire.ContactMailbox("5".repeat(64), listOf("wss://relay.example/")), 1_700_000_000,
        )
        val wrapped = InviteMailbox.wrap(request, v["inviteSecret"].s, aliceSigner)
        assertEquals(1059, wrapped.kind)
        assertTrue(NostrEvents.verify(wrapped))
        assertEquals(listOf(listOf("p", NostrKeys.getPublicKey(mailboxKey))), wrapped.tags)
        assertTrue(wrapped.pubkey != aliceSigner.publicKey, "the outer key must not be the sender's identity")

        val packet = assertNotNull(InviteMailbox.openMailboxWrap(wrapped, v["inviteSecret"].s))
        assertNull(InviteMailbox.openMailboxWrap(wrapped, "6".repeat(64)), "a different invite cannot open it")
        val message = InviteMailbox.openIdentityPacket(packet, bobSigner)
        assertEquals(request, message)
        // Only the intended identity can open the inner layer.
        val eve = LocalIdentitySigner(NostrKeys.generateSecretKey())
        kotlin.test.assertFails { InviteMailbox.openIdentityPacket(packet, eve) }

        // A signer that is not `from` cannot wrap the message.
        kotlin.test.assertFails { InviteMailbox.wrap(request, v["inviteSecret"].s, bobSigner) }
        val acceptance = parseContactExchangeMessage(v["acceptance"]!!.stringify()) as ContactAcceptance
        assertTrue(acceptance.from != bobSigner.publicKey)
        assertTrue(parseContactExchangeMessage(v["request"]!!.stringify()) is ContactRequest)
    }

    @Test
    fun `local key signer signs verifiable events`() = runTest {
        LocalKeySigner(NostrKeys.generateSecretKey()).use { signer ->
            val event = signer.signEvent(dev.forgesworn.signet.contacts.wire.UnsignedNostrEvent(1, "", 1, listOf(listOf("t", "x")), "hi"))
            assertEquals(signer.pubkey, event.pubkey)
            assertTrue(NostrEvents.verify(event))
            val peer = LocalKeySigner(NostrKeys.generateSecretKey())
            assertEquals("secret", peer.nip44Decrypt(signer.pubkey, signer.nip44Encrypt(peer.pubkey, "secret")))
        }
    }
}
