package dev.forgesworn.signet.contacts.nostr

import dev.forgesworn.signet.contacts.ContactsSigner
import dev.forgesworn.signet.contacts.json.JsonArray
import dev.forgesworn.signet.contacts.json.jsonStrings
import dev.forgesworn.signet.contacts.json.toJson
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.UnsignedNostrEvent
import fr.acinq.secp256k1.Secp256k1
import java.security.MessageDigest
import java.security.SecureRandom

/**
 * Keys, event ids and BIP-340 signatures, on secp256k1-kmp. The equivalents
 * of nostr-tools' `generateSecretKey`, `getPublicKey`, `finalizeEvent` and
 * `verifyEvent`.
 */
public object NostrKeys {
    private val rng = SecureRandom()
    private val secp: Secp256k1 get() = Secp256k1.get()

    /** A fresh valid secret key. The caller zeroises it. */
    public fun generateSecretKey(): ByteArray {
        while (true) {
            val key = ByteArray(32).also(rng::nextBytes)
            if (secp.secKeyVerify(key)) return key
            key.fill(0)
        }
    }

    /** Lowercase 64-hex x-only public key for [secretKey]. */
    public fun getPublicKey(secretKey: ByteArray): String {
        val full = secp.pubkeyCreate(secretKey) // 65-byte uncompressed
        return hex(full.copyOfRange(1, 33))
    }

    internal fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }

    internal fun unhex(s: String): ByteArray {
        require(s.length % 2 == 0 && s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) { "invalid hex" }
        return ByteArray(s.length / 2) { i -> s.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
    }
}

public object NostrEvents {
    private val secp: Secp256k1 get() = Secp256k1.get()
    private val rng = SecureRandom()
    private val HEX64 = Regex("^[0-9a-f]{64}$")
    private val HEX128 = Regex("^[0-9a-f]{128}$")

    /** NIP-01 serialisation, `JSON.stringify([0, pubkey, created_at, kind, tags, content])`. */
    public fun serialize(pubkey: String, createdAt: Long, kind: Int, tags: List<List<String>>, content: String): String =
        JsonArray(
            listOf(0.toJson(), pubkey.toJson(), createdAt.toJson(), kind.toJson(), JsonArray(tags.map(::jsonStrings)), content.toJson()),
        ).stringify()

    public fun eventId(pubkey: String, createdAt: Long, kind: Int, tags: List<List<String>>, content: String): String {
        val bytes = dev.forgesworn.signet.contacts.nostr.internal.utf8(serialize(pubkey, createdAt, kind, tags, content))
        return NostrKeys.hex(MessageDigest.getInstance("SHA-256").digest(bytes))
    }

    /** Sign [template] with [secretKey]; the template's own pubkey is replaced by the key's. */
    public fun finalize(template: UnsignedNostrEvent, secretKey: ByteArray): SignedNostrEvent {
        val pubkey = NostrKeys.getPublicKey(secretKey)
        val id = eventId(pubkey, template.createdAt, template.kind, template.tags, template.content)
        val aux = ByteArray(32).also(rng::nextBytes)
        val sig = NostrKeys.hex(secp.signSchnorr(NostrKeys.unhex(id), secretKey, aux))
        return SignedNostrEvent(id, template.kind, pubkey, template.createdAt, template.tags, template.content, sig)
    }

    /** Id recomputed and BIP-340 signature checked. Never throws. */
    public fun verify(event: SignedNostrEvent): Boolean = try {
        HEX64.matches(event.id) && HEX64.matches(event.pubkey) && HEX128.matches(event.sig) &&
            eventId(event.pubkey, event.createdAt, event.kind, event.tags, event.content) == event.id &&
            secp.verifySchnorr(NostrKeys.unhex(event.sig), NostrKeys.unhex(event.id), NostrKeys.unhex(event.pubkey))
    } catch (_: Exception) {
        false
    }
}

/**
 * A [ContactsSigner] over a local secret key, for tests, tools and apps that
 * hold their own key. The key is copied in; [close] zeroises the copy.
 */
public class LocalKeySigner(secretKey: ByteArray) : ContactsSigner, AutoCloseable {
    private val key = secretKey.copyOf()
    override val pubkey: String = NostrKeys.getPublicKey(key)

    override suspend fun nip44Encrypt(peerPubkey: String, plaintext: String): String {
        val conversation = Nip44.conversationKey(key, peerPubkey)
        try {
            return Nip44.encrypt(plaintext, conversation)
        } finally {
            conversation.fill(0)
        }
    }

    override suspend fun nip44Decrypt(peerPubkey: String, ciphertext: String): String {
        val conversation = Nip44.conversationKey(key, peerPubkey)
        try {
            return Nip44.decrypt(ciphertext, conversation)
        } finally {
            conversation.fill(0)
        }
    }

    override suspend fun signEvent(event: UnsignedNostrEvent): SignedNostrEvent = NostrEvents.finalize(event, key)

    override fun close() {
        key.fill(0)
    }
}
