package dev.forgesworn.signet.contacts.nostr

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.toJson
import dev.forgesworn.signet.contacts.wire.CONTACT_MESSAGE_MAX_BYTES
import dev.forgesworn.signet.contacts.wire.ContactExchangeMessage
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.UnsignedNostrEvent
import dev.forgesworn.signet.contacts.wire.deriveContactMailboxSecret
import dev.forgesworn.signet.contacts.wire.parseContactExchangeMessage
import java.security.SecureRandom
import kotlin.coroutines.cancellation.CancellationException

/**
 * Contact-exchange transport (`docs/contact-invite-v1.md`): two recipient
 * layers, so the mailbox holder sees no identity-signed seal until the
 * intended identity decrypts it. A conventional NIP-59 wrap would expose the
 * sender seal's pubkey to everyone holding a standing invite.
 *
 *   kind 1059, `["p", mailboxPubkey]`, random outer key
 *     -> NIP-44(outer -> mailbox) of `{v:1, key, ciphertext}`
 *       -> NIP-44(inner -> recipient identity) of the kind-13 seal
 *         -> the signed exchange message
 */
public interface ContactIdentitySigner {
    public val publicKey: String
    public suspend fun signEvent(event: UnsignedNostrEvent): SignedNostrEvent
    public suspend fun decrypt(senderPubkey: String, ciphertext: String): String
}

public data class SealedContactPacket(val key: String, val ciphertext: String) {
    public val v: Int get() = 1
    public fun toJson(): JsonObject = jsonObject("v" to 1.toJson(), "key" to key.toJson(), "ciphertext" to ciphertext.toJson())
}

public object InviteMailbox {
    private const val MAX_PACKET = 20000
    private const val MAX_WRAP = 32000
    private val HEX64 = Regex("^[0-9a-f]{64}$")
    private val rng = SecureRandom()

    /** A timestamp up to two days before [now], so relay timing does not date the exchange. */
    private fun randomTime(now: Long): Long {
        val r = ByteArray(4).also(rng::nextBytes)
        val value = ((r[0].toLong() and 0xff) shl 24) or ((r[1].toLong() and 0xff) shl 16) or
            ((r[2].toLong() and 0xff) shl 8) or (r[3].toLong() and 0xff)
        return maxOf(0, now - value % 172800)
    }

    private fun encrypt(key: ByteArray, pubkey: String, plaintext: String): String {
        val shared = Nip44.conversationKey(key, pubkey)
        try {
            return Nip44.encrypt(plaintext, shared)
        } finally {
            shared.fill(0)
        }
    }

    private fun decrypt(key: ByteArray, pubkey: String, ciphertext: String): String {
        val shared = Nip44.conversationKey(key, pubkey)
        try {
            return Nip44.decrypt(ciphertext, shared)
        } finally {
            shared.fill(0)
        }
    }

    private fun packet(raw: JsonValue?): SealedContactPacket? {
        val p = raw as? JsonObject ?: return null
        val v = p["v"] as? dev.forgesworn.signet.contacts.json.JsonNumber
        val key = (p["key"] as? dev.forgesworn.signet.contacts.json.JsonString)?.value
        val ciphertext = (p["ciphertext"] as? dev.forgesworn.signet.contacts.json.JsonString)?.value
        return if (v?.value == 1.0 && key != null && HEX64.matches(key) && ciphertext != null && ciphertext.length <= MAX_PACKET) {
            SealedContactPacket(key, ciphertext)
        } else null
    }

    /** Seal [message] as [signer] and wrap it to the invite's mailbox. */
    public suspend fun wrap(message: ContactExchangeMessage, mailboxSecret: String, signer: ContactIdentitySigner): SignedNostrEvent {
        val parsed = parseContactExchangeMessage(message.toJson().stringify())
        require(parsed != null && parsed.from == signer.publicKey) { "Contact exchange signer mismatch" }
        val body = parsed!!.toJson().stringify()
        val seal = signer.signEvent(UnsignedNostrEvent(13, signer.publicKey, randomTime(parsed.createdAt), emptyList(), body))
        require(
            NostrEvents.verify(seal) && seal.pubkey == signer.publicKey && seal.kind == 13 && seal.tags.isEmpty() && seal.content == body,
        ) { "Invalid identity seal" }
        val innerKey = NostrKeys.generateSecretKey()
        val outerKey = NostrKeys.generateSecretKey()
        val mailboxKey = deriveContactMailboxSecret(mailboxSecret)
        try {
            val sealed = SealedContactPacket(NostrKeys.getPublicKey(innerKey), encrypt(innerKey, parsed.to, seal.toJson().stringify()))
            val mailboxPubkey = NostrKeys.getPublicKey(mailboxKey)
            return NostrEvents.finalize(
                UnsignedNostrEvent(
                    1059, "", randomTime(parsed.createdAt), listOf(listOf("p", mailboxPubkey)),
                    encrypt(outerKey, mailboxPubkey, sealed.toJson().stringify()),
                ),
                outerKey,
            )
        } finally {
            innerKey.fill(0); outerKey.fill(0); mailboxKey.fill(0)
        }
    }

    /** Cheap local-only arrival check; never touches the recipient identity signer. */
    public fun openMailboxWrap(event: SignedNostrEvent, mailboxSecret: String): SealedContactPacket? {
        var key: ByteArray? = null
        try {
            if (event.kind != 1059 || event.content.length > MAX_WRAP || !NostrEvents.verify(event)) return null
            key = deriveContactMailboxSecret(mailboxSecret)
            val pubkey = NostrKeys.getPublicKey(key)
            val tag = event.tags.singleOrNull() ?: return null
            if (tag.size != 2 || tag[0] != "p" || tag[1] != pubkey) return null
            val raw = decrypt(key, event.pubkey, event.content)
            if (raw.length > MAX_PACKET) return null
            return packet(Json.parse(raw))
        } catch (_: Exception) {
            return null
        } finally {
            key?.fill(0)
        }
    }

    /**
     * Open the identity layer. Call only when the user opens the inbox, after
     * consuming an unlock budget. A signer refusal propagates (it is
     * retryable); a malformed packet is null.
     */
    public suspend fun openIdentityPacket(sealed: SealedContactPacket, signer: ContactIdentitySigner): ContactExchangeMessage? {
        val p = packet(sealed.toJson()) ?: return null
        val raw = signer.decrypt(p.key, p.ciphertext)
        return try {
            if (raw.length > CONTACT_MESSAGE_MAX_BYTES + 2048) return null
            val seal = SignedNostrEvent.fromJson(Json.parse(raw)) ?: return null
            if (seal.kind != 13 || seal.tags.isNotEmpty() || !NostrEvents.verify(seal)) return null
            val message = parseContactExchangeMessage(seal.content) ?: return null
            if (message.from != seal.pubkey || message.to != signer.publicKey) return null
            message
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            null
        }
    }
}

/** A [ContactIdentitySigner] over a local key, for tests and tools. */
public class LocalIdentitySigner(secretKey: ByteArray) : ContactIdentitySigner, AutoCloseable {
    private val signer = LocalKeySigner(secretKey)
    override val publicKey: String get() = signer.pubkey
    override suspend fun signEvent(event: UnsignedNostrEvent): SignedNostrEvent = signer.signEvent(event)
    override suspend fun decrypt(senderPubkey: String, ciphertext: String): String = signer.nip44Decrypt(senderPubkey, ciphertext)
    override fun close(): Unit = signer.close()
}
