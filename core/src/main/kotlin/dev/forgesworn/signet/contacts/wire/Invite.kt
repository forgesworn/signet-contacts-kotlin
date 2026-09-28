package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.internal.Digest
import dev.forgesworn.signet.contacts.internal.Hex
import dev.forgesworn.signet.contacts.internal.Js
import dev.forgesworn.signet.contacts.internal.SpokenToken
import dev.forgesworn.signet.contacts.internal.WhatwgUrl
import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.MAX_SAFE_INTEGER_LONG
import dev.forgesworn.signet.contacts.json.arr
import dev.forgesworn.signet.contacts.json.isNumber
import dev.forgesworn.signet.contacts.json.jsonArray
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.jsonStrings
import dev.forgesworn.signet.contacts.json.nonNegativeSafeLong
import dev.forgesworn.signet.contacts.json.str
import dev.forgesworn.signet.contacts.json.toJson

/**
 * Contact exchange v1 (`docs/contact-invite-v1.md` in signet-contacts):
 * invites, and the signed commit-and-reveal request / acceptance / reveal
 * that ends in two directional word codes. Unreleased upstream; review the
 * vectors before relying on it.
 */

public const val CONTACT_REQUEST_TTL: Long = 30L * 24 * 60 * 60
public const val CONTACT_MESSAGE_MAX_BYTES: Int = 8192
public const val CONTACT_IDENTITY_DECRYPTS_PER_UNLOCK: Int = 32
public const val CONTACT_INVITE_PENDING_LIMIT: Int = 128
public const val CONTACT_SENDER_PENDING_LIMIT: Int = 8
public const val CONTACT_AUTO_ACCEPT_SECONDS: Long = 300
public const val CONTACT_WORDS_NAMESPACE: String = "signet-contacts:exchange:v1"
private const val MAILBOX_NAMESPACE = "signet-contacts:mailbox:v1"
private const val SCALAR_ORDER = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
private val HEX64 = Regex("^[0-9a-f]{64}$")
private val ID32 = Regex("^[0-9a-f]{32}$")
private val CAPTION_FORBIDDEN = Regex("[\\u0000-\\u001f\\u007f\\u202a-\\u202e\\u2066-\\u2069]")

internal fun hex64(v: JsonValue?): Boolean = v.str()?.let(HEX64::matches) == true
internal fun hex64(v: String?): Boolean = v != null && HEX64.matches(v)
internal fun id32(v: String?): Boolean = v != null && ID32.matches(v)
internal fun isTime(v: Long): Boolean = v in 0..MAX_SAFE_INTEGER_LONG

/** Owner-private mailbox: the invite secret and where to reach it. */
public data class ContactMailbox(val secret: String, val relays: List<String>) {
    public fun toJson(): JsonObject = jsonObject("secret" to secret.toJson(), "relays" to jsonStrings(relays))
}

/** Names, intended recipients and standing/single-use policy stay owner-private. */
public data class ContactInvite(
    val recipient: String,
    val secret: String,
    val relays: List<String>,
    val expiresAt: Long? = null,
    val caption: String? = null,
) {
    public val v: Int get() = 1
    val mailbox: ContactMailbox get() = ContactMailbox(secret, relays)

    public fun toJson(): JsonObject = jsonObject(
        "v" to 1.toJson(), "recipient" to recipient.toJson(), "secret" to secret.toJson(),
        "relays" to jsonStrings(relays), "expiresAt" to expiresAt?.toJson(), "caption" to caption?.toJson(),
    )
}

public sealed class ContactExchangeMessage {
    public abstract val id: String
    public abstract val from: String
    public abstract val to: String
    public abstract val createdAt: Long
    public abstract val type: String
    public val v: Int get() = 1

    /** Canonical key order: the order the parser builds, which every hash is taken over. */
    public abstract fun toJson(): JsonObject

    protected fun base(vararg rest: Pair<String, JsonValue?>): JsonObject = jsonObject(
        "v" to 1.toJson(), "id" to id.toJson(), "from" to from.toJson(), "to" to to.toJson(),
        "createdAt" to createdAt.toJson(), "type" to type.toJson(), *rest,
    )
}

public data class ContactRequest(
    override val id: String,
    override val from: String,
    override val to: String,
    override val createdAt: Long,
    val expiresAt: Long,
    val commitment: String,
    val reply: ContactMailbox,
) : ContactExchangeMessage() {
    override val type: String get() = "signet-contact-request"
    override fun toJson(): JsonObject = base("expiresAt" to expiresAt.toJson(), "commitment" to commitment.toJson(), "reply" to reply.toJson())
}

public data class ContactAcceptance(
    override val id: String,
    override val from: String,
    override val to: String,
    override val createdAt: Long,
    val requestHash: String,
    val nonce: String,
) : ContactExchangeMessage() {
    override val type: String get() = "signet-contact-accept"
    override fun toJson(): JsonObject = base("requestHash" to requestHash.toJson(), "nonce" to nonce.toJson())
}

public data class ContactReveal(
    override val id: String,
    override val from: String,
    override val to: String,
    override val createdAt: Long,
    val requestHash: String,
    val acceptanceHash: String,
    val nonce: String,
) : ContactExchangeMessage() {
    override val type: String get() = "signet-contact-reveal"
    override fun toJson(): JsonObject =
        base("requestHash" to requestHash.toJson(), "acceptanceHash" to acceptanceHash.toJson(), "nonce" to nonce.toJson())
}

public data class VerificationWords(val youSay: String, val theySay: String)

private fun parseRelays(value: JsonValue?): List<String>? {
    val items = value.arr() ?: return null
    if (items.isEmpty() || items.size > 8) return null
    val out = LinkedHashSet<String>()
    for (raw in items) {
        val s = raw.str() ?: return null
        if (s.length > 512) return null
        val url = WhatwgUrl.parse(s) ?: return null
        if (url.protocol != "wss:" || url.username.isNotEmpty() || url.password.isNotEmpty() || url.hash.isNotEmpty()) return null
        out.add(url.href)
    }
    return out.toList()
}

private fun parseMailbox(value: JsonValue?): ContactMailbox? {
    val o = value as? JsonObject ?: return null
    if (!hex64(o["secret"])) return null
    val relays = parseRelays(o["relays"]) ?: return null
    return ContactMailbox(o["secret"].str()!!, relays)
}

private fun decode(raw: String): JsonValue? {
    if (Js.utf8(raw).size > CONTACT_MESSAGE_MAX_BYTES) return null
    return Json.parseOrNull(raw)
}

/** Parse an invite; with [now], an expired one is null. */
public fun parseContactInvite(raw: String, now: Long? = null): ContactInvite? {
    val value = decode(raw) as? JsonObject ?: return null
    if (!value["v"].isNumber(1) || !hex64(value["recipient"])) return null
    val box = parseMailbox(value) ?: return null
    var expiresAt: Long? = null
    value["expiresAt"]?.let { e ->
        val t = e.nonNegativeSafeLong() ?: return null
        if (now != null && t <= now) return null
        expiresAt = t
    }
    var caption: String? = null
    value["caption"]?.let { c ->
        val s = c.str() ?: return null
        if (s.length > 200 || CAPTION_FORBIDDEN.containsMatchIn(s)) return null
        caption = s
    }
    return ContactInvite(value["recipient"].str()!!, box.secret, box.relays, expiresAt, caption)
}

/** Canonical encoding of a valid invite; throws [IllegalArgumentException] otherwise. */
public fun encodeContactInvite(value: ContactInvite): String {
    val parsed = parseContactInvite(value.toJson().stringify()) ?: throw IllegalArgumentException("Invalid contact invite")
    return parsed.toJson().stringify()
}

/**
 * The mailbox secp256k1 secret key derived from an invite secret (HKDF-SHA256,
 * salt `signet-contacts:mailbox:v1`). The caller zeroises it. A vanishingly
 * rare invalid scalar rejects the invite; never reduce modulo the order.
 */
public fun deriveContactMailboxSecret(secret: String): ByteArray {
    require(hex64(secret)) { "Invalid mailbox secret" }
    val input = Hex.decode(secret)
    try {
        val key = Digest.hkdfSha256(input, Js.utf8(MAILBOX_NAMESPACE), ByteArray(0), 32)
        val encoded = Hex.encode(key)
        if (encoded.all { it == '0' } || encoded >= SCALAR_ORDER) {
            key.fill(0)
            throw IllegalArgumentException("Invalid mailbox scalar")
        }
        return key
    } finally {
        input.fill(0)
    }
}

internal fun transcriptDigest(namespace: String, fields: List<JsonValue>): String =
    Digest.sha256Hex(jsonArray(listOf(namespace.toJson()) + fields).stringify())

public fun contactCommitment(id: String, from: String, to: String, nonce: String): String {
    require(id32(id) && hex64(from) && hex64(to) && from != to && hex64(nonce)) { "Invalid commitment input" }
    return transcriptDigest("signet-contacts:commit:v1", listOf(id, from, to, nonce).map { it.toJson() })
}

/** Authenticate the seal signer against `from` before using the parsed body. */
public fun parseContactExchangeMessage(raw: String): ContactExchangeMessage? {
    val v = decode(raw) as? JsonObject ?: return null
    val id = v["id"].str()
    val from = v["from"].str()
    val to = v["to"].str()
    if (!v["v"].isNumber(1) || !id32(id) || !hex64(from) || !hex64(to) || from == to) return null
    val createdAt = v["createdAt"].nonNegativeSafeLong() ?: return null
    id!!; from!!; to!!
    when (v["type"].str()) {
        "signet-contact-request" -> {
            val reply = parseMailbox(v["reply"]) ?: return null
            if (!hex64(v["commitment"])) return null
            val expiresAt = v["expiresAt"].nonNegativeSafeLong() ?: return null
            if (expiresAt <= createdAt || expiresAt - createdAt > CONTACT_REQUEST_TTL) return null
            return ContactRequest(id, from, to, createdAt, expiresAt, v["commitment"].str()!!, reply)
        }
    }
    if (!hex64(v["requestHash"]) || !hex64(v["nonce"])) return null
    val requestHash = v["requestHash"].str()!!
    val nonce = v["nonce"].str()!!
    return when (v["type"].str()) {
        "signet-contact-accept" -> ContactAcceptance(id, from, to, createdAt, requestHash, nonce)
        "signet-contact-reveal" -> if (hex64(v["acceptanceHash"])) {
            ContactReveal(id, from, to, createdAt, requestHash, v["acceptanceHash"].str()!!, nonce)
        } else null
        else -> null
    }
}

public fun contactMessageHash(message: ContactExchangeMessage): String {
    val parsed = parseContactExchangeMessage(message.toJson().stringify())
        ?: throw IllegalArgumentException("Invalid contact exchange message")
    return transcriptDigest("signet-contacts:message:v1", listOf(parsed.toJson()))
}

public fun createContactRequest(
    id: String,
    from: String,
    to: String,
    nonce: String,
    reply: ContactMailbox,
    now: Long,
    expiresAt: Long? = null,
): ContactRequest {
    val draft = jsonObject(
        "v" to 1.toJson(), "type" to "signet-contact-request".toJson(), "id" to id.toJson(),
        "from" to from.toJson(), "to" to to.toJson(), "createdAt" to now.toJson(),
        "expiresAt" to (expiresAt ?: (now + CONTACT_REQUEST_TTL)).toJson(), "reply" to reply.toJson(),
        "commitment" to contactCommitment(id, from, to, nonce).toJson(),
    )
    return parseContactExchangeMessage(draft.stringify()) as? ContactRequest
        ?: throw IllegalArgumentException("Invalid contact request")
}

private fun validRequest(request: ContactRequest, now: Long): ContactRequest {
    val parsed = parseContactExchangeMessage(request.toJson().stringify()) as? ContactRequest
    require(parsed != null && isTime(now) && now >= parsed.createdAt && now < parsed.expiresAt) {
        "Contact request expired or not yet valid"
    }
    return parsed
}

public fun createContactAcceptance(request: ContactRequest, nonce: String, now: Long): ContactAcceptance {
    val parsed = validRequest(request, now)
    require(hex64(nonce)) { "Invalid acceptance nonce" }
    return ContactAcceptance(parsed.id, parsed.to, parsed.from, now, contactMessageHash(parsed), nonce)
}

private fun validAcceptance(request: ContactRequest, acceptance: ContactAcceptance) {
    val parsed = parseContactExchangeMessage(acceptance.toJson().stringify()) as? ContactAcceptance
    require(
        parsed != null && parsed.id == request.id && parsed.from == request.to && parsed.to == request.from &&
            parsed.requestHash == contactMessageHash(request) &&
            parsed.createdAt >= request.createdAt && parsed.createdAt < request.expiresAt,
    ) { "Acceptance does not match request" }
}

public fun createContactReveal(request: ContactRequest, acceptance: ContactAcceptance, nonce: String, now: Long): ContactReveal {
    validRequest(request, now)
    validAcceptance(request, acceptance)
    require(now >= acceptance.createdAt && contactCommitment(request.id, request.from, request.to, nonce) == request.commitment) {
        "Reveal does not match commitment"
    }
    return ContactReveal(
        request.id, request.from, request.to, now,
        contactMessageHash(request), contactMessageHash(acceptance), nonce,
    )
}

/** Words only after every signed message has been authenticated by the caller. */
public fun contactVerificationWords(
    request: ContactRequest,
    acceptance: ContactAcceptance,
    reveal: ContactReveal,
    localPubkey: String,
): VerificationWords {
    val r = validRequest(request, reveal.createdAt)
    validAcceptance(r, acceptance)
    val expected = createContactReveal(r, acceptance, reveal.nonce, reveal.createdAt)
    require(contactMessageHash(expected) == contactMessageHash(reveal)) { "Invalid reveal transcript" }
    val roles = listOf(r.from, r.to).sorted()
    require(localPubkey in roles) { "Identity is not part of this exchange" }
    val material = Hex.decode(
        transcriptDigest(
            "signet-contacts:words-material:v1",
            listOf(contactMessageHash(r).toJson(), contactMessageHash(acceptance).toJson(), reveal.nonce.toJson()),
        ),
    )
    try {
        val pair = SpokenToken.directionalPair(material, CONTACT_WORDS_NAMESPACE, roles[0] to roles[1], 0, 3)
        val other = if (localPubkey == roles[0]) roles[1] else roles[0]
        return VerificationWords(pair.getValue(localPubkey), pair.getValue(other))
    } finally {
        material.fill(0)
    }
}

// ---------------------------------------------------------------------------
// Exchange state machine. Owner-private: persist before emitting each message.
// ---------------------------------------------------------------------------

public enum class ExchangeRole { REQUESTER, RECIPIENT }

public enum class ExchangePhase(public val wire: String) {
    REQUESTED("requested"), ACCEPTED("accepted"), REVEAL_PENDING("reveal-pending"), COMPLETE("complete"), DECLINED("declined"),
}

public data class ContactExchangeState(
    val role: ExchangeRole,
    val request: ContactRequest,
    val nonce: String,
    val acceptance: ContactAcceptance? = null,
    val reveal: ContactReveal? = null,
    val phase: ExchangePhase,
)

public fun beginContactExchange(request: ContactRequest, nonce: String): ContactExchangeState {
    require(contactCommitment(request.id, request.from, request.to, nonce) == request.commitment) { "Wrong request nonce" }
    contactMessageHash(request)
    return ContactExchangeState(ExchangeRole.REQUESTER, request, nonce, phase = ExchangePhase.REQUESTED)
}

public fun acceptContactExchange(request: ContactRequest, nonce: String, now: Long): ContactExchangeState =
    ContactExchangeState(ExchangeRole.RECIPIENT, request, nonce, createContactAcceptance(request, nonce, now), phase = ExchangePhase.ACCEPTED)

/** The first acceptance is immutable, so nobody can grind new words by re-accepting. */
public fun receiveContactAcceptance(state: ContactExchangeState, acceptance: ContactAcceptance, now: Long): ContactExchangeState {
    require(state.role == ExchangeRole.REQUESTER && state.phase != ExchangePhase.DECLINED) { "Exchange cannot accept this message" }
    state.acceptance?.let { pinned ->
        require(contactMessageHash(pinned) == contactMessageHash(acceptance)) { "Acceptance already pinned" }
        return state
    }
    val reveal = createContactReveal(state.request, acceptance, state.nonce, now)
    return state.copy(acceptance = acceptance, reveal = reveal, phase = ExchangePhase.REVEAL_PENDING)
}

public fun receiveContactReveal(state: ContactExchangeState, reveal: ContactReveal, now: Long): ContactExchangeState {
    val acceptance = state.acceptance
    require(
        state.role == ExchangeRole.RECIPIENT && acceptance != null && state.phase != ExchangePhase.DECLINED &&
            Math.abs(now) <= MAX_SAFE_INTEGER_LONG && now >= reveal.createdAt && now < state.request.expiresAt,
    ) { "Exchange cannot accept this reveal" }
    contactVerificationWords(state.request, acceptance!!, reveal, state.request.to)
    state.reveal?.let { pinned ->
        require(contactMessageHash(pinned) == contactMessageHash(reveal)) { "Reveal already pinned" }
        return state
    }
    return state.copy(reveal = reveal, phase = ExchangePhase.COMPLETE)
}

public fun confirmContactRevealSent(state: ContactExchangeState): ContactExchangeState {
    val acceptance = state.acceptance
    val reveal = state.reveal
    require(state.role == ExchangeRole.REQUESTER && state.phase == ExchangePhase.REVEAL_PENDING && acceptance != null && reveal != null) {
        "No reveal to confirm"
    }
    contactVerificationWords(state.request, acceptance!!, reveal!!, state.request.from)
    return state.copy(phase = ExchangePhase.COMPLETE)
}

/**
 * Each attempted identity decrypt consumes budget, including malformed
 * packets. Keep one instance for the whole unlock. Thread-safe.
 */
public class ContactIdentityDecryptBudget {
    private var spent = 0
    private val attempted = HashSet<String>()

    public val remaining: Int
        @Synchronized get() = CONTACT_IDENTITY_DECRYPTS_PER_UNLOCK - spent

    @Synchronized
    public fun consume(packetId: String? = null): Boolean {
        if (remaining <= 0 || (packetId != null && packetId in attempted)) return false
        if (packetId != null) attempted.add(packetId)
        spent++
        return true
    }
}
