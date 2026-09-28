package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.internal.Hex
import dev.forgesworn.signet.contacts.internal.Js
import dev.forgesworn.signet.contacts.internal.SpokenToken
import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.isNumber
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.nonNegativeSafeLong
import dev.forgesworn.signet.contacts.json.str
import dev.forgesworn.signet.contacts.json.toJson

/**
 * Authenticated-channel check profile v1 (`docs/channel-check-v1.md`; a
 * draft, outside the frozen contract). The transport MUST authenticate `from`
 * before accepting a message. Persist every transition before sending its
 * output, especially acceptance pinning before revealing the requester's nonce.
 */

public const val CHANNEL_CHECK_TTL: Long = 600
public const val CHANNEL_CHECK_MAX_BYTES: Int = 2048
public const val CHANNEL_CHECK_WORDS_NAMESPACE: String = "signet-contacts:channel-check:v1"

public sealed class ChannelCheckMessage {
    public abstract val id: String
    public abstract val context: String
    public abstract val from: String
    public abstract val to: String
    public abstract val createdAt: Long
    public abstract val type: String
    public val v: Int get() = 1

    /** Canonical key order, as the parser builds it. */
    public abstract fun toJson(): JsonObject

    protected fun base(vararg rest: Pair<String, JsonValue?>): JsonObject = jsonObject(
        "v" to 1.toJson(), "id" to id.toJson(), "context" to context.toJson(), "from" to from.toJson(),
        "to" to to.toJson(), "createdAt" to createdAt.toJson(), "type" to type.toJson(), *rest,
    )
}

public data class ChannelCheckRequest(
    override val id: String,
    override val context: String,
    override val from: String,
    override val to: String,
    override val createdAt: Long,
    val expiresAt: Long,
    val commitment: String,
) : ChannelCheckMessage() {
    override val type: String get() = "channel-check-request"
    override fun toJson(): JsonObject = base("expiresAt" to expiresAt.toJson(), "commitment" to commitment.toJson())
}

public data class ChannelCheckAcceptance(
    override val id: String,
    override val context: String,
    override val from: String,
    override val to: String,
    override val createdAt: Long,
    val requestHash: String,
    val nonce: String,
) : ChannelCheckMessage() {
    override val type: String get() = "channel-check-accept"
    override fun toJson(): JsonObject = base("requestHash" to requestHash.toJson(), "nonce" to nonce.toJson())
}

public data class ChannelCheckReveal(
    override val id: String,
    override val context: String,
    override val from: String,
    override val to: String,
    override val createdAt: Long,
    val requestHash: String,
    val acceptanceHash: String,
    val nonce: String,
) : ChannelCheckMessage() {
    override val type: String get() = "channel-check-reveal"
    override fun toJson(): JsonObject =
        base("requestHash" to requestHash.toJson(), "acceptanceHash" to acceptanceHash.toJson(), "nonce" to nonce.toJson())
}

public data class ChannelCheckState(
    val role: ExchangeRole,
    val request: ChannelCheckRequest,
    val nonce: String,
    val acceptance: ChannelCheckAcceptance? = null,
    val reveal: ChannelCheckReveal? = null,
    val phase: ExchangePhase,
)

public fun parseChannelCheckMessage(raw: String): ChannelCheckMessage? {
    if (Js.utf8(raw).size > CHANNEL_CHECK_MAX_BYTES) return null
    val v = Json.parseOrNull(raw) as? JsonObject ?: return null
    val id = v["id"].str()
    val context = v["context"].str()
    val from = v["from"].str()
    val to = v["to"].str()
    if (!v["v"].isNumber(1) || !id32(id) || !hex64(context) || !hex64(from) || !hex64(to) || from == to) return null
    val createdAt = v["createdAt"].nonNegativeSafeLong() ?: return null
    id!!; context!!; from!!; to!!
    if (v["type"].str() == "channel-check-request") {
        val expiresAt = v["expiresAt"].nonNegativeSafeLong()
        if (expiresAt != null && expiresAt > createdAt && expiresAt - createdAt <= CHANNEL_CHECK_TTL && hex64(v["commitment"])) {
            return ChannelCheckRequest(id, context, from, to, createdAt, expiresAt, v["commitment"].str()!!)
        }
    }
    if (!hex64(v["requestHash"]) || !hex64(v["nonce"])) return null
    val requestHash = v["requestHash"].str()!!
    val nonce = v["nonce"].str()!!
    return when (v["type"].str()) {
        "channel-check-accept" -> ChannelCheckAcceptance(id, context, from, to, createdAt, requestHash, nonce)
        "channel-check-reveal" -> if (hex64(v["acceptanceHash"])) {
            ChannelCheckReveal(id, context, from, to, createdAt, requestHash, v["acceptanceHash"].str()!!, nonce)
        } else null
        else -> null
    }
}

public fun channelCheckHash(message: ChannelCheckMessage): String {
    val parsed = parseChannelCheckMessage(message.toJson().stringify()) ?: throw IllegalArgumentException("Invalid channel check")
    return transcriptDigest("signet-contacts:channel-message:v1", listOf(parsed.toJson()))
}

public fun channelCheckCommitment(id: String, context: String, from: String, to: String, nonce: String): String {
    require(id32(id) && hex64(context) && hex64(from) && hex64(to) && from != to && hex64(nonce)) { "Invalid channel commitment" }
    return transcriptDigest("signet-contacts:channel-commit:v1", listOf(id, context, from, to, nonce).map { it.toJson() })
}

public fun createChannelCheckRequest(id: String, context: String, from: String, to: String, nonce: String, now: Long): ChannelCheckRequest {
    val draft = jsonObject(
        "v" to 1.toJson(), "type" to "channel-check-request".toJson(), "id" to id.toJson(), "context" to context.toJson(),
        "from" to from.toJson(), "to" to to.toJson(), "createdAt" to now.toJson(),
        "expiresAt" to (now + CHANNEL_CHECK_TTL).toJson(),
        "commitment" to channelCheckCommitment(id, context, from, to, nonce).toJson(),
    )
    return parseChannelCheckMessage(draft.stringify()) as? ChannelCheckRequest
        ?: throw IllegalArgumentException("Invalid channel check request")
}

private fun validChannelRequest(request: ChannelCheckRequest, now: Long): ChannelCheckRequest {
    val parsed = parseChannelCheckMessage(request.toJson().stringify()) as? ChannelCheckRequest
    require(parsed != null && isTime(now) && now >= parsed.createdAt && now < parsed.expiresAt) {
        "Channel check expired or not yet valid"
    }
    return parsed
}

public fun createChannelCheckAcceptance(request: ChannelCheckRequest, nonce: String, now: Long): ChannelCheckAcceptance {
    val r = validChannelRequest(request, now)
    require(hex64(nonce)) { "Invalid channel nonce" }
    return ChannelCheckAcceptance(r.id, r.context, r.to, r.from, now, channelCheckHash(r), nonce)
}

private fun validChannelAcceptance(request: ChannelCheckRequest, acceptance: ChannelCheckAcceptance) {
    val a = parseChannelCheckMessage(acceptance.toJson().stringify()) as? ChannelCheckAcceptance
    require(
        a != null && a.id == request.id && a.context == request.context && a.from == request.to && a.to == request.from &&
            a.requestHash == channelCheckHash(request) && a.createdAt >= request.createdAt && a.createdAt < request.expiresAt,
    ) { "Acceptance does not match channel request" }
}

public fun createChannelCheckReveal(
    request: ChannelCheckRequest,
    acceptance: ChannelCheckAcceptance,
    nonce: String,
    now: Long,
): ChannelCheckReveal {
    val r = validChannelRequest(request, now)
    validChannelAcceptance(r, acceptance)
    require(now >= acceptance.createdAt && channelCheckCommitment(r.id, r.context, r.from, r.to, nonce) == r.commitment) {
        "Reveal does not match channel commitment"
    }
    return ChannelCheckReveal(r.id, r.context, r.from, r.to, now, channelCheckHash(r), channelCheckHash(acceptance), nonce)
}

public fun channelCheckWords(
    request: ChannelCheckRequest,
    acceptance: ChannelCheckAcceptance,
    reveal: ChannelCheckReveal,
    local: String,
): VerificationWords {
    val expected = createChannelCheckReveal(request, acceptance, reveal.nonce, reveal.createdAt)
    require(channelCheckHash(expected) == channelCheckHash(reveal) && (local == request.from || local == request.to)) {
        "Invalid channel transcript"
    }
    // Reveal timestamps never enter word material, so nobody can grind words by delaying.
    val material = Hex.decode(
        transcriptDigest(
            "signet-contacts:channel-words-material:v1",
            listOf(channelCheckHash(request).toJson(), channelCheckHash(acceptance).toJson(), reveal.nonce.toJson()),
        ),
    )
    try {
        val roles = listOf(request.from, request.to).sorted()
        val pair = SpokenToken.directionalPair(material, CHANNEL_CHECK_WORDS_NAMESPACE, roles[0] to roles[1], 0, 3)
        return VerificationWords(pair.getValue(local), pair.getValue(if (local == request.from) request.to else request.from))
    } finally {
        material.fill(0)
    }
}

public fun beginChannelCheck(request: ChannelCheckRequest, nonce: String): ChannelCheckState {
    channelCheckHash(request)
    require(channelCheckCommitment(request.id, request.context, request.from, request.to, nonce) == request.commitment) {
        "Wrong channel request nonce"
    }
    return ChannelCheckState(ExchangeRole.REQUESTER, request, nonce, phase = ExchangePhase.REQUESTED)
}

public fun acceptChannelCheck(request: ChannelCheckRequest, nonce: String, now: Long): ChannelCheckState =
    ChannelCheckState(ExchangeRole.RECIPIENT, request, nonce, createChannelCheckAcceptance(request, nonce, now), phase = ExchangePhase.ACCEPTED)

public fun receiveChannelCheckAcceptance(state: ChannelCheckState, acceptance: ChannelCheckAcceptance, now: Long): ChannelCheckState {
    require(state.role == ExchangeRole.REQUESTER && state.phase != ExchangePhase.DECLINED) { "Channel check cannot accept" }
    state.acceptance?.let { pinned ->
        require(channelCheckHash(pinned) == channelCheckHash(acceptance)) { "Channel acceptance already pinned" }
        return state
    }
    val reveal = createChannelCheckReveal(state.request, acceptance, state.nonce, now)
    return state.copy(acceptance = acceptance, reveal = reveal, phase = ExchangePhase.REVEAL_PENDING)
}

public fun receiveChannelCheckReveal(state: ChannelCheckState, reveal: ChannelCheckReveal, now: Long): ChannelCheckState {
    val acceptance = state.acceptance
    require(
        state.role == ExchangeRole.RECIPIENT && acceptance != null && state.phase != ExchangePhase.DECLINED &&
            isTime(now) && now >= reveal.createdAt && now < state.request.expiresAt,
    ) { "Channel check cannot reveal" }
    channelCheckWords(state.request, acceptance!!, reveal, state.request.to)
    state.reveal?.let { pinned ->
        require(channelCheckHash(pinned) == channelCheckHash(reveal)) { "Channel reveal already pinned" }
        return state
    }
    return state.copy(reveal = reveal, phase = ExchangePhase.COMPLETE)
}

public fun confirmChannelCheckRevealSent(state: ChannelCheckState): ChannelCheckState {
    val acceptance = state.acceptance
    val reveal = state.reveal
    require(state.role == ExchangeRole.REQUESTER && state.phase == ExchangePhase.REVEAL_PENDING && acceptance != null && reveal != null) {
        "No channel reveal to confirm"
    }
    channelCheckWords(state.request, acceptance!!, reveal!!, state.request.from)
    return state.copy(phase = ExchangePhase.COMPLETE)
}
