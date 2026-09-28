package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.arr
import dev.forgesworn.signet.contacts.json.isNumber
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.jsonStrings
import dev.forgesworn.signet.contacts.json.num
import dev.forgesworn.signet.contacts.json.str
import dev.forgesworn.signet.contacts.json.toJson

/**
 * Pairing ack v2: the reply Signet publishes after the owner approves a grant.
 * The plaintext here is NIP-44-encrypted to the app pubkey; the carrying event
 * is signed by a throwaway ephemeral key. `grantedCapabilities` may be
 * NARROWER than the request, and unknown tokens are dropped.
 */

public fun buildPairingAckV2(ack: PairingAckV2): String = jsonObject(
    "v" to 2.toJson(),
    "grantId" to ack.grantId.toJson(),
    "railPubkey" to ack.railPubkey.toJson(),
    "projectionTag" to ack.projectionTag.toJson(),
    "proposalTag" to ack.proposalTag.toJson(),
    "relay" to ack.relay.toJson(),
    "grantedCapabilities" to jsonStrings(ack.grantedCapabilities.map { it.wire }),
    "maxStalenessSeconds" to ack.maxStalenessSeconds.toJson(),
    "challenge" to ack.challenge.toJson(),
).stringify()

/** Parse and validate an ack plaintext against the app's own [expectedChallenge]
 *  (compared byte for byte). Null for anything else. */
public fun parsePairingAckV2(plaintext: String, expectedChallenge: String): PairingAckV2? {
    val o = Json.parseOrNull(plaintext) as? JsonObject ?: return null
    if (!o["v"].isNumber(2)) return null
    val challenge = o["challenge"].str() ?: return null
    if (challenge != expectedChallenge) return null
    if (!isHex(o["grantId"], 32)) return null
    if (!isHex(o["railPubkey"], 64)) return null
    if (!isHex(o["projectionTag"], 32)) return null
    if (!isHex(o["proposalTag"], 32)) return null
    val relay = o["relay"].str()
    if (relay == null || !isValidContactsRelayUrl(relay)) return null
    val grantedRaw = o["grantedCapabilities"].arr() ?: return null
    val granted = normaliseCapabilities(grantedRaw.mapNotNull { it.str()?.let(Capability::fromWire) })
    if (granted.isEmpty()) return null
    return PairingAckV2(
        grantId = o["grantId"].str()!!,
        railPubkey = o["railPubkey"].str()!!,
        projectionTag = o["projectionTag"].str()!!,
        proposalTag = o["proposalTag"].str()!!,
        relay = relay,
        grantedCapabilities = granted,
        maxStalenessSeconds = clampStaleness(o["maxStalenessSeconds"].num()),
        challenge = challenge,
    )
}

/** The ephemeral kind-21237 carrier. [ephemeralPubkey] is a throwaway key. */
public fun ackEventTemplate(ephemeralPubkey: String, appPubkey: String, createdAt: Long, content: String): UnsignedNostrEvent =
    UnsignedNostrEvent(ACK_KIND, ephemeralPubkey, createdAt, listOf(listOf("p", appPubkey)), content)

/**
 * The STORED carrier: same content and key as [ackEventTemplate], addressed by
 * [ackTag] and bounded by a NIP-40 `expiration` at `createdAt +
 * PAIRING_FRESHNESS_SECONDS`.
 */
public fun storedAckEventTemplate(
    ephemeralPubkey: String,
    appPubkey: String,
    createdAt: Long,
    content: String,
    challenge: String,
): UnsignedNostrEvent = UnsignedNostrEvent(
    ACK_STORED_KIND,
    ephemeralPubkey,
    createdAt,
    listOf(
        listOf("d", ackTag(challenge)),
        listOf("p", appPubkey),
        listOf("expiration", (createdAt + PAIRING_FRESHNESS_SECONDS).toString()),
    ),
    content,
)

/** Reduce a validated ack to the shape a consumer persists. */
public fun pairingFromAck(ack: PairingAckV2, pairedAt: Long): PairingV2 = PairingV2(
    grantId = ack.grantId,
    railPubkey = ack.railPubkey,
    projectionTag = ack.projectionTag,
    proposalTag = ack.proposalTag,
    relay = ack.relay,
    grantedCapabilities = ack.grantedCapabilities,
    maxStalenessSeconds = ack.maxStalenessSeconds,
    pairedAt = pairedAt,
)
