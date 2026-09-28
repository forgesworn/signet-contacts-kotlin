package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.arr
import dev.forgesworn.signet.contacts.json.isNumber
import dev.forgesworn.signet.contacts.json.isObjectLike
import dev.forgesworn.signet.contacts.json.jsonArray
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.nonNegativeSafeLong
import dev.forgesworn.signet.contacts.json.str
import dev.forgesworn.signet.contacts.json.toJson

/**
 * App -> Signet proposals. A proposal is NOT a write: it is a signed request
 * Signet validates against the grant. Only `add-ken` and `rename-app-label`
 * exist in v2. A rename carries the GRANT-SCOPED contact id.
 */

private fun JsonValue.prop(key: String): JsonValue? = (this as? JsonObject)?.fields?.get(key)

public fun parseProposal(raw: JsonValue?): ContactProposalV1? {
    val o = raw as? JsonObject ?: return null
    if (!o["v"].isNumber(1)) return null
    if (!isHex(o["grantId"], 32)) return null
    if (!isHex(o["operationId"], 32)) return null
    val createdAt = o["createdAt"].nonNegativeSafeLong() ?: return null
    val value = o["value"]
    if (value == null || !value.isObjectLike()) return null
    val grantId = o["grantId"].str()!!
    val operationId = o["operationId"].str()!!

    return when (o["action"].str()) {
        "add-ken" -> {
            if (!isHex(value.prop("pubkey"), 64)) return null
            val displayName = sanitizeWireText(value.prop("displayName"), MAX_DISPLAY_NAME)
            if (displayName.isEmpty()) return null
            ContactProposalV1(grantId, operationId, AddKenValue(value.prop("pubkey").str()!!, displayName), createdAt)
        }
        "rename-app-label" -> {
            if (!isHex(value.prop("contactId"), 32)) return null
            val label = sanitizeWireText(value.prop("label"), MAX_APP_LABEL)
            if (label.isEmpty()) return null
            // R-7: a rename with no comparable timestamp cannot be applied safely.
            val updatedAt = value.prop("updatedAt").nonNegativeSafeLong() ?: return null
            ContactProposalV1(grantId, operationId, RenameAppLabelValue(value.prop("contactId").str()!!, label, updatedAt), createdAt)
        }
        else -> null
    }
}

public fun parseProposalBatch(json: String): ProposalBatch? {
    val o = Json.parseOrNull(json) as? JsonObject ?: return null
    if (!o["v"].isNumber(1)) return null
    val proposals = o["proposals"].arr() ?: return null
    return ProposalBatch(proposals.take(MAX_PROPOSALS_PER_BATCH).mapNotNull(::parseProposal))
}

/** Round-trip-validating builder: a cap breach or a field that would be
 *  rewritten throws [IllegalArgumentException] here, not silently in transit. */
public fun buildProposalBatch(proposals: List<ContactProposalV1>): String {
    require(proposals.isNotEmpty()) { "signet-contacts: a proposal batch must not be empty" }
    require(proposals.size <= MAX_PROPOSALS_PER_BATCH) {
        "signet-contacts: at most $MAX_PROPOSALS_PER_BATCH proposals per batch"
    }
    val json = jsonObject("v" to 1.toJson(), "proposals" to jsonArray(proposals.map { it.toJson() })).stringify()
    val reparsed = parseProposalBatch(json) ?: throw IllegalArgumentException("signet-contacts: proposal batch is not parseable")
    require(reparsed.proposals == proposals) { "signet-contacts: proposal batch would be rewritten in transit" }
    return json
}

/**
 * Mint a wire proposal from a consumer draft. `operationId` is the
 * idempotency key. R-7: a rename's `updatedAt` comes from the draft when
 * given, else from [nowMs] (ms epoch).
 */
public fun draftToProposal(
    draft: ContactProposalDraft,
    grantId: String,
    createdAt: Long,
    nowMs: () -> Long = System::currentTimeMillis,
): ContactProposalV1 = when (draft) {
    is ContactProposalDraft.RenameAppLabel -> ContactProposalV1(
        grantId, randomHex(16), RenameAppLabelValue(draft.contactId, draft.label, draft.updatedAt ?: nowMs()), createdAt,
    )
    is ContactProposalDraft.AddKen -> ContactProposalV1(grantId, randomHex(16), draft.value, createdAt)
}

public fun proposalEventTemplate(appPubkey: String, grantId: String, createdAt: Long, content: String): UnsignedNostrEvent =
    UnsignedNostrEvent(PROPOSAL_KIND, appPubkey, createdAt, listOf(listOf("d", proposalTag(grantId, appPubkey))), content)

public fun proposalFilter(appPubkey: String, grantId: String): NostrFilter =
    NostrFilter(kinds = listOf(PROPOSAL_KIND), authors = listOf(appPubkey), tags = mapOf("#d" to listOf(proposalTag(grantId, appPubkey))), limit = 1)
