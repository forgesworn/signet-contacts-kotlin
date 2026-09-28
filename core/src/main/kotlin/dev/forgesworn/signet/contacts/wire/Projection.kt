package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.internal.Js
import dev.forgesworn.signet.contacts.internal.WhatwgUrl
import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonArray
import dev.forgesworn.signet.contacts.json.JsonBool
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonString
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.arr
import dev.forgesworn.signet.contacts.json.isNumber
import dev.forgesworn.signet.contacts.json.isObjectLike
import dev.forgesworn.signet.contacts.json.isTrue
import dev.forgesworn.signet.contacts.json.nonNegativeSafeLong
import dev.forgesworn.signet.contacts.json.str

/**
 * ContactProjectionV2: the per-grant encrypted view a consuming app reads.
 * The builder is strict and the parser forgiving: [buildProjection] re-parses
 * its own output and throws unless everything survived, while [parseProjection]
 * drops one malformed contact rather than the whole directory, except that a
 * field the scopes do not cover refuses the whole projection (consent).
 */

private const val MAX_CHECKS_PER_CONTACT = 128

/** https only: a projected URL is fetched by the consumer. */
private fun safeHttpsUrl(value: JsonValue?): String? {
    val s = value.str() ?: return null
    if (s.isEmpty() || s.length > MAX_URL_LEN) return null
    return if (WhatwgUrl.parse(s)?.protocol == "https:") s else null
}

private fun JsonValue.prop(key: String): JsonValue? = (this as? JsonObject)?.fields?.get(key)

private fun parseIdentity(raw: JsonValue): ProjectedIdentity? {
    if (!raw.isObjectLike()) return null
    val pubkey = raw.prop("pubkey")
    if (!isHex(pubkey, 64)) return null
    val v = raw.prop("verification")
    val verification = if (v == null) null else ProjectedVerification.fromWire(v.str()) ?: return null
    return ProjectedIdentity(pubkey.str()!!, verification)
}

private fun parseMethod(raw: JsonValue): ProjectedMethod? {
    if (!raw.isObjectLike()) return null
    val kind = ProjectedMethodKind.fromWire(raw.prop("kind").str()) ?: return null
    val value = sanitizeWireText(raw.prop("value"), MAX_METHOD_VALUE)
    if (value.isEmpty()) return null
    val v = raw.prop("verification")
    val verification = if (v == null) null else MethodVerification.fromWire(v.str()) ?: return null
    return ProjectedMethod(kind, value, verification)
}

private fun parseAvatar(raw: JsonValue?): ProjectedAvatar? {
    if (raw == null || !raw.isObjectLike()) return null
    val url = safeHttpsUrl(raw.prop("url")) ?: return null
    val hash = raw.prop("hash")
    if (!isHex(hash, 64)) return null
    val key = raw.prop("key")
    return ProjectedAvatar(url, hash.str()!!, if (isHex(key, 64)) key.str() else null)
}

/**
 * Parse one contact. Null when the contact cannot be trusted at all, or when
 * it carries a field [scopes] do not cover; an individually unparseable
 * OPTIONAL field is dropped, not fatal.
 */
public fun parseProjectedContact(raw: JsonValue?, scopes: Iterable<String>): ProjectedContact? {
    if (raw == null || !raw.isObjectLike()) return null
    if (uncoveredContactFields(raw, scopes).isNotEmpty()) return null
    val contactId = raw.prop("contactId")
    if (!isHex(contactId, 32)) return null

    val typeRaw = raw.prop("type")
    val type = if (typeRaw == null) null else ProjectedType.fromWire(typeRaw.str()) ?: return null
    val tierRaw = raw.prop("effectiveTier")
    val tier = if (tierRaw == null) null else ProjectedTier.fromWire(tierRaw.str()) ?: return null
    val sourceRaw = raw.prop("tierSource")
    val source = if (sourceRaw == null) null else ProjectedTierSource.fromWire(sourceRaw.str()) ?: return null
    val blockedRaw = raw.prop("blocked")
    if (blockedRaw != null && blockedRaw !is JsonBool) return null

    val identities = raw.prop("identities").arr()
        ?.take(MAX_IDENTITIES_PER_CONTACT)?.mapNotNull(::parseIdentity)?.takeIf { it.isNotEmpty() }
    val displayName = (raw.prop("displayName") as? JsonString)
        ?.let { sanitizeWireText(it.value, MAX_DISPLAY_NAME) }?.takeIf { it.isNotEmpty() }
    val roles = raw.prop("roles").arr()
        ?.take(MAX_ROLES_PER_CONTACT)?.map { sanitizeWireText(it, MAX_ROLE_LEN) }?.filter { it.isNotEmpty() }
        ?.takeIf { it.isNotEmpty() }
    val methods = raw.prop("contactMethods").arr()
        ?.take(MAX_METHODS_PER_CONTACT)?.mapNotNull(::parseMethod)?.takeIf { it.isNotEmpty() }
    val checks = raw.prop("checks").arr()?.take(MAX_CHECKS_PER_CONTACT)?.mapNotNull { c ->
        if (!c.isObjectLike()) return@mapNotNull null
        val pubkey = c.prop("pubkey")
        // The reference compares String(method); this port requires a string.
        val method = CheckMethod.fromWire(c.prop("method").str())
        val checkedAt = c.prop("checkedAt").nonNegativeSafeLong()
        if (!isHex(pubkey, 64) || method == null || checkedAt == null) null
        else ProjectedCheck(pubkey.str()!!, method, checkedAt)
    }?.takeIf { it.isNotEmpty() }
    val linked = raw.prop("linkedPubkeys").arr()
        ?.take(MAX_LINKED_PUBKEYS)?.filter { isHex(it, 64) }?.map { it.str()!! }?.takeIf { it.isNotEmpty() }

    return ProjectedContact(
        contactId = contactId.str()!!,
        type = type,
        effectiveTier = tier,
        tierSource = source,
        blocked = (blockedRaw as? JsonBool)?.value,
        identities = identities,
        displayName = displayName,
        avatar = parseAvatar(raw.prop("avatar")),
        roles = roles,
        contactMethods = methods,
        checks = checks,
        linkedPubkeys = linked,
    )
}

@JvmName("parseProjectedContactForCapabilities")
public fun parseProjectedContact(raw: JsonValue?, scopes: Iterable<Capability>): ProjectedContact? =
    parseProjectedContact(raw, scopes.map { it.wire })

/** Parse a projection plaintext, or null for anything this wire refuses. */
public fun parseProjection(json: String): ContactProjectionV2? = parseProjection(Json.parseOrNull(json))

/** [parseProjection] over an already-parsed JSON value. */
public fun parseProjection(raw: JsonValue?): ContactProjectionV2? {
    val o = raw as? JsonObject ?: return null
    if (!o["v"].isNumber(2)) return null
    if (!isHex(o["grantId"], 32)) return null
    val scopesRaw = o["scopes"].arr() ?: return null
    val issuedAt = o["issuedAt"].nonNegativeSafeLong() ?: return null
    val expiresAt = o["expiresAt"].nonNegativeSafeLong() ?: return null
    if (expiresAt < issuedAt) return null
    val frontierRaw = o["frontier"]
    if (frontierRaw == null || !frontierRaw.isObjectLike()) return null
    val maxClock = frontierRaw.prop("maxClock").nonNegativeSafeLong() ?: return null
    val opCount = frontierRaw.prop("opCount").nonNegativeSafeLong() ?: return null
    // C13: a snapshot names its publisher and its moment.
    val publishedAt = frontierRaw.prop("publishedAt").nonNegativeSafeLong() ?: return null
    val deviceId = frontierRaw.prop("deviceId")
    if (!isHex(deviceId, 32)) return null
    val contactsRaw = o["contacts"].arr() ?: return null

    // Cap before filtering, as everywhere on this wire.
    val scopes = normaliseCapabilities(scopesRaw.take(MAX_CAPABILITIES).mapNotNull { it.str()?.let(Capability::fromWire) })
    val scopeWires = scopes.map { it.wire }
    // M8: a cut the READER makes is as much a truncation as the producer's.
    val parserCapped = contactsRaw.size > MAX_CONTACTS_PER_PROJECTION
    val delivered = contactsRaw.take(MAX_CONTACTS_PER_PROJECTION)
    // Consent (\u00a710): an uncovered field anywhere refuses the whole projection.
    if (delivered.any { uncoveredContactFields(it, scopeWires).isNotEmpty() }) return null
    // A later duplicate contactId is dropped, keeping the first.
    val seen = HashSet<String>()
    val contacts = delivered.mapNotNull { parseProjectedContact(it, scopeWires) }.filter { seen.add(it.contactId) }

    return ContactProjectionV2(
        grantId = o["grantId"].str()!!,
        scopes = scopes,
        frontier = ProjectionFrontier(maxClock, opCount, publishedAt, deviceId.str()!!),
        issuedAt = issuedAt,
        expiresAt = expiresAt,
        contacts = contacts,
        revoked = o["revoked"].isTrue(),
        truncated = o["truncated"].isTrue() || parserCapped,
    )
}

/**
 * Serialise [projection], prove it survives its own parser, then serialise
 * again from the reparsed (canonical) values. Throws
 * [IllegalArgumentException] on an uncovered field, a contact or field that
 * would be dropped or rewritten in transit, or a body over [MAX_WIRE_BYTES].
 */
public fun buildProjection(projection: ContactProjectionV2): String {
    val scopeWires = projection.scopes.map { it.wire }
    for (contact in projection.contacts) {
        val uncovered = uncoveredContactFields(contact.toJson(), scopeWires)
        require(uncovered.isEmpty()) {
            "signet-contacts: projection carries fields its scopes do not cover: ${uncovered.joinToString(", ")}"
        }
    }
    val draft = projection.toJson()
    val reparsed = parseProjection(draft.stringify())
        ?: throw IllegalArgumentException("signet-contacts: projection is not parseable")
    require(reparsed.contacts.size == projection.contacts.size) {
        "signet-contacts: projection would drop contacts in transit"
    }
    val draftContacts = (draft["contacts"] as JsonArray).items
    require(reparsed.contacts.map { it.toJson() } == draftContacts) {
        "signet-contacts: projection would rewrite contact fields in transit"
    }
    require(projection.scopes.toSet() == reparsed.scopes.toSet()) {
        "signet-contacts: projection would narrow scopes in transit"
    }
    val json = reparsed.toJson().stringify()
    val bytes = Js.utf8(json).size
    require(bytes <= MAX_WIRE_BYTES) { "signet-contacts: projection is $bytes bytes, over the $MAX_WIRE_BYTES cap" }
    return json
}

/** UTF-8 byte length of the CANONICAL body, measured as [buildProjection] measures it. */
public fun projectionByteLength(projection: ContactProjectionV2): Int {
    val draft = projection.toJson().stringify()
    val reparsed = parseProjection(draft) ?: return Js.utf8(draft).size
    return Js.utf8(reparsed.toJson().stringify()).size
}

public fun projectionEventTemplate(railPubkey: String, grantId: String, createdAt: Long, content: String): UnsignedNostrEvent =
    UnsignedNostrEvent(PROJECTION_KIND, railPubkey, createdAt, listOf(listOf("d", projectionTag(grantId))), content)

public fun projectionFilter(railPubkey: String, grantId: String): NostrFilter =
    NostrFilter(kinds = listOf(PROJECTION_KIND), authors = listOf(railPubkey), tags = mapOf("#d" to listOf(projectionTag(grantId))), limit = 1)
