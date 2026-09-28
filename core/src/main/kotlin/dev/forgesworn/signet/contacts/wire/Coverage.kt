package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.json.JsonArray
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.isObjectLike
import dev.forgesworn.signet.contacts.json.isTrue
import dev.forgesworn.signet.contacts.internal.jsString

/**
 * Field coverage: the ONE table that says which capability unlocks which
 * projected-contact field (WIRE.md \u00a76 and \u00a710). `requires` is all-of;
 * `orIfBlocked` is an alternative all-of list for a contact carrying
 * `blocked: true` only. A field with no entry is covered by nothing.
 */
public data class FieldCoverageRule(
    val requires: List<Capability>,
    val orIfBlocked: List<Capability>? = null,
)

private val DIRECTORY = Capability.READ_DIRECTORY
private val BLOCKS = Capability.BLOCKS_READ

/** Keyed by field path. `contactMethods[kind=<k>]` is one entry per method kind. */
public val FIELD_COVERAGE: Map<String, FieldCoverageRule> = linkedMapOf(
    "contact" to FieldCoverageRule(listOf(DIRECTORY), listOf(BLOCKS)),
    "identities" to FieldCoverageRule(listOf(DIRECTORY), listOf(BLOCKS)),
    "identities[].verification" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_CHECKS)),
    "displayName" to FieldCoverageRule(listOf(DIRECTORY)),
    "effectiveTier" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_TIER)),
    "tierSource" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_TIER)),
    "roles" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_ROLES)),
    "contactMethods" to FieldCoverageRule(listOf(DIRECTORY)),
    "contactMethods[kind=phone]" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_METHOD_PHONE)),
    "contactMethods[kind=email]" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_METHOD_EMAIL)),
    "contactMethods[kind=website]" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_METHOD_WEBSITE)),
    "contactMethods[kind=postal-address]" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_METHOD_POSTAL_ADDRESS)),
    "contactMethods[kind=other]" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_METHOD_OTHER)),
    "contactMethods[].verification" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_CHECKS)),
    "checks" to FieldCoverageRule(listOf(DIRECTORY, Capability.READ_CHECK_RECORDS)),
    "blocked" to FieldCoverageRule(listOf(BLOCKS)),
)

/** Contact-level keys that no capability covers. */
private val NEVER_COVERED = listOf("avatar", "type", "linkedPubkeys")
private val SCOPED_KEYS = listOf("identities", "displayName", "effectiveTier", "tierSource", "roles", "contactMethods", "checks", "blocked")

private fun covered(path: String, scopes: Set<String>, blocked: Boolean): Boolean {
    val rule = FIELD_COVERAGE[path] ?: return false
    if (rule.requires.all { it.wire in scopes }) return true
    return blocked && rule.orIfBlocked != null && rule.orIfBlocked.all { it.wire in scopes }
}

/** A JavaScript property read: present (even as JSON `null`) means "not undefined". */
private fun JsonValue.prop(key: String): JsonValue? = (this as? JsonObject)?.fields?.get(key)

/**
 * Field paths a raw (unparsed) contact carries that [scopes] do not cover.
 * Empty means the contact is within the grant. Judged by presence on the wire,
 * not by whether the field would survive parsing.
 */
public fun uncoveredContactFields(raw: JsonValue?, scopes: Iterable<String>): List<String> {
    if (raw == null || !raw.isObjectLike()) return emptyList()
    val set = scopes.toSet()
    val blocked = raw.prop("blocked").isTrue()
    val out = ArrayList<String>()
    fun has(k: String) = raw.prop(k) != null

    if (!covered("contact", set, blocked)) out.add("contact")
    for (key in SCOPED_KEYS) if (has(key) && !covered(key, set, blocked)) out.add(key)
    for (key in NEVER_COVERED) if (has(key)) out.add(key)

    (raw.prop("identities") as? JsonArray)?.let { identities ->
        val verified = identities.items.any { it.isObjectLike() && it.prop("verification") != null }
        if (verified && !covered("identities[].verification", set, blocked)) out.add("identities[].verification")
    }
    (raw.prop("contactMethods") as? JsonArray)?.let { methods ->
        for (m in methods.items) {
            if (!m.isObjectLike()) continue
            val path = "contactMethods[kind=${jsString(m.prop("kind"))}]"
            if (!covered(path, set, blocked) && path !in out) out.add(path)
            if (m.prop("verification") != null && !covered("contactMethods[].verification", set, blocked) &&
                "contactMethods[].verification" !in out
            ) out.add("contactMethods[].verification")
        }
    }
    return out
}

@JvmName("uncoveredContactFieldsForCapabilities")
public fun uncoveredContactFields(raw: JsonValue?, scopes: Iterable<Capability>): List<String> =
    uncoveredContactFields(raw, scopes.map { it.wire })
