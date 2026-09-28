package dev.forgesworn.signet.contacts.wire

import java.text.Normalizer

/**
 * Consumer-side state reduction: the half of the contract a consuming app
 * MUST get right, so it lives in the SDK.
 *
 * 1. Blocked is sticky. Expiry and revocation never un-block anybody; only a
 *    newer, accepted, non-revoked projection may shrink the Blocked set.
 * 2. Monotonic frontier, ordered by `(publishedAt, maxClock)` (R-30). A
 *    projection not strictly newer than the one held is ignored, even after a
 *    revocation. A revocation itself is exempt, but never lowers the floor.
 * 3. Freshness is advisory for reads, never for blocks.
 */

public fun emptyContactsState(): ContactsState = ContactsState(null, null, 0, emptyList(), false)

private fun blockedPubkeysOf(contacts: List<ProjectedContact>): List<String> {
    val out = LinkedHashSet<String>()
    for (contact in contacts) {
        if (contact.blocked != true) continue
        contact.identities?.forEach { out.add(it.pubkey) }
        contact.linkedPubkeys?.forEach { out.add(it) }
    }
    return out.toList()
}

/**
 * Apply [projection] to [state]. Returns the SAME instance (`===`) when the
 * projection is rejected: another grant's, or not newer than what is held.
 */
public fun applyProjection(state: ContactsState, projection: ContactProjectionV2, nowSec: Long): ContactsState {
    if (state.grantId != null && state.grantId != projection.grantId) return state

    if (projection.revoked) {
        // Apply even an out-of-order revocation, but never lower the replay floor.
        val held = state.projection?.frontier
        val incoming = projection.frontier
        val frontier = if (held != null && (held.publishedAt > incoming.publishedAt ||
                (held.publishedAt == incoming.publishedAt && held.maxClock > incoming.maxClock))
        ) held else incoming
        return ContactsState(
            grantId = projection.grantId,
            projection = projection.copy(frontier = frontier.copy(), contacts = emptyList()),
            receivedAt = nowSec,
            blockedPubkeys = state.blockedPubkeys, // sticky through revocation
            revoked = true,
        )
    }

    state.projection?.let { heldProjection ->
        val held = heldProjection.frontier
        val incoming = projection.frontier
        val notNewer = incoming.publishedAt < held.publishedAt ||
            (incoming.publishedAt == held.publishedAt && incoming.maxClock <= held.maxClock)
        if (notNewer) return state
    }

    return ContactsState(
        grantId = projection.grantId,
        projection = projection,
        receivedAt = nowSec,
        blockedPubkeys = blockedPubkeysOf(projection.contacts),
        revoked = false,
    )
}

/** True while the held projection is inside its issued staleness window. */
public fun isFresh(state: ContactsState, nowSec: Long): Boolean {
    val projection = state.projection ?: return false
    if (state.revoked) return false
    return nowSec <= projection.expiresAt
}

/** Every pubkey the app must filter at ingress and at display time. */
public fun blockedSetOf(state: ContactsState): Set<String> = LinkedHashSet(state.blockedPubkeys)

/** Contacts an app may show: blocked ones excluded, nothing at all when revoked. */
public fun visibleContacts(state: ContactsState): List<ProjectedContact> {
    val projection = state.projection ?: return emptyList()
    if (state.revoked) return emptyList()
    return projection.contacts.filter { it.blocked != true }
}

// ---------------------------------------------------------------------------
// Check menu and local key lookup
// ---------------------------------------------------------------------------

public data class ContactCheckMenuItem(val method: CheckMethod, val label: String, val guidance: String)

/** A menu for developer-selected UI, never a ranking or automatic proof. */
public val CONTACT_CHECK_MENU: List<ContactCheckMenuItem> = listOf(
    ContactCheckMenuItem(CheckMethod.IN_PERSON, "In person", "Compare the person and their invite QR in person."),
    ContactCheckMenuItem(CheckMethod.WORDS, "Words", "Compare both directional codes after the signed commit-and-reveal exchange."),
    ContactCheckMenuItem(CheckMethod.NIP05, "NIP-05", "Fetch only after an explicit Check action; show the domain and date, not a trust tick."),
    ContactCheckMenuItem(CheckMethod.APP_ATTESTED, "App attestation", "Show the accountable issuer and independently validate its signed attestation."),
)

public enum class ContactKeyLookupStatus(public val wire: String) {
    KNOWN("known"), NOT_IN_CONTACTS("not-in-contacts"), NAME_CLASH("name-clash"), UNAVAILABLE("unavailable"),
}

public data class ContactKeyLookup(
    val status: ContactKeyLookupStatus,
    val contacts: List<ProjectedContact>,
    val fresh: Boolean,
    val blocked: Boolean,
)

private val HEX64_ANY = Regex("^[0-9a-f]{64}$")

/** Uses only the granted local snapshot; performs no name or network lookup.
 *  Throws [IllegalArgumentException] for a pubkey that is not 64 hex. */
public fun lookupContactKey(state: ContactsState, pubkey: String, now: Long, displayName: String? = null): ContactKeyLookup {
    val key = pubkey.lowercase(java.util.Locale.ROOT)
    require(HEX64_ANY.matches(key)) { "Invalid contact public key" }
    val result = ContactKeyLookup(ContactKeyLookupStatus.UNAVAILABLE, emptyList(), isFresh(state, now), key in state.blockedPubkeys)
    val projection = state.projection
    if (state.revoked || projection == null || Capability.READ_DIRECTORY !in projection.scopes) return result
    val contacts = projection.contacts
    val known = contacts.filter { c -> c.identities?.any { it.pubkey == key } == true }
    if (known.isNotEmpty()) return result.copy(status = ContactKeyLookupStatus.KNOWN, contacts = known)
    fun name(value: String?): String = dev.forgesworn.signet.contacts.internal.Js.trim(
        Normalizer.normalize(sanitizeWireText(value ?: "", MAX_DISPLAY_NAME), Normalizer.Form.NFKC).lowercase(java.util.Locale.ROOT),
    )
    val requested = name(displayName)
    val clashes = if (requested.isNotEmpty()) {
        contacts.filter { c -> name(c.displayName) == requested && !c.identities.isNullOrEmpty() }
    } else emptyList()
    return result.copy(
        status = if (clashes.isNotEmpty()) ContactKeyLookupStatus.NAME_CLASH else ContactKeyLookupStatus.NOT_IN_CONTACTS,
        contacts = clashes,
    )
}
