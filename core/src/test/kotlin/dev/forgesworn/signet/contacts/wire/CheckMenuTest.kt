package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private val KEY = "a".repeat(64)
private val OTHER = "b".repeat(64)

private fun state(): ContactsState = ContactsState(
    grantId = "f".repeat(32),
    projection = ContactProjectionV2(
        grantId = "f".repeat(32),
        scopes = listOf(Capability.READ_DIRECTORY),
        frontier = ProjectionFrontier(0, 0, 0, "0".repeat(32)),
        issuedAt = 10,
        expiresAt = 100,
        contacts = listOf(ProjectedContact(contactId = "c".repeat(32), displayName = "Ada", identities = listOf(ProjectedIdentity(KEY)))),
    ),
    receivedAt = 0,
    blockedPubkeys = emptyList(),
    revoked = false,
)

class CheckMenuTest {
    @Test
    fun `looks up keys and flags same-name different-key records without inferring verification`() {
        assertEquals(ContactKeyLookupStatus.KNOWN, lookupContactKey(state(), KEY, 20).status)
        assertEquals(ContactKeyLookupStatus.NAME_CLASH, lookupContactKey(state(), OTHER, 20, " ADA ").status)
        assertEquals(ContactKeyLookupStatus.NOT_IN_CONTACTS, lookupContactKey(state(), OTHER, 20).status)
        assertEquals(listOf(CheckMethod.IN_PERSON, CheckMethod.WORDS, CheckMethod.NIP05, CheckMethod.APP_ATTESTED), CONTACT_CHECK_MENU.map { it.method })
    }

    @Test
    fun `withholds revoked-ungranted directories while keeping sticky blocks`() {
        val revoked = state().copy(revoked = true, blockedPubkeys = listOf(KEY))
        val lookup = lookupContactKey(revoked, KEY, 20)
        assertEquals(ContactKeyLookupStatus.UNAVAILABLE, lookup.status)
        assertEquals(emptyList(), lookup.contacts)
        assertTrue(lookup.blocked)
        assertEquals(ContactKeyLookupStatus.UNAVAILABLE, lookupContactKey(emptyContactsState(), KEY, 20).status)
        val stale = lookupContactKey(state(), KEY, 101)
        assertEquals(ContactKeyLookupStatus.KNOWN, stale.status)
        assertFalse(stale.fresh)
    }
}
