package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue

private val GRANT = "f".repeat(32)
private val DEVICE = "2".repeat(32)
private const val ISSUED = 1_700_000_000L
private const val EXPIRES = ISSUED + 21600

private fun contact(id: String, blocked: Boolean, pubkey: String): ProjectedContact = ProjectedContact(
    contactId = id, type = ProjectedType.PERSON, blocked = blocked,
    identities = listOf(ProjectedIdentity(pubkey, ProjectedVerification.PROVEN)),
    effectiveTier = if (blocked) ProjectedTier.NONE else ProjectedTier.KITH, tierSource = ProjectedTierSource.DIRECT,
)

private fun projection(
    grantId: String = GRANT,
    scopes: List<Capability> = listOf(Capability.READ_DIRECTORY, Capability.BLOCKS_READ),
    frontier: ProjectionFrontier = ProjectionFrontier(5, 10, ISSUED, DEVICE),
    issuedAt: Long = ISSUED,
    expiresAt: Long = EXPIRES,
    contacts: List<ProjectedContact> = listOf(contact("a".repeat(32), false, "b".repeat(64)), contact("c".repeat(32), true, "d".repeat(64))),
    revoked: Boolean = false,
): ContactProjectionV2 = ContactProjectionV2(grantId, scopes, frontier, issuedAt, expiresAt, contacts, revoked)

class StateTest {
    @Test
    fun `applyProjection accepts the first projection and binds the grant`() {
        val state = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        assertEquals(GRANT, state.grantId)
        assertEquals(2, state.projection?.contacts?.size)
        assertEquals(ISSUED + 1, state.receivedAt)
        assertFalse(state.revoked)
    }

    @Test
    fun `applyProjection ignores a projection for a different grant`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val other = applyProjection(first, projection(grantId = "0".repeat(32)), ISSUED + 2)
        assertSame(first, other)
    }

    @Test
    fun `applyProjection ignores a projection whose frontier has gone backwards`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val stale = applyProjection(first, projection(frontier = ProjectionFrontier(4, 9, ISSUED - 5, DEVICE)), ISSUED + 2)
        assertSame(first, stale)
    }

    @Test
    fun `applyProjection accepts an equal frontier with a newer issuedAt (a cover republish)`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val again = applyProjection(
            first,
            projection(issuedAt = ISSUED + 10, expiresAt = EXPIRES + 10, frontier = ProjectionFrontier(5, 10, ISSUED + 10, DEVICE)),
            ISSUED + 11,
        )
        assertEquals(EXPIRES + 10, again.projection?.expiresAt)
    }

    // R-30: safety first. A block published from a second device whose log has
    // not merged the first device's recent operations carries a Lamport
    // frontier no higher than the one already held; recency decides, the
    // Lamport clock only breaks a same-second tie.
    @Test
    fun `applyProjection accepts a later-published projection whose Lamport clock is behind (R-30)`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val laggingDeviceBlock = applyProjection(
            first,
            projection(frontier = ProjectionFrontier(2, 4, ISSUED + 30, "3".repeat(32)), contacts = listOf(contact("e".repeat(32), true, "f".repeat(64)))),
            ISSUED + 31,
        )
        assertNotSame(first, laggingDeviceBlock)
        assertEquals(setOf("f".repeat(64)), blockedSetOf(laggingDeviceBlock))
    }

    @Test
    fun `applyProjection ignores an earlier-published projection even when its Lamport clock is ahead (R-30)`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val staleReplay = applyProjection(
            first,
            projection(frontier = ProjectionFrontier(99, 200, ISSUED - 1, "3".repeat(32)), contacts = emptyList()),
            ISSUED + 2,
        )
        assertSame(first, staleReplay)
    }

    @Test
    fun `applyProjection breaks an equal-publishedAt tie by maxClock, in both directions (R-30)`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val sameMomentLowerClock = applyProjection(
            first,
            projection(frontier = ProjectionFrontier(4, 9, ISSUED, "3".repeat(32)), contacts = emptyList()),
            ISSUED + 2,
        )
        assertSame(first, sameMomentLowerClock)
        val sameMomentHigherClock = applyProjection(
            first,
            projection(frontier = ProjectionFrontier(6, 11, ISSUED, "3".repeat(32)), contacts = emptyList()),
            ISSUED + 3,
        )
        assertEquals(emptyList(), sameMomentHigherClock.projection?.contacts)
    }

    @Test
    fun `applyProjection replaces the blocked set when a newer projection un-blocks someone`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        assertEquals(setOf("d".repeat(64)), blockedSetOf(first))
        val unblocked = applyProjection(
            first,
            projection(
                frontier = ProjectionFrontier(6, 11, ISSUED + 2, DEVICE),
                contacts = listOf(contact("a".repeat(32), false, "b".repeat(64)), contact("c".repeat(32), false, "d".repeat(64))),
            ),
            ISSUED + 2,
        )
        assertEquals(0, blockedSetOf(unblocked).size)
    }

    @Test
    fun `applyProjection applies old revocations without lowering the persisted replay floor`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val older = projection(revoked = true, contacts = emptyList(), frontier = ProjectionFrontier(1, 1, ISSUED - 20, DEVICE))
        val revoked = applyProjection(first, older, ISSUED + 2)
        assertTrue(revoked.revoked)
        assertEquals(emptyList(), visibleContacts(revoked))
        assertEquals(first.projection?.frontier, revoked.projection?.frontier)
        assertEquals(blockedSetOf(first), blockedSetOf(revoked))
        // Simulates a reload from persisted state: a fresh, structurally equal
        // instance rather than the same object reference.
        val restored = revoked.copy()
        val intermediate = projection(frontier = ProjectionFrontier(99, 100, ISSUED - 10, DEVICE))
        assertSame(restored, applyProjection(restored, intermediate, ISSUED + 3))
        val sameTimeOlder = projection(revoked = true, frontier = ProjectionFrontier(4, 9, ISSUED, DEVICE))
        val again = applyProjection(restored, sameTimeOlder, ISSUED + 4)
        assertEquals(5L, again.projection?.frontier?.maxClock)
        assertSame(again, applyProjection(again, projection(), ISSUED + 5))
        val newer = projection(frontier = ProjectionFrontier(1, 2, ISSUED + 1, DEVICE))
        assertFalse(applyProjection(again, newer, ISSUED + 6).revoked)
    }

    @Test
    fun `applyProjection keeps the blocked set through revocation and empties the contacts`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val revoked = applyProjection(
            first,
            projection(contacts = emptyList(), revoked = true, frontier = ProjectionFrontier(6, 11, ISSUED + 2, DEVICE)),
            ISSUED + 2,
        )
        assertTrue(revoked.revoked)
        assertEquals(emptyList(), revoked.projection?.contacts)
        assertEquals(setOf("d".repeat(64)), blockedSetOf(revoked))
    }

    @Test
    fun `applyProjection accepts a revocation even when its frontier went backwards`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val revoked = applyProjection(
            first,
            projection(contacts = emptyList(), revoked = true, frontier = ProjectionFrontier(1, 1, ISSUED + 2, DEVICE)),
            ISSUED + 2,
        )
        assertTrue(revoked.revoked)
    }

    @Test
    fun `applyProjection does not un-revoke via a frontier that is not newer than the one that revoked (F2)`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val revokedAtF2 = applyProjection(
            first,
            projection(contacts = emptyList(), revoked = true, frontier = ProjectionFrontier(6, 11, ISSUED + 2, DEVICE)),
            ISSUED + 2,
        )
        assertTrue(revokedAtF2.revoked)

        // F1 (the original, older frontier) must not resurrect the directory.
        val stillRevoked = applyProjection(revokedAtF2, projection(frontier = ProjectionFrontier(5, 10, ISSUED, DEVICE)), ISSUED + 3)
        assertSame(revokedAtF2, stillRevoked)
        assertTrue(stillRevoked.revoked)

        // F3, strictly newer than F2, may un-revoke.
        val unrevoked = applyProjection(revokedAtF2, projection(frontier = ProjectionFrontier(7, 12, ISSUED + 3, DEVICE)), ISSUED + 4)
        assertFalse(unrevoked.revoked)
        assertEquals(2, unrevoked.projection?.contacts?.size)
    }

    @Test
    fun `applyProjection ignores an exact frontier tie (same maxClock and publishedAt) rather than re-applying it`() {
        val first = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        val same = applyProjection(first, projection(frontier = ProjectionFrontier(5, 10, ISSUED, DEVICE)), ISSUED + 2)
        assertSame(first, same)
    }

    @Test
    fun `applyProjection includes linked pubkeys in the blocked set`() {
        val withLink = projection(contacts = listOf(contact("c".repeat(32), true, "d".repeat(64)).copy(linkedPubkeys = listOf("e".repeat(64)))))
        val state = applyProjection(emptyContactsState(), withLink, ISSUED + 1)
        assertEquals(setOf("d".repeat(64), "e".repeat(64)), blockedSetOf(state))
    }

    @Test
    fun `isFresh is true up to expiresAt, false after, false when revoked, false when empty`() {
        val state = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        assertTrue(isFresh(state, EXPIRES))
        assertFalse(isFresh(state, EXPIRES + 1))
        assertFalse(isFresh(emptyContactsState(), ISSUED))
        val revoked = applyProjection(state, projection(contacts = emptyList(), revoked = true), ISSUED + 2)
        assertFalse(isFresh(revoked, ISSUED + 3))
    }

    @Test
    fun `blockedSetOf never un-blocks because the projection went stale`() {
        val state = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        assertFalse(isFresh(state, EXPIRES + 10_000))
        assertEquals(setOf("d".repeat(64)), blockedSetOf(state))
    }

    @Test
    fun `visibleContacts excludes blocked contacts and returns nothing once revoked`() {
        val state = applyProjection(emptyContactsState(), projection(), ISSUED + 1)
        assertEquals(listOf("a".repeat(32)), visibleContacts(state).map { it.contactId })
        val revoked = applyProjection(state, projection(contacts = emptyList(), revoked = true), ISSUED + 2)
        assertEquals(emptyList(), visibleContacts(revoked))
    }
}
