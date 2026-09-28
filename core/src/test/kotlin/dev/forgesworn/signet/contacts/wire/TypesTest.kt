package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals

class TypesTest {
    // "'opIds' in projection.frontier is false" does not port: ProjectionFrontier
    // is a fixed data class with no dynamic property map to probe for an absent
    // key, so there is no way to ask it for a field it was never given.
    @Test
    fun `constructs a full projection with every documented field`() {
        val contact = ProjectedContact(
            contactId = "a".repeat(32),
            type = ProjectedType.PERSON,
            identities = listOf(ProjectedIdentity("b".repeat(64), ProjectedVerification.PROVEN)),
            displayName = "Sam",
            avatar = ProjectedAvatar("https://blossom.example/abc", "c".repeat(64), "d".repeat(64)),
            effectiveTier = ProjectedTier.KITH,
            tierSource = ProjectedTierSource.DIRECT,
            roles = listOf("coach"),
            contactMethods = listOf(ProjectedMethod(ProjectedMethodKind.EMAIL, "sam@example.com", MethodVerification.UNVERIFIED)),
            blocked = false,
            linkedPubkeys = listOf("e".repeat(64)),
        )
        val projection = ContactProjectionV2(
            grantId = "f".repeat(32),
            scopes = listOf(Capability.READ_DIRECTORY),
            frontier = ProjectionFrontier(maxClock = 7, opCount = 12, publishedAt = 1_700_000_000, deviceId = "2".repeat(32)),
            issuedAt = 1_700_000_000,
            expiresAt = 1_700_021_600,
            contacts = listOf(contact),
            truncated = true,
        )
        assertEquals(ProjectedTier.KITH, projection.contacts[0].effectiveTier)
        assertEquals(21600L, projection.expiresAt - projection.issuedAt)
        assertEquals(32, projection.frontier.deviceId.length)
    }

    @Test
    fun `constructs a pairing request, ack, persisted pairing and proposal batch`() {
        val request = PairingRequestV2(
            appPubkey = "a".repeat(64), appName = "Flock",
            capabilities = listOf(Capability.READ_DIRECTORY, Capability.BLOCKS_READ),
            directory = DirectoryKind.OWNER, rendezvousRelay = "wss://relay.example.com",
            t = 1_700_000_000, challenge = "D".repeat(32),
        )
        val ack = PairingAckV2(
            grantId = "f".repeat(32), railPubkey = "b".repeat(64),
            projectionTag = "0".repeat(32), proposalTag = "1".repeat(32),
            relay = "wss://relay.example.com",
            grantedCapabilities = listOf(Capability.READ_DIRECTORY),
            maxStalenessSeconds = 21600, challenge = request.challenge,
        )
        val pairing = PairingV2(
            grantId = ack.grantId, railPubkey = ack.railPubkey, projectionTag = ack.projectionTag,
            proposalTag = ack.proposalTag, relay = ack.relay, grantedCapabilities = ack.grantedCapabilities,
            maxStalenessSeconds = ack.maxStalenessSeconds, pairedAt = 1_700_000_001,
        )
        val batch = ProposalBatch(
            listOf(
                ContactProposalV1(
                    grantId = ack.grantId, operationId = "9".repeat(32),
                    value = AddKenValue(pubkey = "c".repeat(64), displayName = "Ada"),
                    createdAt = 1_700_000_002,
                ),
            ),
        )
        assertEquals(ack.grantId, pairing.grantId)
        assertEquals(1, batch.proposals.size)
    }

    @Test
    fun `starts consumer state empty and keeps a sticky blocked list`() {
        val state = ContactsState(
            grantId = null, projection = null, receivedAt = 0,
            blockedPubkeys = listOf("a".repeat(64)), revoked = false,
        )
        assertEquals(1, state.blockedPubkeys.size)
    }

    @Test
    fun `types a pending proposal as consumer-side state only`() {
        val pending = PendingProposal(
            grantId = "f".repeat(32), operationId = "9".repeat(32),
            value = AddKenValue(pubkey = "c".repeat(64), displayName = "Ada"), sentAt = 1_700_000_000,
        )
        // R-9: `sentAt` is the only timing the SDK offers.
        assertEquals(1_700_000_000L, pending.sentAt)
        assertEquals(32, pending.operationId.length)
    }

    @Test
    fun `describes a signed event without importing nostr-tools`() {
        val event = SignedNostrEvent(
            id = "0".repeat(64), pubkey = "1".repeat(64), createdAt = 1, kind = 30078,
            tags = listOf(listOf("d", "2".repeat(32))), content = "ciphertext", sig = "3".repeat(128),
        )
        assertEquals("d", event.tags[0][0])
    }
}
