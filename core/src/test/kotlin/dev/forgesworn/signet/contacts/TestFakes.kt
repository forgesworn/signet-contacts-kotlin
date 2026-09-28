package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonString
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.toJson
import dev.forgesworn.signet.contacts.wire.Capability
import dev.forgesworn.signet.contacts.wire.ContactProjectionV2
import dev.forgesworn.signet.contacts.wire.NostrFilter
import dev.forgesworn.signet.contacts.wire.PairingV2
import dev.forgesworn.signet.contacts.wire.ProjectedContact
import dev.forgesworn.signet.contacts.wire.ProjectedIdentity
import dev.forgesworn.signet.contacts.wire.ProjectionFrontier
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.UnsignedNostrEvent
import dev.forgesworn.signet.contacts.wire.buildProjection
import dev.forgesworn.signet.contacts.wire.projectionTag
import dev.forgesworn.signet.contacts.wire.proposalTag
import dev.forgesworn.signet.contacts.wire.sealVaultPayload

/**
 * Fixtures shared by the ported client/app-invite/adapter tests, mirroring
 * client.test.ts's module-level constants and helpers. Kept in one file so
 * every test suite in this package sees the same GRANT/APP/RAIL identities.
 */

internal val GRANT = "f".repeat(32)
internal val APP = "a".repeat(64)
internal val RAIL = "b".repeat(64)
internal val CHALLENGE = "D".repeat(32)
internal val RELAYS = listOf("wss://relay.example.com")

internal fun stateKey(grantId: String): String = "signet-contacts:state:$grantId"
internal fun pendingKey(grantId: String): String = "signet-contacts:pending:$grantId"

/**
 * A fake signer: "encryption" is a reversible tagged wrapper, so a test can
 * assert who a payload was addressed to without a real crypto dependency.
 * `decrypt` is strict: a payload addressed to a DIFFERENT pubkey throws,
 * exactly like `fakeSigner` in the TypeScript reference.
 *
 * Each leg is an overridable `var` (a spy would be in TS) so a test can swap
 * in a throwing implementation for one leg while keeping the others real, and
 * call counts are tracked for the "must not have been called" assertions.
 */
internal class FakeSigner(override val pubkey: String = APP) : ContactsSigner {
    var encryptCalls: Int = 0
        private set
    var decryptCalls: Int = 0
        private set
    var signEventCalls: Int = 0
        private set
    val decryptArgs: MutableList<Pair<String, String>> = mutableListOf()

    var encryptImpl: suspend (String, String) -> String = { peer, plaintext -> sealedEncrypt(peer, plaintext) }
    var decryptImpl: suspend (String, String) -> String = { _, ciphertext -> sealedDecrypt(pubkey, ciphertext) }
    var signImpl: suspend (UnsignedNostrEvent) -> SignedNostrEvent = { event -> asSigned(event, "0".repeat(64), "1".repeat(128)) }

    override suspend fun nip44Encrypt(peerPubkey: String, plaintext: String): String {
        encryptCalls++
        return encryptImpl(peerPubkey, plaintext)
    }

    override suspend fun nip44Decrypt(peerPubkey: String, ciphertext: String): String {
        decryptCalls++
        decryptArgs.add(peerPubkey to ciphertext)
        return decryptImpl(peerPubkey, ciphertext)
    }

    override suspend fun signEvent(event: UnsignedNostrEvent): SignedNostrEvent {
        signEventCalls++
        return signImpl(event)
    }
}

internal fun sealedEncrypt(peer: String, plaintext: String): String =
    jsonObject("to" to peer.toJson(), "plaintext" to plaintext.toJson()).stringify()

/** The reverse of [sealedEncrypt]; throws when the envelope was not addressed to [pubkey]. */
internal fun sealedDecrypt(pubkey: String, ciphertext: String): String {
    val o = Json.parse(ciphertext) as JsonObject
    val to = (o["to"] as? JsonString)?.value ?: throw RuntimeException("bad ciphertext")
    if (to != pubkey) throw RuntimeException("wrong recipient")
    return (o["plaintext"] as JsonString).value
}

/** Stamp an [UnsignedNostrEvent] into a [SignedNostrEvent] with the given id/sig. */
internal fun asSigned(template: UnsignedNostrEvent, id: String, sig: String): SignedNostrEvent =
    SignedNostrEvent(id, template.kind, template.pubkey, template.createdAt, template.tags, template.content, sig)

/** Mirrors client.test.ts's `signed()`: id `'2'.repeat(64)`, sig `'3'.repeat(64)`. */
internal fun signed(template: UnsignedNostrEvent): SignedNostrEvent = asSigned(template, "2".repeat(64), "3".repeat(128))

/** Seal a projection the way the app really publishes one (R-4): a v2 vault
 *  envelope, content key wrapped to [recipient] (APP by default - the only
 *  identity [FakeSigner] will open for unless told otherwise). */
internal suspend fun sealProjection(signer: ContactsSigner, proj: ContactProjectionV2, recipient: String = APP): String =
    sealVaultPayload(buildProjection(proj), signer, recipient) ?: error("test setup: sealVaultPayload returned null")

/**
 * A configurable [RelayIo] fake: each leg defaults to the TS reference's usual
 * "does nothing" stub (`fetchNewest` -> null, `publish` -> true, `fetchMany`/
 * `subscribe` unsupported), and a test overrides only the `*Impl` legs it
 * cares about. Call counts stand in for `vi.fn()`'s own call tracking.
 */
internal open class FakeRelay : RelayIo {
    var fetchNewestCalls: Int = 0
        private set
    var publishCalls: Int = 0
        private set
    var fetchManyCalls: Int = 0
        private set
    val publishedEvents: MutableList<SignedNostrEvent> = mutableListOf()
    val fetchNewestFilters: MutableList<NostrFilter> = mutableListOf()

    var fetchNewestImpl: suspend (NostrFilter, List<String>, String?) -> SignedNostrEvent? = { _, _, _ -> null }
    var publishImpl: suspend (SignedNostrEvent, List<String>) -> Boolean = { _, _ -> true }
    var fetchManyImpl: (suspend (NostrFilter, List<String>, String?) -> List<SignedNostrEvent>?)? = null
    var subscribeImpl: ((NostrFilter, List<String>, (SignedNostrEvent) -> Unit) -> RelaySubscription?)? = null

    override suspend fun fetchNewest(filter: NostrFilter, relays: List<String>, author: String?): SignedNostrEvent? {
        fetchNewestCalls++
        fetchNewestFilters.add(filter)
        return fetchNewestImpl(filter, relays, author)
    }

    override suspend fun publish(event: SignedNostrEvent, relays: List<String>): Boolean {
        publishCalls++
        publishedEvents.add(event)
        return publishImpl(event, relays)
    }

    override suspend fun fetchMany(filter: NostrFilter, relays: List<String>, author: String?): List<SignedNostrEvent>? {
        fetchManyCalls++
        return fetchManyImpl?.invoke(filter, relays, author)
    }

    override fun subscribe(filter: NostrFilter, relays: List<String>, onEvent: (SignedNostrEvent) -> Unit): RelaySubscription? =
        subscribeImpl?.invoke(filter, relays, onEvent)
}

internal val PAIRING: PairingV2 = PairingV2(
    grantId = GRANT, railPubkey = RAIL,
    projectionTag = projectionTag(GRANT), proposalTag = proposalTag(GRANT, APP),
    relay = RELAYS[0], grantedCapabilities = listOf(Capability.READ_DIRECTORY),
    maxStalenessSeconds = 21600, pairedAt = 1_700_000_000,
)

/** Mirrors client.test.ts's `projection(over)`: named-argument overrides of the
 *  same one-contact, read:directory-only fixture. */
internal fun testProjection(
    grantId: String = GRANT,
    scopes: List<Capability> = listOf(Capability.READ_DIRECTORY),
    frontier: ProjectionFrontier = ProjectionFrontier(maxClock = 5, opCount = 10, publishedAt = 1_700_000_000, deviceId = "2".repeat(32)),
    issuedAt: Long = 1_700_000_000,
    expiresAt: Long = 1_700_021_600,
    contacts: List<ProjectedContact> = listOf(
        ProjectedContact(contactId = "c".repeat(32), displayName = "Dee", identities = listOf(ProjectedIdentity("d".repeat(64)))),
    ),
    revoked: Boolean = false,
    truncated: Boolean = false,
): ContactProjectionV2 = ContactProjectionV2(grantId, scopes, frontier, issuedAt, expiresAt, contacts, revoked, truncated)
