package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonString
import dev.forgesworn.signet.contacts.json.jsonArray
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.toJson
import dev.forgesworn.signet.contacts.wire.ACK_CANDIDATE_LIMIT
import dev.forgesworn.signet.contacts.wire.ACK_KIND
import dev.forgesworn.signet.contacts.wire.ACK_STORED_KIND
import dev.forgesworn.signet.contacts.wire.AddKenValue
import dev.forgesworn.signet.contacts.wire.Capability
import dev.forgesworn.signet.contacts.wire.ContactProposalDraft
import dev.forgesworn.signet.contacts.wire.MAX_ENVELOPE_CHARS
import dev.forgesworn.signet.contacts.wire.MAX_PROPOSALS_PER_BATCH
import dev.forgesworn.signet.contacts.wire.MAX_STALENESS_SECONDS
import dev.forgesworn.signet.contacts.wire.NostrFilter
import dev.forgesworn.signet.contacts.wire.PAIRING_FRESHNESS_SECONDS
import dev.forgesworn.signet.contacts.wire.PairingAckV2
import dev.forgesworn.signet.contacts.wire.PairingV2
import dev.forgesworn.signet.contacts.wire.PendingProposal
import dev.forgesworn.signet.contacts.wire.RenameAppLabelValue
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.ackEventTemplate
import dev.forgesworn.signet.contacts.wire.ackTag
import dev.forgesworn.signet.contacts.wire.buildPairingAckV2
import dev.forgesworn.signet.contacts.wire.buildProjection
import dev.forgesworn.signet.contacts.wire.parseProposalBatch
import dev.forgesworn.signet.contacts.wire.projectionEventTemplate
import dev.forgesworn.signet.contacts.wire.projectionTag
import dev.forgesworn.signet.contacts.wire.proposalTag
import dev.forgesworn.signet.contacts.wire.storedAckEventTemplate
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.async
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Ported from client.test.ts. Every test builds its own [SignetContactsClient]
 * so fixtures stay independent, matching the TS reference's per-`it` setup.
 *
 * Timing: TypeScript's `vi.useFakeTimers()`/`vi.advanceTimersByTimeAsync`
 * become `runTest` plus `advanceTimeBy`/`runCurrent`, with `elapsedMs` wired
 * to `testScheduler.currentTime` so `awaitPairingAck`'s deadline and `start`'s
 * poll loop run on the SAME virtual clock the coroutine dispatcher advances.
 * `AbortSignal` has no Kotlin equivalent here: cancelling the coroutine that
 * is awaiting `awaitPairingAck` is the port of "abort", and it propagates
 * `CancellationException` rather than resolving to null (see the class doc on
 * `SignetContactsClient.awaitPairingAck`).
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class SignetContactsClientTest {

    private fun ackPlaintext(
        grantId: String = GRANT, railPubkey: String = RAIL, grantedCapabilities: List<Capability> = listOf(Capability.READ_DIRECTORY),
        maxStalenessSeconds: Long = 21600, challenge: String = CHALLENGE,
    ): String = buildPairingAckV2(
        PairingAckV2(grantId, railPubkey, projectionTag(grantId), proposalTag(grantId, APP), RELAYS[0], grantedCapabilities, maxStalenessSeconds, challenge),
    )

    private fun ackEvent(content: String, id: String = "4".repeat(64), sig: String = "5".repeat(128), ephemeralPubkey: String = "9".repeat(64), createdAt: Long = 1_700_000_000): SignedNostrEvent =
        asSigned(ackEventTemplate(ephemeralPubkey, APP, createdAt, content), id, sig)

    private fun storedAckEvent(content: String, challenge: String = CHALLENGE, id: String = "4".repeat(64), sig: String = "5".repeat(128), ephemeralPubkey: String = "9".repeat(64), createdAt: Long = 1_700_000_000): SignedNostrEvent =
        asSigned(storedAckEventTemplate(ephemeralPubkey, APP, createdAt, content, challenge), id, sig)

    private fun hasKind(filter: NostrFilter, kind: Int): Boolean = filter.kinds?.contains(kind) == true

    // Hoisted out of the crowding test below: an inline `sortedByDescending`
    // nested inside that test's lambdas generates a compiler class-file name
    // long enough to break on an ecryptfs home directory (its encoding of a
    // filename over 143 chars is rejected outright). Keeping the sort as its
    // own named function, rather than inlined at the call site, keeps the
    // generated class name short regardless of which test calls it.
    private fun newestFirst(events: List<SignedNostrEvent>): List<SignedNostrEvent> = events.sortedByDescending { it.createdAt }

    // ------------------------------------------------------------------
    // awaitPairingAck
    // ------------------------------------------------------------------

    @Test
    fun `returns the pairing when the ack matches the challenge`() = runTest {
        val signer = FakeSigner()
        val content = signer.nip44Encrypt(APP, ackPlaintext())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> ackEvent(content) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        val pairing = client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 50, pollMs = 5)
        assertEquals(GRANT, pairing?.grantId)
        assertEquals(1_700_000_000, pairing?.pairedAt)
    }

    @Test
    fun `returns null and stops polling on timeout`() = runTest {
        val relay = FakeRelay()
        val client = SignetContactsClient(FakeSigner(), relay, elapsedMs = { testScheduler.currentTime })
        assertNull(client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 30, pollMs = 10))
        assertTrue(relay.fetchNewestCalls > 0)
    }

    @Test
    fun `ignores an ack carrying someone else's challenge`() = runTest {
        val signer = FakeSigner()
        val content = signer.nip44Encrypt(APP, ackPlaintext(challenge = "E".repeat(32)))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> ackEvent(content) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        assertNull(client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 30, pollMs = 10))
    }

    @Test
    fun `rejects an ack that grants a capability the app never requested`() = runTest {
        val signer = FakeSigner()
        val content = signer.nip44Encrypt(APP, ackPlaintext(grantedCapabilities = listOf(Capability.READ_DIRECTORY, Capability.PROPOSE_ADD_KEN)))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> ackEvent(content) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        val pairing = client.awaitPairingAck(
            CHALLENGE, RELAYS, timeoutMs = 30, pollMs = 10, requestedCapabilities = listOf(Capability.READ_DIRECTORY),
        )
        assertNull(pairing)
    }

    @Test
    fun `accepts an ack that grants a strict subset of the requested capabilities`() = runTest {
        val signer = FakeSigner()
        val content = signer.nip44Encrypt(APP, ackPlaintext())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> ackEvent(content) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        val pairing = client.awaitPairingAck(
            CHALLENGE, RELAYS, timeoutMs = 30, pollMs = 10,
            requestedCapabilities = listOf(Capability.READ_DIRECTORY, Capability.PROPOSE_ADD_KEN),
        )
        assertEquals(GRANT, pairing?.grantId)
    }

    @Test
    fun `ignores an ack whose carrier event is older than the freshness window`() = runTest {
        val signer = FakeSigner()
        val content = signer.nip44Encrypt(APP, ackPlaintext())
        val staleCreatedAt = 1_700_000_000 - PAIRING_FRESHNESS_SECONDS - 1
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> ackEvent(content, createdAt = staleCreatedAt) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        assertNull(client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 30, pollMs = 10))
    }

    // I3: both the app pubkey and the rendezvous relay are printed in the QR a
    // consumer shows on screen, so anyone who photographs it can park junk
    // addressed to the app. A single-candidate fetch let one such event keep
    // the genuine ack out of the answer for the whole pairing window.
    @Test
    fun `accepts the genuine ack from behind newer junk events (I3)`() = runTest {
        val signer = FakeSigner()
        val genuine = ackEvent(signer.nip44Encrypt(APP, ackPlaintext()), id = "4".repeat(64))
        val junkUndecryptable = ackEvent("not even JSON", id = "6".repeat(64), ephemeralPubkey = "8".repeat(64), createdAt = 1_700_000_002)
        val junkWrongChallenge = ackEvent(
            signer.nip44Encrypt(APP, ackPlaintext(grantId = "0".repeat(32), challenge = "E".repeat(32))),
            id = "7".repeat(64), ephemeralPubkey = "7".repeat(64), createdAt = 1_700_000_001,
        )
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> junkUndecryptable }
        relay.fetchManyImpl = { _, _, _ -> listOf(junkUndecryptable, junkWrongChallenge, genuine) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        val pairing = client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 50, pollMs = 5)
        assertEquals(GRANT, pairing?.grantId)
        assertTrue(relay.fetchManyCalls > 0)
    }

    @Test
    fun `falls back to the single newest when the transport has no fetchMany (I3)`() = runTest {
        val signer = FakeSigner()
        val content = signer.nip44Encrypt(APP, ackPlaintext())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> ackEvent(content) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        assertEquals(GRANT, client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 50, pollMs = 5)?.grantId)
    }

    @Test
    fun `never decrypts an ack candidate whose content is over the envelope cap`() = runTest {
        val signer = FakeSigner()
        val oversized = ackEvent("x".repeat(MAX_ENVELOPE_CHARS + 1))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> oversized }
        relay.fetchManyImpl = { _, _, _ -> listOf(oversized) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        assertNull(client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 30, pollMs = 10))
        assertEquals(0, signer.decryptCalls)
    }

    @Test
    fun `rejects an ack whose railPubkey is the app's own pubkey`() = runTest {
        val signer = FakeSigner()
        val content = signer.nip44Encrypt(APP, ackPlaintext(railPubkey = APP))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> ackEvent(content) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        assertNull(client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 30, pollMs = 10))
    }

    // B4: the STORED (kind 30078) copy of the ack exists so a consumer that was
    // backgrounded through the ephemeral ack's whole life can still find it by
    // polling. No live event here - only fetchNewest polling turns it up.
    @Test
    fun `resolves from a STORED ack found only by polling - the backgrounded-app case`() = runTest {
        val signer = FakeSigner()
        val content = signer.nip44Encrypt(APP, ackPlaintext())
        val stored = storedAckEvent(content)
        val relay = FakeRelay()
        relay.fetchNewestImpl = { filter, _, _ -> if (hasKind(filter, ACK_STORED_KIND)) stored else null }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        assertEquals(GRANT, client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 50, pollMs = 5)?.grantId)
    }

    // Crowding mitigation: a photographed QR lets an attacker flood the STORED
    // ack tag with junk. If ACK_CANDIDATE_LIMIT or more newer junk events sit
    // in front of the genuine (older) ack, a poll that only asks for the
    // newest page would never see it; the fix pages backward with `until`.
    @Test
    fun `pages back past a wall of newer junk to reach the genuine stored ack (crowding)`() = runTest {
        val signer = FakeSigner()
        val base = 1_700_000_000L
        val genuineContent = signer.nip44Encrypt(APP, ackPlaintext())
        val junk = (0 until ACK_CANDIDATE_LIMIT).map { i ->
            asSigned(storedAckEventTemplate("7".repeat(64), APP, base - i, "not even JSON, always fails to decrypt", CHALLENGE), i.toString().padStart(64, '0'), "5".repeat(128))
        }
        val genuine = asSigned(storedAckEventTemplate("9".repeat(64), APP, base - 15, genuineContent, CHALLENGE), "8".repeat(64), "5".repeat(128))
        val allStored = junk + genuine
        val relay = FakeRelay()
        relay.fetchManyImpl = { filter, _, _ ->
            if (!hasKind(filter, ACK_STORED_KIND)) emptyList() else {
                val until = filter.until ?: Long.MAX_VALUE
                newestFirst(allStored.filter { it.createdAt <= until }).take(ACK_CANDIDATE_LIMIT)
            }
        }
        val client = SignetContactsClient(signer, relay, now = { base }, elapsedMs = { testScheduler.currentTime })
        val pairing = client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 200, pollMs = 5)
        assertEquals(GRANT, pairing?.grantId)
    }

    @Test
    fun `still resolves from an ephemeral LIVE ack, unaffected by the stored filter`() = runTest {
        val signer = FakeSigner()
        var receiveEphemeral: ((SignedNostrEvent) -> Unit)? = null
        val content = signer.nip44Encrypt(APP, ackPlaintext())
        val relay = FakeRelay()
        relay.subscribeImpl = { filter, _, onEvent ->
            if (hasKind(filter, ACK_KIND)) receiveEphemeral = onEvent
            RelaySubscription {}
        }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        val waiting = async { client.awaitPairingAck(CHALLENGE, RELAYS, pollMs = 10_000) }
        runCurrent()
        assertNotNull(receiveEphemeral)
        receiveEphemeral!!(ackEvent(content))
        assertEquals(GRANT, waiting.await()?.grantId)
    }

    @Test
    fun `queries the stored ack with kind 30078 and the ack's own d tag, never merged with the ephemeral filter`() = runTest {
        val filters = mutableListOf<NostrFilter>()
        val relay = FakeRelay()
        relay.fetchNewestImpl = { filter, _, _ -> filters.add(filter); null }
        val client = SignetContactsClient(FakeSigner(), relay, elapsedMs = { testScheduler.currentTime })
        client.awaitPairingAck(CHALLENGE, RELAYS, timeoutMs = 5, pollMs = 5)
        val storedFilter = filters.firstOrNull { hasKind(it, ACK_STORED_KIND) }
        assertNotNull(storedFilter)
        assertEquals(listOf(ACK_STORED_KIND), storedFilter!!.kinds)
        assertEquals(listOf(ackTag(CHALLENGE)), storedFilter.tags["#d"])
        assertNull(storedFilter.tags["#p"])
        assertEquals(ACK_CANDIDATE_LIMIT, storedFilter.limit)

        val ephemeralFilter = filters.firstOrNull { hasKind(it, ACK_KIND) }
        assertNotNull(ephemeralFilter)
        assertEquals(listOf(ACK_KIND), ephemeralFilter!!.kinds)
    }

    // Security review fix: the producer accepts the pairing link until
    // t+PAIRING_FRESHNESS_SECONDS and the stored ack lives until its own
    // created_at+PAIRING_FRESHNESS_SECONDS - a second window after the first -
    // so the default timeout covers both in sequence.
    @Test
    fun `defaults timeoutMs to 2 times PAIRING_FRESHNESS_SECONDS times 1000 (600s)`() = runTest {
        val defaultTimeoutMs = 2 * PAIRING_FRESHNESS_SECONDS * 1000
        val relay = FakeRelay()
        val client = SignetContactsClient(FakeSigner(), relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        val waiting = async { client.awaitPairingAck(CHALLENGE, RELAYS, pollMs = 10_000) }
        advanceTimeBy(defaultTimeoutMs - 1_000)
        runCurrent()
        assertTrue(relay.fetchNewestCalls > 0)
        advanceTimeBy(20_000)
        runCurrent()
        assertNull(waiting.await())
        val callsAfterReturn = relay.fetchNewestCalls
        advanceTimeBy(10_000)
        runCurrent()
        assertEquals(callsAfterReturn, relay.fetchNewestCalls)
    }

    // TS's "resumes from a frozen/late timer" test relies on `vi.setSystemTime`
    // jumping the wall clock WITHOUT firing the pending fake timer, then firing
    // it late, to prove a poll always runs before the deadline check even when
    // the deadline has already elapsed by the time the (overdue) timer fires.
    // Under kotlinx-coroutines-test, `elapsedMs` and the delay-driving virtual
    // clock are the SAME `testScheduler.currentTime`: advancing it always runs
    // every task scheduled up to the new time, so there is no way to move the
    // clock "past deadline" without the intervening poll having already run -
    // the two clocks TS decouples cannot be decoupled here. Skipped: no Kotlin
    // equivalent. The underlying property (poll runs before the deadline
    // check) is still exercised by every ordinary timeout test above, since
    // the Kotlin loop's poll-then-check-deadline structure is unconditional.

    // ------------------------------------------------------------------
    // ephemeral pairing acknowledgements
    // ------------------------------------------------------------------

    @Test
    fun `keeps a live listener between polling queries and removes it after approval`() = runTest {
        val signer = FakeSigner()
        var stoppedCalls = 0
        var receive: ((SignedNostrEvent) -> Unit)? = null
        val content = signer.nip44Encrypt(APP, ackPlaintext())
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, onEvent -> receive = onEvent; RelaySubscription { stoppedCalls++ } }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        val waiting = async { client.awaitPairingAck(CHALLENGE, RELAYS, pollMs = 10_000) }
        runCurrent()
        receive!!(ackEvent(content))
        assertEquals(GRANT, waiting.await()?.grantId)
        // Two live subscriptions (ephemeral kind 21237 + stored kind 30078),
        // both handed the same fake `close`, so teardown calls it twice.
        assertEquals(2, stoppedCalls)
    }

    // TS aborts via AbortSignal and asserts the promise resolves null. Kotlin
    // has no AbortSignal: cancelling the coroutine AWAITING awaitPairingAck is
    // the port of "abort" here, and it propagates cancellation rather than
    // returning null (see the class doc). What still ports directly is that
    // teardown - both subscriptions closed - runs on that cancellation path.
    @Test
    fun `cancels a waiting live listener and still tears down both subscriptions`() = runTest {
        var stoppedCalls = 0
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, _ -> RelaySubscription { stoppedCalls++ } }
        val client = SignetContactsClient(FakeSigner(), relay, elapsedMs = { testScheduler.currentTime })
        val job = launch { client.awaitPairingAck(CHALLENGE, RELAYS) }
        runCurrent()
        job.cancelAndJoin()
        assertEquals(2, stoppedCalls)
    }

    @Test
    fun `limits identity decryption to 32 unique candidates for one pairing attempt`() = runTest {
        val signer = FakeSigner()
        signer.decryptImpl = { _, _ -> throw RuntimeException("not our ack") }
        var id = 0
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> id++; ackEvent("junk", id = id.toString().padStart(64, '0')) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_000 }, elapsedMs = { testScheduler.currentTime })
        assertNull(client.awaitPairingAck(CHALLENGE, RELAYS, pollMs = 0, timeoutMs = 5000))
        assertEquals(32, signer.decryptCalls)
    }

    // ------------------------------------------------------------------
    // fetchProjection
    // ------------------------------------------------------------------

    @Test
    fun `opens the sealed envelope, applies and exposes state`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_100 })
        val p = client.fetchProjection(PAIRING)
        assertEquals(1, p?.contacts?.size)
        assertTrue(client.isFresh())
        assertEquals(GRANT, client.getState().grantId)
        assertTrue(signer.decryptArgs.any { it.first == RAIL })
    }

    @Test
    fun `pins the rail author - an event from another key is ignored`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val imposter = signed(projectionEventTemplate(RAIL, GRANT, 1, content)).copy(pubkey = "7".repeat(64))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> imposter }
        val client = SignetContactsClient(signer, relay)
        assertNull(client.fetchProjection(PAIRING))
    }

    @Test
    fun `ignores a projection whose grantId is not this pairing's`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection(grantId = "0".repeat(32)))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val client = SignetContactsClient(signer, relay)
        assertNull(client.fetchProjection(PAIRING))
    }

    @Test
    fun `fires onRevoked once when a revocation lands`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection(contacts = emptyList(), revoked = true))
        var onRevokedCalls = 0
        val grantsSeen = mutableListOf<String>()
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val client = SignetContactsClient(signer, relay)
        client.onRevoked { g -> onRevokedCalls++; grantsSeen.add(g) }
        client.fetchProjection(PAIRING)
        client.fetchProjection(PAIRING)
        assertEquals(1, onRevokedCalls)
        assertEquals(listOf(GRANT), grantsSeen)
    }

    @Test
    fun `persists and reloads state through injected storage`() = runTest {
        val storage = MemoryStorage()
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val first = SignetContactsClient(signer, relay, storage = storage)
        first.fetchProjection(PAIRING)
        val second = SignetContactsClient(signer, relay, storage = storage)
        val loaded = second.load(GRANT)
        assertEquals(1, loaded.projection?.contacts?.size)
        assertEquals(0, second.getBlockedSet().size)
    }

    @Test
    fun `rejects a projection whose staleness window exceeds the grant's clamp`() = runTest {
        val signer = FakeSigner()
        val tooWide = testProjection(issuedAt = 1_700_000_000, expiresAt = 1_700_000_000 + PAIRING.maxStalenessSeconds + 1)
        val content = sealProjection(signer, tooWide)
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val client = SignetContactsClient(signer, relay)
        assertNull(client.fetchProjection(PAIRING))
        assertNull(client.getState().grantId)
    }

    // TS smuggled a non-string `pubkey: 12345` past the type system; Kotlin's
    // SignedNostrEvent.pubkey is a String, so that exact shape cannot be
    // constructed. Ported with a syntactically valid but wrong-shaped pubkey
    // instead, keeping the "malformed relay data never throws" guarantee.
    @Test
    fun `does not throw when the relay returns a malformed event`() = runTest {
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ ->
            SignedNostrEvent(id = "1".repeat(64), kind = 30078, pubkey = "not-a-pubkey", createdAt = 1, tags = emptyList(), content = "", sig = "1".repeat(128))
        }
        val client = SignetContactsClient(FakeSigner(), relay)
        assertNull(client.fetchProjection(PAIRING))
    }

    // Ruling R-4.
    @Test
    fun `resolves null for a bare NIP-44 payload - the app never publishes one for this wire`() = runTest {
        val signer = FakeSigner()
        val bare = signer.nip44Encrypt(APP, buildProjection(testProjection()))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, bare)) }
        val client = SignetContactsClient(signer, relay)
        assertNull(client.fetchProjection(PAIRING))
    }

    @Test
    fun `resolves null for a projection sealed to a DIFFERENT app pubkey`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection(), recipient = "e".repeat(64))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val client = SignetContactsClient(signer, relay)
        assertNull(client.fetchProjection(PAIRING))
    }

    @Test
    fun `resolves null for a tampered envelope`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val envelope = Json.parse(content) as JsonObject
        val ctBytes = java.util.Base64.getDecoder().decode((envelope["ct"] as JsonString).value)
        ctBytes[0] = (ctBytes[0].toInt() xor 0x01).toByte()
        val tampered = jsonObject(
            "v" to 2.toJson(), "k" to envelope["k"]!!, "iv" to envelope["iv"]!!,
            "ct" to java.util.Base64.getEncoder().encodeToString(ctBytes).toJson(), "b" to envelope["b"]!!,
        ).stringify()
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, tampered)) }
        val client = SignetContactsClient(signer, relay)
        assertNull(client.fetchProjection(PAIRING))
    }

    @Test
    fun `returns null for an older replay and leaves state untouched`() = runTest {
        val signer = FakeSigner()
        val newer = testProjection(frontier = dev.forgesworn.signet.contacts.wire.ProjectionFrontier(5, 10, 1_700_000_000, "2".repeat(32)))
        val older = testProjection(frontier = dev.forgesworn.signet.contacts.wire.ProjectionFrontier(1, 1, 1_699_999_000, "2".repeat(32)))
        var contentToServe = sealProjection(signer, newer)
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, contentToServe)) }
        val client = SignetContactsClient(signer, relay)
        val first = client.fetchProjection(PAIRING)
        assertEquals(5L, first?.frontier?.maxClock)
        contentToServe = sealProjection(signer, older)
        val replay = client.fetchProjection(PAIRING)
        assertNull(replay)
        assertEquals(5L, client.getState().projection?.frontier?.maxClock)
    }

    @Test
    fun `resolves null for a projection whose scopes exceed the grant's capabilities`() = runTest {
        val signer = FakeSigner()
        val overScoped = testProjection(scopes = listOf(Capability.READ_DIRECTORY, Capability.BLOCKS_READ))
        val content = sealProjection(signer, overScoped)
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val client = SignetContactsClient(signer, relay)
        assertNull(client.fetchProjection(PAIRING))
        assertNull(client.getState().grantId)
    }

    // ------------------------------------------------------------------
    // start / stop - live updates with a poll fallback (R-32)
    // ------------------------------------------------------------------

    @Test
    fun `applies a projection pushed down the subscription, without any fetch`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        var push: ((SignedNostrEvent) -> Unit)? = null
        var closeCalls = 0
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, onEvent -> push = onEvent; RelaySubscription { closeCalls++ } }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_100 }, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        val stop = client.start(PAIRING, pollMs = 60_000)
        assertNotNull(push)
        push!!(signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)))
        runCurrent()
        assertEquals(1, client.getState().projection?.contacts?.size)
        stop()
        assertTrue(closeCalls > 0)
    }

    @Test
    fun `fires onRevoked from the live path`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection(contacts = emptyList(), revoked = true))
        var push: ((SignedNostrEvent) -> Unit)? = null
        var onRevokedCalls = 0
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, onEvent -> push = onEvent; RelaySubscription {} }
        val client = SignetContactsClient(signer, relay, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.onRevoked { onRevokedCalls++ }
        client.start(PAIRING, pollMs = 60_000)
        push!!(signed(projectionEventTemplate(RAIL, GRANT, 1, content)))
        runCurrent()
        assertEquals(1, onRevokedCalls)
        client.stop()
        // Still exactly once when the same revocation then arrives by poll.
        assertEquals(1, onRevokedCalls)
    }

    // Regression: an onRevoked listener used to fire while `lock` was still
    // held by the ingest that triggered it. A listener that calls back into
    // another method taking the same lock - `load` here, reached through
    // `runBlocking` since the callback type is not itself `suspend` -
    // deadlocked: `load` could never acquire a lock its own caller was still
    // holding. The listener now fires only after that lock is released, so
    // this completes well inside the timeout instead of hanging forever.
    @Test
    fun `an onRevoked listener that calls back into load via runBlocking does not deadlock`() = runBlocking {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection(contacts = emptyList(), revoked = true))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_100 })
        var loadedGrantId: String? = null
        client.onRevoked {
            runBlocking { loadedGrantId = client.load(GRANT).grantId }
        }
        withTimeout(5_000) {
            client.fetchProjection(PAIRING)
        }
        assertEquals(GRANT, loadedGrantId)
    }

    @Test
    fun `polls when the transport cannot subscribe, and stops polling on stop`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_100 }, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.start(PAIRING, pollMs = 10)
        // Nothing is fetched synchronously: the first poll is one interval away.
        assertEquals(0, relay.fetchNewestCalls)
        advanceTimeBy(10)
        runCurrent()
        assertEquals(1, client.getState().projection?.contacts?.size)
        client.stop()
        val afterStop = relay.fetchNewestCalls
        advanceTimeBy(60)
        runCurrent()
        assertEquals(afterStop, relay.fetchNewestCalls)
    }

    @Test
    fun `gives each start its own handle, so a stale one cannot tear down a later subscription`() = runTest {
        val closeCalls = intArrayOf(0, 0)
        var index = 0
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, _ -> val i = index++; RelaySubscription { closeCalls[i]++ } }
        val client = SignetContactsClient(FakeSigner(), relay, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        val stopFirst = client.start(PAIRING, pollMs = 60_000)
        val stopSecond = client.start(PAIRING, pollMs = 60_000)
        assertEquals(1, closeCalls[0]) // replaced by the second start
        stopFirst() // must be inert, not a teardown of the live subscription
        assertEquals(0, closeCalls[1])
        stopSecond()
        assertEquals(1, closeCalls[1])
    }

    // `revokedAnnounced` tracks `state.revoked` rather than latching true for
    // the client's whole life, so a grant revoked, un-revoked by a strictly
    // newer projection, then revoked again fires onRevoked on every edge.
    @Test
    fun `fires onRevoked on every revocation edge, and never twice for one`() = runTest {
        val signer = FakeSigner()
        val revocation = sealProjection(signer, testProjection(
            contacts = emptyList(), revoked = true,
            frontier = dev.forgesworn.signet.contacts.wire.ProjectionFrontier(5, 10, 1_700_000_000, "2".repeat(32)),
        ))
        val unrevoke = sealProjection(signer, testProjection(
            frontier = dev.forgesworn.signet.contacts.wire.ProjectionFrontier(6, 11, 1_700_000_010, "2".repeat(32)),
        ))
        val secondRevocation = sealProjection(signer, testProjection(
            contacts = emptyList(), revoked = true,
            frontier = dev.forgesworn.signet.contacts.wire.ProjectionFrontier(7, 12, 1_700_000_020, "2".repeat(32)),
        ))
        var serve = revocation
        var onRevokedCalls = 0
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, serve)) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_100 })
        client.onRevoked { onRevokedCalls++ }

        client.fetchProjection(PAIRING)
        assertEquals(1, onRevokedCalls)
        // The same tombstone arriving again (a relay replay, or the poll racing
        // the live socket) is not a second revocation.
        client.fetchProjection(PAIRING)
        assertEquals(1, onRevokedCalls)

        serve = unrevoke
        client.fetchProjection(PAIRING)
        assertFalse(client.getState().revoked)
        assertEquals(1, onRevokedCalls)

        serve = secondRevocation
        client.fetchProjection(PAIRING)
        assertTrue(client.getState().revoked)
        assertEquals(2, onRevokedCalls)
    }

    @Test
    fun `skips a poll tick that the live socket has already covered`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        var push: ((SignedNostrEvent) -> Unit)? = null
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, onEvent -> push = onEvent; RelaySubscription {} }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_100 }, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.start(PAIRING, pollMs = 200)
        // Deliver half an interval in, so the tick at 200ms sees a socket that
        // has plainly just worked.
        advanceTimeBy(100)
        runCurrent()
        push!!(signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)))
        runCurrent()
        assertEquals(1, client.getState().projection?.contacts?.size)
        advanceTimeBy(180) // total 280: past the (skipped) 200ms tick
        runCurrent()
        assertEquals(0, relay.fetchNewestCalls)
        // Once the socket goes quiet for a whole interval, the safety net resumes.
        advanceTimeBy(120) // total 400: the real, un-skipped tick
        runCurrent()
        assertTrue(relay.fetchNewestCalls > 0)
        client.stop()
    }

    @Test
    fun `replaces the previous subscription when start is called again, and stop is idempotent`() = runTest {
        val closeCalls = intArrayOf(0, 0)
        var index = 0
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, _ -> val i = index++; RelaySubscription { closeCalls[i]++ } }
        val client = SignetContactsClient(FakeSigner(), relay, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.start(PAIRING, pollMs = 60_000)
        client.start(PAIRING, pollMs = 60_000)
        assertEquals(1, closeCalls[0])
        client.stop()
        client.stop()
        assertEquals(1, closeCalls[1])
    }

    // A closed client must never open another subscription: with a caller-owned
    // scope already gone (or about to be), a subscription opened after `close()`
    // would leak - nothing is left running to ever tear it down.
    @Test
    fun `start after close throws and never touches the relay`() = runTest {
        var subscribeCalls = 0
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, _ -> subscribeCalls++; RelaySubscription {} }
        val client = SignetContactsClient(FakeSigner(), relay, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.close()
        assertFailsWith<IllegalStateException> { client.start(PAIRING, pollMs = 60_000) }
        assertEquals(0, subscribeCalls)
    }

    // A suspended ingest (e.g. a slow decrypt) that is still in flight when
    // `stop()` runs must not go on to write `state` once it is eventually
    // unblocked: `stop()` cancels the run's job, which cancels every ingest
    // launched under it, live push or poll alike.
    @Test
    fun `stop cancels an in-flight ingest so it cannot write state after the fact`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val gate = CompletableDeferred<Unit>()
        val realDecrypt = signer.decryptImpl
        signer.decryptImpl = { peer, ciphertext -> gate.await(); realDecrypt(peer, ciphertext) }
        var push: ((SignedNostrEvent) -> Unit)? = null
        var onRevokedCalls = 0
        val storage = MemoryStorage()
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, onEvent -> push = onEvent; RelaySubscription {} }
        val client = SignetContactsClient(signer, relay, storage = storage, now = { 1_700_000_100 }, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.onRevoked { onRevokedCalls++ }
        client.start(PAIRING, pollMs = 60_000)
        push!!(signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)))
        runCurrent() // the ingest starts and suspends inside the mutex, waiting on `gate`
        client.stop() // cancels the still-suspended ingest
        runCurrent()
        gate.complete(Unit) // unblocks a coroutine that, by now, is already cancelled
        runCurrent()
        assertNull(client.getState().projection)
        assertEquals(0, onRevokedCalls)
        assertNull(storage.get(stateKey(GRANT)))
    }

    // A commit that has already passed its final cancellation check (immediately
    // before it writes `state`) must land in full even when `stop()` cancels the
    // run while it is still suspended persisting - never a torn commit (state
    // updated but storage or the revocation announcement missing, or any other
    // partial mix). Gates the SECOND storage write (persistPending) so the first
    // (persistState) has already gone through by the time `stop()` runs, proving
    // the in-progress commit is not itself interrupted partway.
    @Test
    fun `commit begun before stop is atomic - state, both storage keys and the listener land together`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection(contacts = emptyList(), revoked = true))
        val gate = CompletableDeferred<Unit>()
        val map = mutableMapOf<String, String>()
        var setCalls = 0
        val storage = object : StorageIo {
            override suspend fun get(key: String): String? = map[key]
            override suspend fun set(key: String, value: String) {
                setCalls++
                if (setCalls == 2) gate.await() // suspend persistPending's write, mid-commit
                map[key] = value
            }
        }
        var push: ((SignedNostrEvent) -> Unit)? = null
        var onRevokedCalls = 0
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, onEvent -> push = onEvent; RelaySubscription {} }
        val client = SignetContactsClient(signer, relay, storage = storage, now = { 1_700_000_100 }, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.onRevoked { onRevokedCalls++ }
        client.start(PAIRING, pollMs = 60_000)
        push!!(signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)))
        runCurrent() // the ingest passes its final ensureActive() check, commits `state`,
        // persists it, and suspends on `gate` while persisting `pending`
        client.stop() // cancels the run; the commit is already underway and must finish
        runCurrent()
        assertTrue(client.getState().revoked) // the in-memory commit already landed
        assertNotNull(map[stateKey(GRANT)]) // and so did its storage write
        gate.complete(Unit)
        runCurrent()
        // Once unblocked, the REST of the same commit lands too: never left partial.
        assertNotNull(map[pendingKey(GRANT)])
        assertEquals(1, onRevokedCalls)
    }

    @Test
    fun `survives a transport whose subscribe throws, falling back to the poll alone`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1_700_000_000, content)) }
        relay.subscribeImpl = { _, _, _ -> throw RuntimeException("socket refused") }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_100 }, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.start(PAIRING, pollMs = 10)
        advanceTimeBy(10)
        runCurrent()
        assertEquals(1, client.getState().projection?.contacts?.size)
        client.stop()
    }

    @Test
    fun `ignores a pushed event that is not this grant's rail, and never throws into the transport`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        var push: ((SignedNostrEvent) -> Unit)? = null
        val relay = FakeRelay()
        relay.subscribeImpl = { _, _, onEvent -> push = onEvent; RelaySubscription {} }
        val client = SignetContactsClient(signer, relay, elapsedMs = { testScheduler.currentTime }, scope = backgroundScope)
        client.start(PAIRING, pollMs = 60_000)
        push!!(signed(projectionEventTemplate(RAIL, GRANT, 1, content)).copy(pubkey = "7".repeat(64)))
        runCurrent()
        assertNull(client.getState().projection)
        client.stop()
    }

    // ------------------------------------------------------------------
    // load - stored-row validation (I2)
    // ------------------------------------------------------------------

    @Test
    fun `drops a malformed pending row rather than keeping it`() = runTest {
        val storage = MemoryStorage()
        storage.set(
            pendingKey(GRANT),
            """[
                {"operationId":"not-hex","action":"add-ken","value":{"pubkey":"${"d".repeat(64)}","displayName":"Ada"},"sentAt":1},
                {"operationId":"${"a".repeat(32)}","action":"add-ken","value":{"pubkey":"not-hex","displayName":"Ada"},"sentAt":1},
                {"operationId":"${"c".repeat(32)}","action":"delete-everything","value":{},"sentAt":1},
                {"operationId":"${"b".repeat(32)}","action":"add-ken","value":{"pubkey":"${"d".repeat(64)}","displayName":"Ada"},"sentAt":1}
            ]""",
        )
        val client = SignetContactsClient(FakeSigner(), FakeRelay(), storage = storage)
        client.load(GRANT)
        val pending = client.pendingProposals()
        assertEquals(1, pending.size)
        assertEquals("b".repeat(32), pending[0].operationId)
    }

    @Test
    fun `drops a corrupt stored projection without wedging a later fetchProjection, keeping blockedPubkeys`() = runTest {
        val storage = MemoryStorage()
        storage.set(
            stateKey(GRANT),
            """{"grantId":"$GRANT","projection":{"v":2,"grantId":"$GRANT"},"receivedAt":1,"blockedPubkeys":["${"d".repeat(64)}"],"revoked":false}""",
        )
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val client = SignetContactsClient(signer, relay, storage = storage)
        val loaded = client.load(GRANT)
        assertNull(loaded.projection)
        // Sticky Blocked set survives even though the projection it came from did not.
        assertTrue(client.getBlockedSet().contains("d".repeat(64)))
        val p = client.fetchProjection(PAIRING)
        assertEquals(1, p?.contacts?.size)
    }

    @Test
    fun `drops a stored projection whose grantId does not match the ARGUMENT grantId, pinning state to the argument`() = runTest {
        val otherGrant = "9".repeat(32)
        val storage = MemoryStorage()
        storage.set(
            stateKey(otherGrant),
            """{"grantId":"$GRANT","projection":${testProjection().toJson().stringify()},"receivedAt":1,"blockedPubkeys":[],"revoked":false}""",
        )
        val signer = FakeSigner()
        val otherPairing = PAIRING.copy(grantId = otherGrant)
        val content = sealProjection(signer, testProjection(grantId = otherGrant))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, otherGrant, 1, content)) }
        val client = SignetContactsClient(signer, relay, storage = storage)
        val loaded = client.load(otherGrant)
        assertEquals(otherGrant, loaded.grantId)
        assertNull(loaded.projection)
        val p = client.fetchProjection(otherPairing)
        assertEquals(1, p?.contacts?.size)
    }

    // ------------------------------------------------------------------
    // propose
    // ------------------------------------------------------------------

    // ADD_KEN_PAIRING grants propose:add-ken in addition to PAIRING's own
    // read:directory - needed so the "refuses a draft the grant does not
    // cover" test below can rely on PAIRING granting neither propose action.
    private val addKenPairing = PAIRING.copy(grantedCapabilities = listOf(Capability.READ_DIRECTORY, Capability.PROPOSE_ADD_KEN))

    private fun plaintextOf(event: SignedNostrEvent): String = ((Json.parse(event.content) as JsonObject)["plaintext"] as JsonString).value

    @Test
    fun `encrypts to the rail, signs as the app and publishes under the proposal tag`() = runTest {
        var captured: SignedNostrEvent? = null
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured = e; true }
        val client = SignetContactsClient(FakeSigner(), relay, now = { 1_700_000_500 })
        val ok = client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("c".repeat(64), "Ada")))
        assertTrue(ok)
        assertEquals(APP, captured!!.pubkey)
        assertEquals(listOf(listOf("d", proposalTag(GRANT, APP))), captured!!.tags)
        val inner = Json.parse(captured!!.content) as JsonObject
        assertEquals(RAIL, (inner["to"] as JsonString).value)
        val batch = parseProposalBatch(plaintextOf(captured!!))
        assertEquals(dev.forgesworn.signet.contacts.wire.ProposalAction.ADD_KEN, batch?.proposals?.get(0)?.action)
        assertEquals(GRANT, batch?.proposals?.get(0)?.grantId)
    }

    @Test
    fun `dedupes two add-ken drafts in one call for the same pubkey (case-insensitive), keeping the last`() = runTest {
        var captured: SignedNostrEvent? = null
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured = e; true }
        val client = SignetContactsClient(FakeSigner(), relay, now = { 1_700_000_500 })
        val pubkey = "c".repeat(64)
        val ok = client.propose(
            addKenPairing,
            listOf(ContactProposalDraft.AddKen(pubkey.uppercase(), "First"), ContactProposalDraft.AddKen(pubkey, "Second")),
        )
        assertTrue(ok)
        val batch = parseProposalBatch(plaintextOf(captured!!))!!
        assertEquals(1, batch.proposals.size)
        assertEquals("Second", (batch.proposals[0].value as AddKenValue).displayName)
        assertEquals(1, client.pendingProposals().size)
    }

    @Test
    fun `dedupes two rename-app-label drafts in one call for the same contactId, keeping the last`() = runTest {
        var captured: SignedNostrEvent? = null
        val renamePairing = PAIRING.copy(grantedCapabilities = listOf(Capability.READ_DIRECTORY, Capability.PROPOSE_RENAME_APP_LABEL))
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured = e; true }
        val client = SignetContactsClient(FakeSigner(), relay, now = { 1_700_000_500 })
        val contactId = "a".repeat(32)
        val ok = client.propose(
            renamePairing,
            listOf(
                ContactProposalDraft.RenameAppLabel(contactId, "Old label", 1_700_000_000_000),
                ContactProposalDraft.RenameAppLabel(contactId, "New label", 1_700_000_600_000),
            ),
        )
        assertTrue(ok)
        val batch = parseProposalBatch(plaintextOf(captured!!))!!
        assertEquals(1, batch.proposals.size)
        val value = batch.proposals[0].value as RenameAppLabelValue
        assertEquals("New label", value.label)
        assertEquals(1_700_000_600_000L, value.updatedAt)
    }

    @Test
    fun `refuses a draft the grant does not cover, without touching the relay`() = runTest {
        val relay = FakeRelay()
        val client = SignetContactsClient(FakeSigner(), relay)
        val ok = client.propose(PAIRING, listOf(ContactProposalDraft.RenameAppLabel("a".repeat(32), "Coach")))
        assertFalse(ok)
        assertEquals(0, relay.publishCalls)
    }

    @Test
    fun `refuses an empty draft list`() = runTest {
        val client = SignetContactsClient(FakeSigner(), FakeRelay())
        assertFalse(client.propose(PAIRING, emptyList()))
    }

    @Test
    fun `stamps a rename-app-label draft's updatedAt from the injected clock`() = runTest {
        var captured: SignedNostrEvent? = null
        val renamePairing = PAIRING.copy(grantedCapabilities = listOf(Capability.READ_DIRECTORY, Capability.PROPOSE_RENAME_APP_LABEL))
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured = e; true }
        val client = SignetContactsClient(FakeSigner(), relay, now = { 1_700_000_500 }, nowMs = { 1_700_000_500_123 })
        val ok = client.propose(renamePairing, listOf(ContactProposalDraft.RenameAppLabel("a".repeat(32), "Coach")))
        assertTrue(ok)
        val batch = parseProposalBatch(plaintextOf(captured!!))
        val value = batch?.proposals?.get(0)?.value as RenameAppLabelValue
        assertEquals(1_700_000_500_123L, value.updatedAt)
    }

    @Test
    fun `resolves false, never throws, when the signer's nip44Encrypt rejects`() = runTest {
        val signer = FakeSigner()
        signer.encryptImpl = { _, _ -> throw RuntimeException("bunker offline") }
        val relay = FakeRelay()
        val client = SignetContactsClient(signer, relay)
        assertFalse(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("c".repeat(64), "Ada"))))
        assertEquals(0, relay.publishCalls)
        assertEquals(emptyList(), client.pendingProposals())
    }

    @Test
    fun `resolves false, never throws, when signEvent rejects`() = runTest {
        val signer = FakeSigner()
        signer.signImpl = { throw RuntimeException("user declined") }
        val client = SignetContactsClient(signer, FakeRelay())
        assertFalse(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("c".repeat(64), "Ada"))))
        assertEquals(emptyList(), client.pendingProposals())
    }

    @Test
    fun `resolves false, never throws, when the relay's publish rejects`() = runTest {
        val relay = FakeRelay()
        relay.publishImpl = { _, _ -> throw RuntimeException("socket closed") }
        val client = SignetContactsClient(FakeSigner(), relay)
        assertFalse(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("c".repeat(64), "Ada"))))
        assertEquals(emptyList(), client.pendingProposals())
    }

    // ------------------------------------------------------------------
    // propose - resend (B2)
    // ------------------------------------------------------------------

    @Test
    fun `resends a still-pending proposal on the next call, byte-identical to the first send`() = runTest {
        var clock = 1_700_000_500L
        val captured = mutableListOf<SignedNostrEvent>()
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured.add(e); true }
        val client = SignetContactsClient(FakeSigner(), relay, now = { clock })
        client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("c".repeat(64), "Ada")))
        val firstProposal = parseProposalBatch(plaintextOf(captured[0]))!!.proposals[0]

        clock += 100 // a second, later call - the resent entry must keep the ORIGINAL createdAt
        client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("d".repeat(64), "Bo")))
        val secondBatch = parseProposalBatch(plaintextOf(captured[1]))!!
        assertEquals(2, secondBatch.proposals.size)
        // New drafts come first.
        assertEquals("d".repeat(64), (secondBatch.proposals[0].value as AddKenValue).pubkey)
        val resent = secondBatch.proposals[1]
        assertEquals(firstProposal.operationId, resent.operationId)
        assertEquals(firstProposal.action, resent.action)
        assertEquals(firstProposal.value, resent.value)
        assertEquals(firstProposal.createdAt, resent.createdAt)
        assertEquals(1_700_000_500L, resent.createdAt) // not the later clock
    }

    @Test
    fun `caps at MAX_PROPOSALS_PER_BATCH, new drafts first, resends newest-sentAt-first`() = runTest {
        val storage = MemoryStorage()
        val baseSentAt = 1_700_000_000L
        val rows = (0 until 60).map { i ->
            PendingProposal(
                GRANT, i.toString(16).padStart(32, '0'),
                AddKenValue(i.toString(16).padStart(64, '9'), "P$i"), baseSentAt + i,
            )
        }
        storage.set(pendingKey(GRANT), jsonArray(rows.map { it.toJson() }).stringify())

        val captured = mutableListOf<SignedNostrEvent>()
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured.add(e); true }
        val client = SignetContactsClient(FakeSigner(), relay, storage = storage, now = { baseSentAt + 1000 })
        client.load(GRANT)
        val newDrafts = (0 until 5).map { k -> ContactProposalDraft.AddKen("f$k".padStart(64, 'f'), "New$k") }
        assertTrue(client.propose(addKenPairing, newDrafts))

        val batch = parseProposalBatch(plaintextOf(captured[0]))!!
        assertEquals(MAX_PROPOSALS_PER_BATCH, batch.proposals.size)
        val resent = batch.proposals.drop(newDrafts.size)
        assertEquals(MAX_PROPOSALS_PER_BATCH - newDrafts.size, resent.size) // 45
        val resentSentAts = resent.map { it.createdAt }
        assertEquals(baseSentAt + 59, resentSentAts.first()) // newest first
        assertEquals(baseSentAt + 15, resentSentAts.last()) // the 45 newest of 60, so 15..59
        assertEquals(resentSentAts.sortedDescending(), resentSentAts)
        // The 15 oldest (rows 0..14) were pushed out of the batch, not dropped -
        // they stay pending for a later call or reconcilePending to deal with.
        assertEquals(65, client.pendingProposals().size) // 60 original + 5 new
    }

    @Test
    fun `does not resend an add-ken superseded by a new draft for the same pubkey, and drops it only on success`() = runTest {
        val storage = MemoryStorage()
        val pubkey = "c".repeat(64)
        val oldRow = PendingProposal(GRANT, "1".repeat(32), AddKenValue(pubkey, "Old name"), 1_700_000_000)
        storage.set(pendingKey(GRANT), jsonArray(listOf(oldRow.toJson())).stringify())

        // A failed publish must leave the superseded row exactly where it was.
        val failingRelay = FakeRelay()
        failingRelay.publishImpl = { _, _ -> false }
        val failing = SignetContactsClient(FakeSigner(), failingRelay, storage = storage, now = { 1_700_000_500 })
        failing.load(GRANT)
        assertFalse(failing.propose(addKenPairing, listOf(ContactProposalDraft.AddKen(pubkey, "New name"))))
        assertEquals(listOf(oldRow), failing.pendingProposals())

        // A successful publish drops it, and it must never have ridden along.
        val captured = mutableListOf<SignedNostrEvent>()
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured.add(e); true }
        val client = SignetContactsClient(FakeSigner(), relay, storage = storage, now = { 1_700_000_500 })
        client.load(GRANT)
        assertTrue(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen(pubkey, "New name"))))
        val batch = parseProposalBatch(plaintextOf(captured[0]))!!
        assertEquals(1, batch.proposals.size) // the superseded row never rode along
        assertFalse(client.pendingProposals().any { it.operationId == oldRow.operationId })
    }

    @Test
    fun `does not resend a rename-app-label superseded by a new draft for the same contactId`() = runTest {
        val storage = MemoryStorage()
        val contactId = "a".repeat(32)
        val oldRow = PendingProposal(GRANT, "6".repeat(32), RenameAppLabelValue(contactId, "Old label", 1_700_000_000_000), 1_700_000_000)
        storage.set(pendingKey(GRANT), jsonArray(listOf(oldRow.toJson())).stringify())
        val renamePairing = PAIRING.copy(grantedCapabilities = listOf(Capability.READ_DIRECTORY, Capability.PROPOSE_RENAME_APP_LABEL))
        val captured = mutableListOf<SignedNostrEvent>()
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured.add(e); true }
        val client = SignetContactsClient(FakeSigner(), relay, storage = storage, now = { 1_700_000_500 })
        client.load(GRANT)
        assertTrue(client.propose(renamePairing, listOf(ContactProposalDraft.RenameAppLabel(contactId, "New label", 1_700_000_600_000))))
        val batch = parseProposalBatch(plaintextOf(captured[0]))!!
        assertEquals(1, batch.proposals.size)
        assertFalse(client.pendingProposals().any { it.operationId == oldRow.operationId })
    }

    @Test
    fun `does not resend a pending entry older than the wire's staleness ceiling, even under a looser local window`() = runTest {
        val storage = MemoryStorage()
        val staleRow = PendingProposal(GRANT, "2".repeat(32), AddKenValue("c".repeat(64), "Stale"), 1_700_000_000)
        storage.set(pendingKey(GRANT), jsonArray(listOf(staleRow.toJson())).stringify())
        val nowSec = 1_700_000_000L + MAX_STALENESS_SECONDS + 1
        val captured = mutableListOf<SignedNostrEvent>()
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured.add(e); true }
        val client = SignetContactsClient(
            FakeSigner(), relay, storage = storage, now = { nowSec },
            maxPendingStalenessSeconds = MAX_STALENESS_SECONDS * 10, // looser than the wire's own ceiling
        )
        client.load(GRANT)
        assertTrue(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("d".repeat(64), "New"))))
        val batch = parseProposalBatch(plaintextOf(captured[0]))!!
        assertEquals(1, batch.proposals.size) // the stale row is excluded from the batch
        // Not dropped either - only resend is refused; reconcilePending owns aging it out.
        assertTrue(client.pendingProposals().any { it.operationId == staleRow.operationId })
    }

    @Test
    fun `does not resend a pending entry whose capability the grant no longer covers`() = runTest {
        val storage = MemoryStorage()
        val renameRow = PendingProposal(GRANT, "3".repeat(32), RenameAppLabelValue("a".repeat(32), "Coach", 1_700_000_000_000), 1_700_000_000)
        storage.set(pendingKey(GRANT), jsonArray(listOf(renameRow.toJson())).stringify())
        val captured = mutableListOf<SignedNostrEvent>()
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured.add(e); true }
        val client = SignetContactsClient(FakeSigner(), relay, storage = storage, now = { 1_700_000_500 })
        client.load(GRANT)
        // addKenPairing grants only add-ken; the rename row's capability is gone.
        assertTrue(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("d".repeat(64), "New"))))
        val batch = parseProposalBatch(plaintextOf(captured[0]))!!
        assertEquals(1, batch.proposals.size)
        assertTrue(client.pendingProposals().any { it.operationId == renameRow.operationId })
    }

    @Test
    fun `leaves pending fully unchanged, resend candidates included, when the publish fails`() = runTest {
        val storage = MemoryStorage()
        val existingRow = PendingProposal(GRANT, "4".repeat(32), AddKenValue("c".repeat(64), "Existing"), 1_700_000_000)
        storage.set(pendingKey(GRANT), jsonArray(listOf(existingRow.toJson())).stringify())
        val relay = FakeRelay()
        relay.publishImpl = { _, _ -> false }
        val client = SignetContactsClient(FakeSigner(), relay, storage = storage, now = { 1_700_000_500 })
        client.load(GRANT)
        assertFalse(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("d".repeat(64), "New"))))
        assertEquals(listOf(existingRow), client.pendingProposals())
    }

    @Test
    fun `never resends an item reconcilePending already cleared via an accepted projection`() = runTest {
        val signer = FakeSigner()
        val pubkey = "d".repeat(64)
        val proj = testProjection(contacts = listOf(
            dev.forgesworn.signet.contacts.wire.ProjectedContact(contactId = "c".repeat(32), displayName = "Ada", identities = listOf(dev.forgesworn.signet.contacts.wire.ProjectedIdentity(pubkey))),
        ))
        val content = sealProjection(signer, proj)
        val captured = mutableListOf<SignedNostrEvent>()
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        relay.publishImpl = { e, _ -> captured.add(e); true }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_500 })
        client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen(pubkey, "Ada")))
        assertEquals(1, client.pendingProposals().size)
        client.fetchProjection(PAIRING)
        assertEquals(emptyList(), client.pendingProposals()) // reconciled away by the projection

        assertTrue(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("e".repeat(64), "Bo"))))
        val batch = parseProposalBatch(plaintextOf(captured[1]))!!
        assertEquals(1, batch.proposals.size) // nothing resurrected
    }

    // ------------------------------------------------------------------
    // pending is scoped to its own grant (F2)
    // ------------------------------------------------------------------

    private val grantB = "e".repeat(32)
    private val pairingB = addKenPairing.copy(grantId = grantB, projectionTag = projectionTag(grantB), proposalTag = proposalTag(grantB, APP))

    @Test
    fun `re-pairing to a new grant never carries the old grant's pending proposals into the new one`() = runTest {
        val storage = MemoryStorage()
        val captured = mutableListOf<SignedNostrEvent>()
        val relay = FakeRelay()
        relay.publishImpl = { e, _ -> captured.add(e); true }
        val client = SignetContactsClient(FakeSigner(), relay, storage = storage, now = { 1_700_000_500 })

        // Pending on grant A (the current pairing) - never read by a producer,
        // so it is still sitting in `pending` when the app re-pairs.
        val pubkeyA = "c".repeat(64)
        assertTrue(client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen(pubkeyA, "Ada"))))
        assertEquals(1, client.pendingProposals().size)

        // Re-pair to grant B, in the same session - no restart, so nothing but
        // `load` stands between A's leftover row and B's next batch.
        client.load(grantB)
        assertTrue(client.propose(pairingB, listOf(ContactProposalDraft.AddKen("e".repeat(64), "Bo"))))

        // A's entry did not ride along in B's batch.
        val batchB = parseProposalBatch(plaintextOf(captured[1]))!!
        assertEquals(1, batchB.proposals.size)
        assertEquals("e".repeat(64), (batchB.proposals[0].value as AddKenValue).pubkey)

        // Nor was it persisted under B's storage key.
        val storedB = Json.parse(storage.get(pendingKey(grantB))!!) as dev.forgesworn.signet.contacts.json.JsonArray
        assertEquals(1, storedB.items.size)

        // It is still pending for A.
        val pending = client.pendingProposals()
        assertEquals(2, pending.size)
        val forA = pending.firstOrNull { (it.value as? AddKenValue)?.pubkey == pubkeyA }
        assertEquals(GRANT, forA?.grantId)
    }

    @Test
    fun `load drops a stored pending row carrying a DIFFERENT grantId than the one being loaded`() = runTest {
        val storage = MemoryStorage()
        // Stored under grantB's own key, but tagged for GRANT (stale key reuse
        // or a corrupted write) - must not be adopted as a grantB row.
        storage.set(
            pendingKey(grantB),
            """[{"grantId":"$GRANT","operationId":"${"a".repeat(32)}","action":"add-ken","value":{"pubkey":"${"c".repeat(64)}","displayName":"Ada"},"sentAt":1}]""",
        )
        val client = SignetContactsClient(FakeSigner(), FakeRelay(), storage = storage)
        client.load(grantB)
        assertEquals(emptyList(), client.pendingProposals())
    }

    @Test
    fun `load stamps a legacy row with no grantId with the grant it was just loaded under`() = runTest {
        val storage = MemoryStorage()
        storage.set(
            pendingKey(GRANT),
            """[{"operationId":"${"a".repeat(32)}","action":"add-ken","value":{"pubkey":"${"c".repeat(64)}","displayName":"Ada"},"sentAt":1}]""",
        )
        val client = SignetContactsClient(FakeSigner(), FakeRelay(), storage = storage)
        client.load(GRANT)
        val pending = client.pendingProposals()
        assertEquals(1, pending.size)
        assertEquals(GRANT, pending[0].grantId)
    }

    @Test
    fun `reconcilePending only reconciles the grant the projection actually belongs to`() = runTest {
        val signer = FakeSigner()
        val pubkey = "c".repeat(64)
        // Grant B's own projection happens to carry the SAME pubkey as A's
        // pending add-ken - it must not reconcile A's entry away.
        val contentB = sealProjection(signer, testProjection(
            grantId = grantB,
            contacts = listOf(dev.forgesworn.signet.contacts.wire.ProjectedContact(contactId = "c".repeat(32), displayName = "Ada", identities = listOf(dev.forgesworn.signet.contacts.wire.ProjectedIdentity(pubkey)))),
        ))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, grantB, 1, contentB)) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_500 })
        client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen(pubkey, "Ada")))
        assertEquals(1, client.pendingProposals().size)

        client.fetchProjection(pairingB)
        val pending = client.pendingProposals()
        assertEquals(1, pending.size) // A's entry survives B's projection
        assertEquals(GRANT, pending[0].grantId)
    }

    // ------------------------------------------------------------------
    // pendingProposals (R-9)
    // ------------------------------------------------------------------

    @Test
    fun `remembers what was sent, with the time it was sent`() = runTest {
        val client = SignetContactsClient(FakeSigner(), FakeRelay(), now = { 1_700_000_500 })
        client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("d".repeat(64), "Ada")))
        val pending = client.pendingProposals()
        assertEquals(1, pending.size)
        assertEquals(dev.forgesworn.signet.contacts.wire.ProposalAction.ADD_KEN, pending[0].action)
        assertEquals(1_700_000_500L, pending[0].sentAt)
        assertTrue(Regex("^[0-9a-f]{32}$").matches(pending[0].operationId))
    }

    @Test
    fun `remembers nothing for a proposal it refused to send`() = runTest {
        val relay = FakeRelay()
        relay.publishImpl = { _, _ -> false }
        val client = SignetContactsClient(FakeSigner(), relay)
        client.propose(PAIRING, listOf(ContactProposalDraft.AddKen("d".repeat(64), "Ada")))
        assertEquals(emptyList(), client.pendingProposals())
    }

    @Test
    fun `clears an add-ken once a projection carries that pubkey`() = runTest {
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection())
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val client = SignetContactsClient(signer, relay, now = { 1_700_000_500 })
        client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("d".repeat(64), "Ada")))
        assertEquals(1, client.pendingProposals().size)
        client.fetchProjection(PAIRING)
        assertEquals(emptyList(), client.pendingProposals())
    }

    @Test
    fun `gives up on a proposal older than the staleness window`() = runTest {
        var clock = 1_700_000_500L
        val signer = FakeSigner()
        val content = sealProjection(signer, testProjection(contacts = emptyList()))
        val relay = FakeRelay()
        relay.fetchNewestImpl = { _, _, _ -> signed(projectionEventTemplate(RAIL, GRANT, 1, content)) }
        val client = SignetContactsClient(signer, relay, now = { clock }, maxPendingStalenessSeconds = 100)
        client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("9".repeat(64), "Bo")))
        clock += 101
        client.fetchProjection(PAIRING)
        assertEquals(emptyList(), client.pendingProposals())
    }

    @Test
    fun `persists a proposal sent BEFORE any projection has ever been fetched`() = runTest {
        val storage = MemoryStorage()
        val signer = FakeSigner()
        val first = SignetContactsClient(signer, FakeRelay(), storage = storage, now = { 1_700_000_500 })
        // No fetchProjection call at all - `state.grantId` is still null here.
        assertTrue(first.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("d".repeat(64), "Ada"))))

        val second = SignetContactsClient(signer, FakeRelay(), storage = storage)
        val loaded = second.load(GRANT)
        assertNotNull(loaded)
        assertEquals(1, second.pendingProposals().size)
        assertEquals(dev.forgesworn.signet.contacts.wire.ProposalAction.ADD_KEN, second.pendingProposals()[0].action)
    }

    @Test
    fun `pendingProposals returns a deep copy - mutating a returned value cannot corrupt internal state`() = runTest {
        // Kotlin's PendingProposal/ProposalValue are immutable data classes, so
        // the equivalent of TS's "mutate the returned entry" is that the SAME
        // list is returned each call and a caller cannot obtain a mutable
        // reference to the internal value at all - the property this test
        // guards is structurally guaranteed rather than runtime-checked.
        val client = SignetContactsClient(FakeSigner(), FakeRelay(), now = { 1_700_000_500 })
        client.propose(addKenPairing, listOf(ContactProposalDraft.AddKen("d".repeat(64), "Ada")))
        val first = client.pendingProposals()
        val second = client.pendingProposals()
        assertEquals(first, second)
        assertEquals("Ada", (second[0].value as AddKenValue).displayName)
    }
}
