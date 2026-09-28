package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonNull
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.arr
import dev.forgesworn.signet.contacts.json.isTrue
import dev.forgesworn.signet.contacts.json.jsonArray
import dev.forgesworn.signet.contacts.json.num
import dev.forgesworn.signet.contacts.json.str
import dev.forgesworn.signet.contacts.wire.ACK_CANDIDATE_LIMIT
import dev.forgesworn.signet.contacts.wire.ACK_KIND
import dev.forgesworn.signet.contacts.wire.ACK_STORED_KIND
import dev.forgesworn.signet.contacts.wire.AddKenValue
import dev.forgesworn.signet.contacts.wire.Capability
import dev.forgesworn.signet.contacts.wire.ContactProjectionV2
import dev.forgesworn.signet.contacts.wire.ContactProposalDraft
import dev.forgesworn.signet.contacts.wire.ContactProposalV1
import dev.forgesworn.signet.contacts.wire.ContactsState
import dev.forgesworn.signet.contacts.wire.DirectoryKind
import dev.forgesworn.signet.contacts.wire.MAX_ENVELOPE_CHARS
import dev.forgesworn.signet.contacts.wire.MAX_PROPOSALS_PER_BATCH
import dev.forgesworn.signet.contacts.wire.MAX_STALENESS_SECONDS
import dev.forgesworn.signet.contacts.wire.NostrFilter
import dev.forgesworn.signet.contacts.wire.PAIRING_FRESHNESS_SECONDS
import dev.forgesworn.signet.contacts.wire.PairingRequestV2Result
import dev.forgesworn.signet.contacts.wire.PairingUriOptionsV2
import dev.forgesworn.signet.contacts.wire.PairingV2
import dev.forgesworn.signet.contacts.wire.PendingProposal
import dev.forgesworn.signet.contacts.wire.ProposalAction
import dev.forgesworn.signet.contacts.wire.RenameAppLabelValue
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.ackTag
import dev.forgesworn.signet.contacts.wire.applyProjection
import dev.forgesworn.signet.contacts.wire.blockedSetOf
import dev.forgesworn.signet.contacts.wire.buildPairingUriV2
import dev.forgesworn.signet.contacts.wire.buildProposalBatch
import dev.forgesworn.signet.contacts.wire.draftToProposal
import dev.forgesworn.signet.contacts.wire.emptyContactsState
import dev.forgesworn.signet.contacts.wire.isHex
import dev.forgesworn.signet.contacts.wire.openVaultPayload
import dev.forgesworn.signet.contacts.wire.pairingFromAck
import dev.forgesworn.signet.contacts.wire.parsePairingAckV2
import dev.forgesworn.signet.contacts.wire.parsePairingRequestV2
import dev.forgesworn.signet.contacts.wire.parseProjection
import dev.forgesworn.signet.contacts.wire.projectionFilter
import dev.forgesworn.signet.contacts.wire.proposalEventTemplate
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.CopyOnWriteArraySet
import kotlin.coroutines.cancellation.CancellationException

/** R-32: how often [SignetContactsClient.start] re-fetches when nothing has been pushed. */
public const val DEFAULT_LIVE_POLL_MS: Long = 60_000

/** R-9 default: a week. A proposal never applied is dropped rather than shown for ever. */
public const val DEFAULT_PENDING_STALENESS_SECONDS: Long = 604_800

private const val STATE_KEY_PREFIX = "signet-contacts:state:"
private const val PENDING_KEY_PREFIX = "signet-contacts:pending:"

/** How many `until`-paged fetches one poll makes for the STORED ack filter. */
private const val MAX_ACK_PAGES = 3

/** How many distinct ack candidates one [SignetContactsClient.awaitPairingAck] attempt opens. */
private const val MAX_ACK_ATTEMPTS = 32

/** Runs [block], turning any failure except cancellation into [fallback]. */
private suspend inline fun <T> orElse(fallback: T, block: () -> T): T = try {
    block()
} catch (e: CancellationException) {
    throw e
} catch (_: Throwable) {
    fallback
}

/**
 * Consumer client. Signing, encryption, relay I/O and storage are all
 * injected; the SDK opens no socket and holds no key. The client owns one
 * thing: the reduced [ContactsState], including the sticky Blocked set,
 * persisted through [storage] so a restart never silently un-blocks anybody.
 *
 * Hostile or malformed relay data never throws out of a public method: every
 * failure reads as "nothing" (null / false). Cancellation, by contrast,
 * propagates as it should in Kotlin.
 *
 * @param now seconds clock (freshness, `sentAt`).
 * @param nowMs ms clock a `rename-app-label` with no `updatedAt` is stamped from.
 * @param elapsedMs the clock deadlines and live-delivery gaps are measured on.
 *   Separate from [nowMs] so a test can pin the LWW stamp without freezing
 *   every deadline, and can drive it from a virtual-time scheduler.
 * @param scope where [start]'s poll loop and pushed ingests run.
 */
public class SignetContactsClient(
    private val signer: ContactsSigner,
    private val relay: RelayIo,
    private val storage: StorageIo = MemoryStorage(),
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
    private val nowMs: () -> Long = System::currentTimeMillis,
    private val maxPendingStalenessSeconds: Long = DEFAULT_PENDING_STALENESS_SECONDS,
    private val elapsedMs: () -> Long = System::currentTimeMillis,
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.Default),
) {
    @Volatile private var state: ContactsState = emptyContactsState()
    @Volatile private var pending: List<PendingProposal> = emptyList()
    @Volatile private var revokedAnnounced = false
    private val revokedListeners = CopyOnWriteArraySet<(String) -> Unit>()

    /** Every ingest, pushed or polled, runs under this lock, so two events can never
     *  interleave their read-modify-write of [state]. Also guards [pending] writes. */
    private val lock = Mutex()

    private val liveLock = Any()
    private var unsubscribe: RelaySubscription? = null
    private var pollJob: Job? = null
    private var liveGeneration = 0L
    @Volatile private var lastLiveDeliveryMs = 0L

    // ------------------------------------------------------------------
    // Pairing
    // ------------------------------------------------------------------

    public fun buildPairingUri(
        appName: String,
        capabilities: List<Capability>,
        directory: DirectoryKind,
        relay: String,
        nowSec: Long,
        challenge: String,
    ): String = buildPairingUriV2(PairingUriOptionsV2(signer.pubkey, appName, capabilities, directory, relay, nowSec, challenge))

    public fun parsePairingUri(
        input: String,
        nowSec: Long? = null,
        freshnessSeconds: Long = PAIRING_FRESHNESS_SECONDS,
    ): PairingRequestV2Result = parsePairingRequestV2(input, nowSec, freshnessSeconds)

    /**
     * Wait for the owner's ack. Listens live on both the ephemeral and the
     * stored filter when the transport can subscribe, and polls both every
     * [pollMs]. Accepts the first candidate that decrypts to this app AND
     * echoes [challenge]; opens at most 32 distinct candidates per attempt.
     * [requestedCapabilities], when given, refuses an ack that grants more.
     * Returns null on timeout; cancel the calling coroutine to abandon early.
     *
     * Every poll runs BEFORE the deadline check that can end the wait, so a
     * resumed (backgrounded) app gets one more look at the relays even if its
     * clock ran past [timeoutMs] while suspended.
     */
    public suspend fun awaitPairingAck(
        challenge: String,
        relays: List<String>,
        timeoutMs: Long = 2 * PAIRING_FRESHNESS_SECONDS * 1000,
        pollMs: Long = 2000,
        requestedCapabilities: Collection<Capability>? = null,
    ): PairingV2? {
        val deadline = elapsedMs() + timeoutMs
        val ephemeralFilter = NostrFilter(kinds = listOf(ACK_KIND), tags = mapOf("#p" to listOf(signer.pubkey)), limit = ACK_CANDIDATE_LIMIT)
        // Not merged with the ephemeral filter: a combined #p filter would
        // also pull in projections, which are kind 30078 too.
        val storedFilter = NostrFilter(kinds = listOf(ACK_STORED_KIND), tags = mapOf("#d" to listOf(ackTag(challenge))), limit = ACK_CANDIDATE_LIMIT)
        val allowed = requestedCapabilities?.toSet()

        val guard = Any()
        val live = ArrayDeque<SignedNostrEvent>()
        val attempted = HashSet<String>()
        val wake = Channel<Unit>(Channel.CONFLATED)
        val onLiveEvent: (SignedNostrEvent) -> Unit = { event ->
            synchronized(guard) {
                if (event.id !in attempted) {
                    if (live.none { it.id == event.id }) live.addLast(event)
                    if (live.size > ACK_CANDIDATE_LIMIT) live.removeFirst()
                }
            }
            wake.trySend(Unit)
        }
        val subscriptions = listOfNotNull(
            runCatching { relay.subscribe(ephemeralFilter, relays, onLiveEvent) }.getOrNull(),
            runCatching { relay.subscribe(storedFilter, relays, onLiveEvent) }.getOrNull(),
        )
        try {
            while (true) {
                orElse(Unit) {
                    val polledEphemeral = orElse(emptyList()) { fetchAckCandidates(ephemeralFilter, relays) }
                    val snapshot = synchronized(guard) { attempted.toSet() }
                    val polledStored = orElse(emptyList()) { fetchAckCandidatesPaged(storedFilter, relays, snapshot) }
                    val drained = synchronized(guard) { live.toList().also { live.clear() } }
                    for (event in drained + polledEphemeral + polledStored) {
                        if (synchronized(guard) { attempted.size } >= MAX_ACK_ATTEMPTS) return null
                        // Bounded before it can buy a signer round trip.
                        if (event.content.length > MAX_ENVELOPE_CHARS) continue
                        // The ack carries no timestamp of its own: freshness is the carrier's.
                        if (Math.abs(now() - event.createdAt) > PAIRING_FRESHNESS_SECONDS) continue
                        if (!synchronized(guard) { attempted.add(event.id) }) continue
                        val pairing = orElse(null) {
                            val plaintext = signer.nip44Decrypt(event.pubkey, event.content)
                            val ack = parsePairingAckV2(plaintext, challenge) ?: return@orElse null
                            // Narrowing only: an ack granting what was never asked for is not this request's.
                            val overGranted = allowed != null && ack.grantedCapabilities.any { it !in allowed }
                            // The app cannot be its own rail; that would make the author pin trivial.
                            val selfRail = ack.railPubkey.equals(signer.pubkey, ignoreCase = true)
                            if (!overGranted && !selfRail) pairingFromAck(ack, now()) else null
                        }
                        if (pairing != null) return pairing
                    }
                }
                val remaining = deadline - elapsedMs()
                if (remaining <= 0 || synchronized(guard) { attempted.size } >= MAX_ACK_ATTEMPTS) break
                if (synchronized(guard) { live.isNotEmpty() }) continue
                withTimeoutOrNull(minOf(pollMs, remaining)) { wake.receive() }
            }
            return null
        } finally {
            for (s in subscriptions) runCatching { s.close() }
            wake.close()
        }
    }

    /** I3: up to [ACK_CANDIDATE_LIMIT] candidates, newest first. No author pin:
     *  the ack's key is a throwaway, so NIP-44 plus the challenge is the gate. */
    private suspend fun fetchAckCandidates(filter: NostrFilter, relays: List<String>): List<SignedNostrEvent> {
        val many = relay.fetchMany(filter, relays)
        if (many != null) return many.take(ACK_CANDIDATE_LIMIT)
        return listOfNotNull(relay.fetchNewest(filter, relays))
    }

    /**
     * Crowding mitigation for the STORED ack filter: a full page whose every id
     * was already attempted pages backward with `until = oldest - 1` (a relay's
     * `until` is inclusive), at most [MAX_ACK_PAGES] fetches per call.
     */
    private suspend fun fetchAckCandidatesPaged(filter: NostrFilter, relays: List<String>, attempted: Set<String>): List<SignedNostrEvent> {
        var current = filter
        var page = fetchAckCandidates(current, relays)
        var pages = 1
        while (pages < MAX_ACK_PAGES && page.size == ACK_CANDIDATE_LIMIT && page.all { it.id in attempted }) {
            val oldest = page.minOf { it.createdAt }
            current = current.copy(until = oldest - 1)
            page = fetchAckCandidates(current, relays)
            pages++
        }
        return page
    }

    // ------------------------------------------------------------------
    // Projection
    // ------------------------------------------------------------------

    public suspend fun fetchProjection(pairing: PairingV2): ContactProjectionV2? = orElse(null) {
        val event = relay.fetchNewest(projectionFilter(pairing.railPubkey, pairing.grantId), listOf(pairing.relay), pairing.railPubkey)
            ?: return@orElse null
        ingestProjectionEvent(pairing, event)
    }

    /** The whole acceptance path for ONE projection event, shared by fetch and live. */
    private suspend fun ingestProjectionEvent(pairing: PairingV2, event: SignedNostrEvent): ContactProjectionV2? = lock.withLock {
        orElse(null) {
            // Author pin: a projection not signed by this grant's rail is not this grant's.
            if (!event.pubkey.equals(pairing.railPubkey, ignoreCase = true)) return@orElse null
            if (event.content.length > MAX_ENVELOPE_CHARS) return@orElse null
            // R-4: the content is a v2 vault envelope, never a bare NIP-44 payload.
            val plaintext = openVaultPayload(event.content, signer, pairing.railPubkey) ?: return@orElse null
            val projection = parseProjection(plaintext) ?: return@orElse null
            if (projection.grantId != pairing.grantId) return@orElse null
            // The grant's capabilities are a ceiling on what a projection may claim.
            if (projection.scopes.any { it !in pairing.grantedCapabilities }) return@orElse null
            // And its clamped staleness is a ceiling on the projection's window.
            if (projection.expiresAt - projection.issuedAt > pairing.maxStalenessSeconds) return@orElse null

            val nowSec = now()
            val next = applyProjection(state, projection, nowSec)
            if (next === state) return@orElse null // the frontier rule rejected it
            state = next
            // Tracks state.revoked rather than latching, so each rising edge announces once.
            val alreadyAnnounced = revokedAnnounced
            revokedAnnounced = next.revoked
            reconcilePending(projection, nowSec)
            persistState()
            persistPending(pairing.grantId)
            if (next.revoked && !alreadyAnnounced) {
                // Each listener is isolated: one that throws cannot silence the rest.
                for (cb in revokedListeners) runCatching { cb(next.grantId ?: projection.grantId) }
            }
            projection
        }
    }

    /** R-9: an add-ken clears when a projection carries that pubkey; a rename clears
     *  when the contact shows that label; anything past the staleness window is given up. */
    private fun reconcilePending(projection: ContactProjectionV2, nowSec: Long) {
        val pubkeys = HashSet<String>()
        val labels = HashMap<String, String>()
        for (contact in projection.contacts) {
            contact.identities?.forEach { pubkeys.add(it.pubkey.lowercase()) }
            contact.displayName?.let { labels[contact.contactId] = it }
        }
        pending = pending.filter { p ->
            if (p.grantId != projection.grantId) return@filter true // F2
            if (nowSec - p.sentAt > maxPendingStalenessSeconds) return@filter false
            when (val v = p.value) {
                is AddKenValue -> v.pubkey.lowercase() !in pubkeys
                is RenameAppLabelValue -> labels[v.contactId] != v.label
            }
        }
    }

    private suspend fun persistState() {
        val s = state
        val grantId = s.grantId ?: return
        orElse(Unit) { storage.set("$STATE_KEY_PREFIX$grantId", s.toJson().stringify()) }
    }

    /** Keyed off the CALLER's grantId, and only that grant's rows (F2). */
    private suspend fun persistPending(grantId: String) {
        val scoped = pending.filter { it.grantId == grantId }
        orElse(Unit) { storage.set("$PENDING_KEY_PREFIX$grantId", jsonArray(scoped.map { it.toJson() }).stringify()) }
    }

    // ------------------------------------------------------------------
    // Live updates
    // ------------------------------------------------------------------

    /**
     * R-32: subscribe to this grant's projection slot and poll every [pollMs]
     * as the fallback. One subscription per client: a second call replaces
     * the first. The returned function tears down only while THIS
     * subscription is still current, so a late cleanup is inert.
     */
    public fun start(pairing: PairingV2, pollMs: Long = DEFAULT_LIVE_POLL_MS): () -> Unit {
        val generation: Long
        val filter = projectionFilter(pairing.railPubkey, pairing.grantId)
        synchronized(liveLock) {
            stopLiveLocked()
            generation = liveGeneration
            lastLiveDeliveryMs = 0
            unsubscribe = runCatching {
                relay.subscribe(filter, listOf(pairing.relay)) { event ->
                    lastLiveDeliveryMs = elapsedMs()
                    scope.launch { orElse(null) { ingestProjectionEvent(pairing, event) } }
                }
            }.getOrNull()
            pollJob = scope.launch {
                while (isActive) {
                    delay(pollMs)
                    // A socket that delivered within the last interval is plainly alive.
                    if (unsubscribe != null && elapsedMs() - lastLiveDeliveryMs < pollMs) continue
                    orElse(null) {
                        relay.fetchNewest(filter, listOf(pairing.relay), pairing.railPubkey)?.let { ingestProjectionEvent(pairing, it) }
                    }
                }
            }
        }
        return {
            synchronized(liveLock) { if (generation == liveGeneration) stopLiveLocked() }
        }
    }

    /** Stop the live subscription and the poll. Idempotent. */
    public fun stop() {
        synchronized(liveLock) { stopLiveLocked() }
    }

    private fun stopLiveLocked() {
        liveGeneration++
        unsubscribe?.let { runCatching { it.close() } }
        unsubscribe = null
        pollJob?.cancel()
        pollJob = null
    }

    // ------------------------------------------------------------------
    // State
    // ------------------------------------------------------------------

    public fun getState(): ContactsState = state

    /** Apply at ingress AND at display. Sticky through expiry and revocation. */
    public fun getBlockedSet(): Set<String> = blockedSetOf(state)

    /** A display hint that the directory may be stale, never a permission check. */
    public fun isFresh(nowSec: Long = now()): Boolean = dev.forgesworn.signet.contacts.wire.isFresh(state, nowSec)

    /** R-9: proposals sent and not yet seen applied. Consumer-side only. */
    public fun pendingProposals(): List<PendingProposal> = pending.toList()

    /** Called once per revocation edge. Returns an unsubscribe function. */
    public fun onRevoked(cb: (grantId: String) -> Unit): () -> Unit {
        revokedListeners.add(cb)
        return { revokedListeners.remove(cb) }
    }

    // ------------------------------------------------------------------
    // Proposals
    // ------------------------------------------------------------------

    /**
     * Send [drafts], and RESEND whatever is still pending for this grant (B2):
     * proposals ride one replaceable event per grant, so a second batch would
     * otherwise overwrite an unread first. New drafts go first; resends are
     * newest first, not superseded, still granted, and not stale; the batch is
     * capped so new suggestions are never squeezed out. Two drafts for the
     * same target in one call keep only the last (F3). Everything is scoped
     * to this grant (F2). Returns false, with `pending` untouched, on any
     * failure to build, encrypt, sign or publish.
     */
    public suspend fun propose(pairing: PairingV2, drafts: List<ContactProposalDraft>): Boolean {
        if (drafts.isEmpty()) return false
        val granted = pairing.grantedCapabilities.toSet()
        if (drafts.any { it.action.capability !in granted }) return false

        val createdAt = now()
        val newProposals: List<ContactProposalV1>
        val isSuperseded: (PendingProposal) -> Boolean
        val plaintext: String
        try {
            val stamped = drafts.map { d ->
                if (d is ContactProposalDraft.RenameAppLabel && d.updatedAt == null) d.copy(updatedAt = nowMs()) else d
            }
            val deduped = LinkedHashMap<String, ContactProposalDraft>()
            for (d in stamped) {
                val key = when (d) {
                    is ContactProposalDraft.AddKen -> "add-ken:${d.value.pubkey.lowercase()}"
                    is ContactProposalDraft.RenameAppLabel -> "rename-app-label:${d.contactId}"
                }
                deduped[key] = d // keeps first-seen position, last value
            }
            newProposals = deduped.values.map { draftToProposal(it, pairing.grantId, createdAt, nowMs) }

            val kenPubkeys = newProposals.mapNotNull { (it.value as? AddKenValue)?.pubkey?.lowercase() }.toSet()
            val renameIds = newProposals.mapNotNull { (it.value as? RenameAppLabelValue)?.contactId }.toSet()
            isSuperseded = { p ->
                p.grantId == pairing.grantId && when (val v = p.value) {
                    is AddKenValue -> v.pubkey.lowercase() in kenPubkeys
                    is RenameAppLabelValue -> v.contactId in renameIds
                }
            }
            val maxResendAge = minOf(maxPendingStalenessSeconds, MAX_STALENESS_SECONDS)
            val eligible = pending.filter { p ->
                p.grantId == pairing.grantId && createdAt - p.sentAt <= maxResendAge &&
                    p.action.capability in granted && !isSuperseded(p)
            }.sortedByDescending { it.sentAt } // stable
            val resend = eligible.take(maxOf(0, MAX_PROPOSALS_PER_BATCH - newProposals.size)).map { p ->
                // Byte-identical in meaning to the first send: same operationId, value, createdAt.
                ContactProposalV1(pairing.grantId, p.operationId, p.value, p.sentAt)
            }
            plaintext = buildProposalBatch(newProposals + resend)
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return false
        }

        val ok = orElse(false) {
            val content = signer.nip44Encrypt(pairing.railPubkey, plaintext)
            val event = signer.signEvent(proposalEventTemplate(signer.pubkey, pairing.grantId, createdAt, content))
            relay.publish(event, listOf(pairing.relay))
        }
        // Only a batch that actually reached a relay changes `pending`.
        if (ok) {
            lock.withLock {
                pending = pending.filterNot(isSuperseded) + newProposals.map {
                    PendingProposal(pairing.grantId, it.operationId, it.value, createdAt)
                }
                persistPending(pairing.grantId)
            }
        }
        return ok
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /**
     * Rehydrate this grant's pending proposals and state, Blocked set
     * included. Call BEFORE the first [fetchProjection] on every launch. A
     * stored row is re-validated exactly as a wire value would be; a corrupt
     * projection is dropped without taking the Blocked set with it.
     */
    public suspend fun load(grantId: String): ContactsState = lock.withLock {
        try {
            val rawPending = storage.get("$PENDING_KEY_PREFIX$grantId")
            // Only once the read succeeded: a throwing store keeps what is in memory.
            pending = pending.filter { it.grantId != grantId }
            if (rawPending != null && rawPending.isNotEmpty()) {
                val rows = Json.parse(rawPending).arr()
                if (rows != null) {
                    val loaded = rows.mapNotNull { storedPendingProposal(it) }
                        .filter { it.first == null || it.first == grantId }
                        .map { it.second.copy(grantId = grantId) }
                    pending = pending + loaded
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // Unreadable pending state: a UI convenience, never a correctness input.
        }
        try {
            val raw = storage.get("$STATE_KEY_PREFIX$grantId")
            if (raw != null && raw.isNotEmpty()) {
                val parsed = Json.parse(raw) as? JsonObject
                val blocked = parsed?.get("blockedPubkeys")?.arr()
                if (parsed != null && blocked != null) {
                    val rawProjection = parsed["projection"]
                    val projection = if (rawProjection == null || rawProjection == JsonNull) null else parseProjection(rawProjection)
                    // Pinned to the ARGUMENT grantId: a row addressing another grant
                    // must not resurrect a projection under this one.
                    val next = ContactsState(
                        grantId = grantId,
                        projection = if (parsed["grantId"].str() == grantId) projection else null,
                        receivedAt = parsed["receivedAt"].num()?.takeIf { it.isFinite() }?.toLong() ?: 0,
                        blockedPubkeys = blocked.mapNotNull { it.str() },
                        revoked = parsed["revoked"].isTrue(),
                    )
                    state = next
                    revokedAnnounced = next.revoked
                }
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // Unreadable stored state: start empty rather than throw at app start.
        }
        state
    }

    /**
     * A stored pending row, trusted no further than a wire value: returns its
     * stored grantId (null for a row written before F2) and the row itself.
     */
    private fun storedPendingProposal(candidate: JsonValue): Pair<String?, PendingProposal>? {
        val o = candidate as? JsonObject ?: return null
        val storedGrant = o["grantId"]
        if (storedGrant != null && !isHex(storedGrant, 32)) return null
        if (!isHex(o["operationId"], 32)) return null
        val sentAt = o["sentAt"].num()?.takeIf { it.isFinite() } ?: return null
        val v = o["value"] as? JsonObject ?: return null
        val value = when (ProposalAction.fromWire(o["action"].str())) {
            ProposalAction.ADD_KEN -> {
                if (!isHex(v["pubkey"], 64)) return null
                AddKenValue(v["pubkey"].str()!!, v["displayName"].str() ?: return null)
            }
            ProposalAction.RENAME_APP_LABEL -> {
                if (!isHex(v["contactId"], 32)) return null
                val label = v["label"].str() ?: return null
                val updatedAt = v["updatedAt"].num()?.takeIf { it.isFinite() } ?: return null
                RenameAppLabelValue(v["contactId"].str()!!, label, updatedAt.toLong())
            }
            null -> return null
        }
        return storedGrant.str() to PendingProposal("", o["operationId"].str()!!, value, sentAt.toLong())
    }
}
