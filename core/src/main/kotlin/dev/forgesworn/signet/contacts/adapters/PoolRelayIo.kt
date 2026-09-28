package dev.forgesworn.signet.contacts.adapters

import dev.forgesworn.signet.contacts.RelayIo
import dev.forgesworn.signet.contacts.RelaySubscription
import dev.forgesworn.signet.contacts.wire.NostrFilter
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.isValidContactsRelayUrl
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeoutOrNull
import kotlin.coroutines.cancellation.CancellationException

/**
 * The per-relay primitives a Nostr client library already has. Structural on
 * purpose, as the TypeScript `SimplePoolLike` is: wrap Quartz, an OkHttp
 * socket, or anything else, and [PoolRelayIo] adds the bounds and the rules.
 */
public interface RelayPool {
    /** The newest event [relay] holds for [filter], or null. Throwing reads as "no answer". */
    public suspend fun get(relay: String, filter: NostrFilter): SignedNostrEvent?

    /** Every event [relay] returns for [filter] up to EOSE, or null when the pool
     *  cannot query (the adapter then falls back to [get]). */
    public suspend fun query(relay: String, filter: NostrFilter): List<SignedNostrEvent>? = null

    /** Returns when [relay] accepted [event]; throws when it refused. */
    public suspend fun publish(relay: String, event: SignedNostrEvent)

    /** Live delivery across [relays] until closed. */
    public fun subscribe(relays: List<String>, filter: NostrFilter, onEvent: (SignedNostrEvent) -> Unit): RelaySubscription
}

/** Bounds every individual pool call. */
public const val DEFAULT_RELAY_TIMEOUT_MS: Long = 8000

private const val DEFAULT_FETCH_MANY_LIMIT = 10
private const val MAX_FETCH_MANY_LIMIT = 100

/**
 * [RelayIo] over a [RelayPool]. Every pool call is raced against
 * [timeoutMs]; a stalled, failed or malformed answer reads as "no answer from
 * that relay", never as a hang or a throw. Relays are queried one by one so
 * this adapter, not the pool, decides which answer is newest: highest
 * `created_at`, a same-second tie going to the LOWEST id.
 *
 * @param verify when given, every event is checked with it and dropped on
 *   false. Pass the `nostr` module's signature check unless the pool already
 *   verifies; [RelayIo] requires verified events.
 */
public class PoolRelayIo(
    private val pool: RelayPool,
    private val timeoutMs: Long = DEFAULT_RELAY_TIMEOUT_MS,
    private val verify: ((SignedNostrEvent) -> Boolean)? = null,
) : RelayIo {
    /** A bad relay list is a caller bug, not a transient failure, so it throws. */
    private fun assertValidRelays(relays: List<String>) {
        for (r in relays) {
            require(isValidContactsRelayUrl(r)) { "signet-contacts: relay must be wss:// or ws://localhost|127.0.0.1, got \"$r\"" }
        }
    }

    private suspend fun <T> bounded(block: suspend () -> T): T? = try {
        withTimeoutOrNull(timeoutMs) { block() }
    } catch (e: CancellationException) {
        throw e
    } catch (_: Throwable) {
        null
    }

    private fun accept(event: SignedNostrEvent, author: String?): Boolean {
        if (author != null && !event.pubkey.equals(author, ignoreCase = true)) return false
        return verify?.let { v -> runCatching { v(event) }.getOrDefault(false) } ?: true
    }

    private fun newer(a: SignedNostrEvent, b: SignedNostrEvent): Boolean =
        a.createdAt > b.createdAt || (a.createdAt == b.createdAt && a.id < b.id)

    override suspend fun fetchNewest(filter: NostrFilter, relays: List<String>, author: String?): SignedNostrEvent? {
        assertValidRelays(relays)
        val answers = coroutineScope { relays.map { r -> async { bounded { pool.get(r, filter) } } }.awaitAll() }
        var best: SignedNostrEvent? = null
        for (event in answers) {
            if (event == null || !accept(event, author)) continue
            if (best == null || newer(event, best)) best = event
        }
        return best
    }

    override suspend fun fetchMany(filter: NostrFilter, relays: List<String>, author: String?): List<SignedNostrEvent> {
        assertValidRelays(relays)
        val limit = filter.limit?.takeIf { it > 0 }?.let { minOf(it, MAX_FETCH_MANY_LIMIT) } ?: DEFAULT_FETCH_MANY_LIMIT
        val answers = coroutineScope {
            relays.map { r ->
                async {
                    bounded {
                        val many = pool.query(r, filter)
                        many?.take(MAX_FETCH_MANY_LIMIT) ?: listOfNotNull(pool.get(r, filter))
                    }.orEmpty()
                }
            }.awaitAll()
        }
        val byId = LinkedHashMap<String, SignedNostrEvent>()
        for (event in answers.flatten()) {
            if (!accept(event, author)) continue
            byId.putIfAbsent(event.id, event)
        }
        return byId.values.sortedWith { a, b ->
            if (a.createdAt != b.createdAt) b.createdAt.compareTo(a.createdAt) else a.id.compareTo(b.id)
        }.take(limit)
    }

    override suspend fun publish(event: SignedNostrEvent, relays: List<String>): Boolean {
        assertValidRelays(relays)
        // Any ONE relay accepting is enough for the event to reach the network.
        val settled = coroutineScope { relays.map { r -> async { bounded { pool.publish(r, event); true } ?: false } }.awaitAll() }
        return settled.any { it }
    }

    override fun subscribe(filter: NostrFilter, relays: List<String>, onEvent: (SignedNostrEvent) -> Unit): RelaySubscription {
        assertValidRelays(relays)
        val sub = pool.subscribe(relays, filter) { event -> if (accept(event, null)) onEvent(event) }
        return RelaySubscription { runCatching { sub.close() } }
    }
}
