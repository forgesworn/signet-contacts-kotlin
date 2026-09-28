package dev.forgesworn.signet.contacts.adapters

import dev.forgesworn.signet.contacts.RelaySubscription
import dev.forgesworn.signet.contacts.wire.NostrFilter
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.test.currentTime
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Ported from adapters/nostr-tools.test.ts. The Kotlin port's [RelayPool] is
 * per-relay (`get`/`query`/`publish`/`subscribe` each take one relay), unlike
 * the TypeScript `SimplePoolLike`, which is handed the whole relay list per
 * call - so fixtures here are built around one [RelayPool] whose `get`/
 * `query`/`publish` behaviour is keyed off the `relay` argument, rather than
 * a single pool-wide mock.
 */
@OptIn(kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class PoolRelayIoTest {
    private val event = SignedNostrEvent(
        id = "0".repeat(64), pubkey = "b".repeat(64), createdAt = 1, kind = 30078,
        tags = listOf(listOf("d", "a".repeat(32))), content = "ciphertext", sig = "1".repeat(128),
    )

    private class FakePool(
        var getImpl: suspend (String, NostrFilter) -> SignedNostrEvent? = { _, _ -> null },
        var queryImpl: (suspend (String, NostrFilter) -> List<SignedNostrEvent>?)? = null,
        var publishImpl: suspend (String, SignedNostrEvent) -> Unit = { _, _ -> },
        var subscribeImpl: (List<String>, NostrFilter, (SignedNostrEvent) -> Unit) -> RelaySubscription = { _, _, _ -> RelaySubscription {} },
    ) : RelayPool {
        val getCalls: MutableList<Pair<String, NostrFilter>> = mutableListOf()
        override suspend fun get(relay: String, filter: NostrFilter): SignedNostrEvent? {
            getCalls.add(relay to filter)
            return getImpl(relay, filter)
        }
        override suspend fun query(relay: String, filter: NostrFilter): List<SignedNostrEvent>? = queryImpl?.invoke(relay, filter)
        override suspend fun publish(relay: String, event: SignedNostrEvent) = publishImpl(relay, event)
        override fun subscribe(relays: List<String>, filter: NostrFilter, onEvent: (SignedNostrEvent) -> Unit): RelaySubscription =
            subscribeImpl(relays, filter, onEvent)
    }

    @Test
    fun `maps fetchNewest onto pool_get and pins the author`() = runTest {
        val pool = FakePool(getImpl = { _, _ -> event })
        val io = PoolRelayIo(pool)
        assertEquals(event, io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("wss://r.example"), event.pubkey))
        assertEquals("wss://r.example" to NostrFilter(kinds = listOf(30078)), pool.getCalls[0])
        assertNull(io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("wss://r.example"), "c".repeat(64)))
    }

    // TS also checked "answers with a non-event" (a plain `{ not: 'an event' }`
    // object smuggled past the type system): RelayPool.get is typed
    // suspend fun get(...): SignedNostrEvent?, so a non-conforming value
    // cannot be returned at all in Kotlin. Only the throwing half ports.
    @Test
    fun `returns null when the pool throws`() = runTest {
        val pool = FakePool(getImpl = { _, _ -> throw RuntimeException("offline") })
        val io = PoolRelayIo(pool)
        assertNull(io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("wss://r.example")))
    }

    @Test
    fun `maps fetchMany onto pool_query, newest first and deduped by id`() = runTest {
        val older = event.copy(id = "1".repeat(64), createdAt = 10)
        val newer = event.copy(id = "2".repeat(64), createdAt = 20)
        var queryCalls = 0
        val pool = FakePool(queryImpl = { _, _ -> queryCalls++; listOf(older, newer, newer.copy()) })
        val io = PoolRelayIo(pool)
        val many = io.fetchMany(NostrFilter(kinds = listOf(21237), limit = 10), listOf("wss://r.example"))
        assertEquals(listOf(newer.id, older.id), many.map { it.id })
        assertTrue(queryCalls > 0)
    }

    @Test
    fun `caps fetchMany at the filter limit and pins the author`() = runTest {
        val events = (0 until 5).map { i -> event.copy(id = i.toString().repeat(64), createdAt = 100L + i) }
        val stranger = event.copy(id = "9".repeat(64), createdAt = 999, pubkey = "c".repeat(64))
        val pool = FakePool(queryImpl = { _, _ -> events + stranger })
        val io = PoolRelayIo(pool)
        val many = io.fetchMany(NostrFilter(kinds = listOf(21237), limit = 2), listOf("wss://r.example"), event.pubkey)
        assertEquals(2, many.size)
        assertTrue(many.all { it.pubkey == event.pubkey })
        assertEquals(104L, many[0].createdAt)
    }

    @Test
    fun `degrades fetchMany to one get per relay when the pool has no query`() = runTest {
        val perRelay = mapOf(
            "wss://a.example" to event.copy(id = "a".repeat(64), createdAt = 5),
            "wss://b.example" to event.copy(id = "b".repeat(64), createdAt = 9),
        )
        val pool = FakePool(getImpl = { relay, _ -> perRelay[relay] })
        val io = PoolRelayIo(pool)
        val many = io.fetchMany(NostrFilter(kinds = listOf(21237), limit = 10), listOf("wss://a.example", "wss://b.example"))
        assertEquals(listOf("b".repeat(64), "a".repeat(64)), many.map { it.id })
    }

    @Test
    fun `resolves fetchMany to an empty list when every relay times out or throws`() = runTest {
        val pool = FakePool(queryImpl = { _, _ -> throw RuntimeException("offline") })
        val io = PoolRelayIo(pool, timeoutMs = 10)
        assertEquals(emptyList(), io.fetchMany(NostrFilter(kinds = listOf(21237)), listOf("wss://r.example")))
    }

    @Test
    fun `resolves publish true when at least one relay accepts`() = runTest {
        val pool = FakePool(publishImpl = { relay, _ -> if (relay == "wss://a.example") throw RuntimeException("rejected") })
        val io = PoolRelayIo(pool)
        assertTrue(io.publish(event, listOf("wss://a.example", "wss://b.example")))
    }

    @Test
    fun `resolves publish false when every relay rejects`() = runTest {
        val pool = FakePool(publishImpl = { _, _ -> throw RuntimeException("no") })
        val io = PoolRelayIo(pool)
        assertFalse(io.publish(event, listOf("wss://a.example")))
    }

    @Test
    fun `forwards events through verify and closes cleanly`() {
        var closeCalls = 0
        var emit: ((SignedNostrEvent) -> Unit)? = null
        val pool = FakePool(subscribeImpl = { _, _, onEvent -> emit = onEvent; RelaySubscription { closeCalls++ } })
        // A `verify` backend stands in for the "well-formed events only" check
        // the TS adapter did by type-narrowing a raw `unknown`: Kotlin's
        // RelayPool.subscribe callback is already typed SignedNostrEvent, so
        // there is no untyped junk to filter - `verify` is the equivalent gate.
        val io = PoolRelayIo(pool, verify = { it.id == event.id })
        val seen = mutableListOf<SignedNostrEvent>()
        val sub = io.subscribe(NostrFilter(kinds = listOf(30078)), listOf("wss://r.example")) { seen.add(it) }
        emit!!(event.copy(id = "9".repeat(64)))
        emit!!(event)
        assertEquals(listOf(event), seen)
        sub.close()
        assertEquals(1, closeCalls)
    }

    @Test
    fun `picks the newest event across relays when they disagree`() = runTest {
        val older = event.copy(id = "1".repeat(64), createdAt = 3)
        val newer = event.copy(id = "2".repeat(64), createdAt = 5)
        val pool = FakePool(getImpl = { relay, _ -> if (relay == "wss://a.example") older else newer })
        val io = PoolRelayIo(pool)
        val result = io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("wss://a.example", "wss://b.example"), event.pubkey)
        assertEquals(newer, result)
    }

    @Test
    fun `breaks a same-createdAt tie by the lowest id`() = runTest {
        val highId = event.copy(id = "f".repeat(64), createdAt = 5)
        val lowId = event.copy(id = "0".repeat(64), createdAt = 5)
        val pool = FakePool(getImpl = { relay, _ -> if (relay == "wss://a.example") highId else lowId })
        val io = PoolRelayIo(pool)
        val result = io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("wss://a.example", "wss://b.example"), event.pubkey)
        assertEquals(lowId, result)
    }

    @Test
    fun `bounds fetchNewest to timeoutMs and resolves null on a stalling relay`() = runTest {
        val pool = FakePool(getImpl = { _, _ -> CompletableDeferred<SignedNostrEvent?>().await() })
        val io = PoolRelayIo(pool, timeoutMs = 5000)
        val result = io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("wss://r.example"))
        assertNull(result)
        assertEquals(5000L, currentTime)
    }

    @Test
    fun `clears the timer immediately when a relay answers before the timeout`() = runTest {
        val pool = FakePool(getImpl = { _, _ -> event })
        val io = PoolRelayIo(pool, timeoutMs = 5000)
        val result = io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("wss://r.example"), event.pubkey)
        assertEquals(event, result)
        assertTrue(currentTime < 5000L)
    }

    @Test
    fun `bounds publish to timeoutMs and resolves false when every relay stalls`() = runTest {
        val pool = FakePool(publishImpl = { _, _ -> CompletableDeferred<Unit>().await() })
        val io = PoolRelayIo(pool, timeoutMs = 4000)
        val result = io.publish(event, listOf("wss://a.example"))
        assertFalse(result)
        assertEquals(4000L, currentTime)
    }

    @Test
    fun `resolves publish true when one relay answers before the timeout and another stalls`() = runTest {
        val pool = FakePool(publishImpl = { relay, _ -> if (relay == "wss://a.example") CompletableDeferred<Unit>().await() })
        val io = PoolRelayIo(pool, timeoutMs = 4000)
        assertTrue(io.publish(event, listOf("wss://a.example", "wss://b.example")))
    }

    @Test
    fun `throws synchronously for a relay URL that is neither wss nor loopback ws`() = runTest {
        val pool = FakePool()
        val io = PoolRelayIo(pool)
        assertFailsWith<IllegalArgumentException> { io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("http://evil.example")) }
        assertFailsWith<IllegalArgumentException> { io.publish(event, listOf("ws://evil.example")) }
        assertFailsWith<IllegalArgumentException> { io.subscribe(NostrFilter(kinds = listOf(30078)), listOf("ws://192.168.1.1")) {} }
    }

    @Test
    fun `accepts wss and loopback ws relays`() = runTest {
        val pool = FakePool(getImpl = { _, _ -> null })
        val io = PoolRelayIo(pool)
        assertNull(io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("ws://localhost:4869")))
        assertNull(io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("ws://127.0.0.1:4869")))
        assertNull(io.fetchNewest(NostrFilter(kinds = listOf(30078)), listOf("wss://relay.example")))
    }

    // TS also had "never rejects, and clears the timer, when the pool returns
    // a synchronous non-promise value" - a pool that satisfies the structural
    // `SimplePoolLike` shape but lies about being async (returns a plain
    // value instead of a real Promise). RelayPool's methods are `suspend
    // fun`s: Kotlin's coroutine machinery compiles every implementation to
    // proper continuation-passing, so there is no "satisfies the interface
    // but is secretly synchronous/non-thenable" case to guard against - the
    // language rules it out. Skipped: no Kotlin equivalent.
}
