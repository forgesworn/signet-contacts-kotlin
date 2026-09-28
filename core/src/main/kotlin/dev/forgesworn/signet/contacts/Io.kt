package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.wire.NostrFilter
import dev.forgesworn.signet.contacts.wire.OpenEnvelopeBackend
import dev.forgesworn.signet.contacts.wire.SealEnvelopeBackend
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.UnsignedNostrEvent
import java.util.concurrent.ConcurrentHashMap

/**
 * The app's OWN signer: NIP-46, a hardware signer, or a local key. No second
 * key is needed. `nip44Decrypt` may be a remote round trip; the SDK
 * type-checks what comes back rather than trusting it.
 */
public interface ContactsSigner : SealEnvelopeBackend, OpenEnvelopeBackend {
    /** Lowercase 64-hex x-only public key. */
    public val pubkey: String

    public suspend fun signEvent(event: UnsignedNostrEvent): SignedNostrEvent
}

/** A live subscription handle. Closing twice is harmless. */
public fun interface RelaySubscription {
    public fun close()
}

/**
 * Relay I/O. Implementations MUST verify event signatures (the bundled
 * [dev.forgesworn.signet.contacts.adapters.PoolRelayIo] can do it for you).
 */
public interface RelayIo {
    /** The newest event matching [filter] across [relays], or null. [author], when
     *  given, pins the answer to that pubkey. */
    public suspend fun fetchNewest(filter: NostrFilter, relays: List<String>, author: String? = null): SignedNostrEvent?

    /** True when at least one relay accepted [event]. */
    public suspend fun publish(event: SignedNostrEvent, relays: List<String>): Boolean

    /**
     * I3: several candidates for one filter, NEWEST FIRST, deduped by id and
     * capped at `filter.limit`. Return null when the transport cannot do it;
     * the client then falls back to [fetchNewest].
     */
    public suspend fun fetchMany(filter: NostrFilter, relays: List<String>, author: String? = null): List<SignedNostrEvent>? = null

    /**
     * R-32: live delivery of everything matching [filter] until the returned
     * subscription is closed. Return null when the transport cannot do it; the
     * client then runs on polling alone. [onEvent] may be called on any thread.
     */
    public fun subscribe(filter: NostrFilter, relays: List<String>, onEvent: (SignedNostrEvent) -> Unit): RelaySubscription? = null
}

/**
 * Where the sticky Blocked set and pending proposals persist. Both calls are
 * free to fail: the client treats storage as a convenience and never throws
 * out of a read or a write.
 */
public interface StorageIo {
    public suspend fun get(key: String): String?
    public suspend fun set(key: String, value: String)
}

/** In-memory storage, per client. Nothing survives the process, including the
 *  Blocked set: pass a persistent [StorageIo] in any real app. */
public class MemoryStorage : StorageIo {
    private val map = ConcurrentHashMap<String, String>()
    override suspend fun get(key: String): String? = map[key]
    override suspend fun set(key: String, value: String) {
        map[key] = value
    }
}
