# signet-contacts-kotlin

A Kotlin port of [signet-contacts](https://github.com/forgesworn/signet-contacts):
the v2 wire for **application access to a Signet contact directory**.
Capability-scoped pairing, a per-grant encrypted projection the owner controls,
and a small proposal channel for an app to ask (never demand) for a contact to
be added or relabelled.

It is a *consumer* SDK: it runs inside the app that wants a slice of somebody's
contacts, once that person has granted it. It targets the JVM 17 bytecode
level, so it works on Android (minSdk 26 and up) and on a desktop JVM.

Consumer requirements: Android Gradle Plugin 8.x or later (needed for JVM 17
bytecode, class-file major version 61, and `PermittedSubclasses` on sealed
classes), and Kotlin 2.0 or later. No JDK-only API is used anywhere in the
public surface, so both artefacts run unmodified on Android.

The TypeScript package is the reference. This port is held to it by
[signet-contacts-conformance](https://github.com/forgesworn/signet-contacts-conformance):
every vector there runs in this build, and a mismatch fails it.

## Modules

| Artefact | What it is | Dependencies |
| --- | --- | --- |
| `dev.forgesworn:signet-contacts` | the wire layer, `SignetContactsClient`, `AppInviteClient`, and `PoolRelayIo` over any Nostr client's per-relay primitives | kotlinx-coroutines only; crypto is the JDK's own |
| `dev.forgesworn:signet-contacts-nostr` | secp256k1 event signing and verification, NIP-44 v2, a `LocalKeySigner`, and the contact-exchange mailbox (`InviteMailbox`) | secp256k1-kmp |

The split matches the TypeScript package, where nostr-tools is an optional peer
dependency: an app that already has a signer and a relay pool never needs the
second artefact. If you do use it, add the native half for your platform, at
the version the nostr module compiles its API half against (`0.19.0`):
`fr.acinq.secp256k1:secp256k1-kmp-jni-android:0.19.0` on Android,
`fr.acinq.secp256k1:secp256k1-kmp-jni-jvm:0.19.0` on a desktop JVM.

One Gradle caveat on the desktop JVM: the classes behind
`secp256k1-kmp-jni-jvm` are Java 8 bytecode and run on JVM 17, but its Gradle
module metadata declares JVM 21. A Gradle build that targets JVM 17 refuses to
resolve it ("no matching variant"). Either build with a JDK 21 target, or set
`TargetJvmVersion.TARGET_JVM_VERSION_ATTRIBUTE` to 21 on the classpaths that
resolve it, as the `nostr` test classpaths in this repository do
(`nostr/build.gradle.kts`). `secp256k1-kmp-jni-android` is not affected.

Packages: the client, `ContactsSigner`, `RelayIo` and `StorageIo` are in
`dev.forgesworn.signet.contacts`; `PoolRelayIo` and `RelayPool` in
`dev.forgesworn.signet.contacts.adapters`; the wire types, `Capability` and
`DirectoryKind` in `dev.forgesworn.signet.contacts.wire`; `Json` in
`dev.forgesworn.signet.contacts.json`; and, from the second artefact,
`NostrEvents`, `LocalKeySigner` and `InviteMailbox` in
`dev.forgesworn.signet.contacts.nostr`.

## Install

There is no published release yet. Use a Gradle composite build against a
checkout pinned to a commit you have reviewed:

```bash
git clone https://github.com/forgesworn/signet-contacts-kotlin ../signet-contacts-kotlin
git -C ../signet-contacts-kotlin checkout <commit>
```

```kotlin
// settings.gradle.kts
includeBuild("../signet-contacts-kotlin")

// build.gradle.kts
dependencies {
    implementation("dev.forgesworn:signet-contacts:0.1.0")
    implementation("dev.forgesworn:signet-contacts-nostr:0.1.0") // optional
}
```

`includeBuild` substitutes each dependency by group and Gradle project name, so
the code you get is whatever the checkout contains. The checkout names its
projects after the artefacts (`:signet-contacts` and `:signet-contacts-nostr`,
in the `core/` and `nostr/` directories) and sets the group `dev.forgesworn`
for both, so the two coordinates above resolve to it. Keep `0.1.0`, the version
the checkout declares in its root `build.gradle.kts`. The native secp256k1
artefacts above are not part of the checkout: add them yourself if you use the
nostr module.

## Interfaces

You supply a `ContactsSigner`, a `RelayPool` (wrapped by `PoolRelayIo`, which
implements `RelayIo`) and, in any real app, a `StorageIo`. Signatures as
declared in the source, KDoc omitted:

```kotlin
// dev.forgesworn.signet.contacts
interface ContactsSigner : SealEnvelopeBackend, OpenEnvelopeBackend {
    val pubkey: String                                      // lowercase 64-hex x-only key
    suspend fun signEvent(event: UnsignedNostrEvent): SignedNostrEvent
    // inherited from SealEnvelopeBackend and OpenEnvelopeBackend (package ...wire):
    //   suspend fun nip44Encrypt(peerPubkey: String, plaintext: String): String
    //   suspend fun nip44Decrypt(peerPubkey: String, ciphertext: String): String
}

fun interface RelaySubscription { fun close() }             // closing twice is harmless

interface RelayIo {                                         // PoolRelayIo implements this
    suspend fun fetchNewest(filter: NostrFilter, relays: List<String>, author: String? = null): SignedNostrEvent?
    suspend fun publish(event: SignedNostrEvent, relays: List<String>): Boolean   // true if at least one relay accepted
    suspend fun fetchMany(filter: NostrFilter, relays: List<String>, author: String? = null): List<SignedNostrEvent>? = null
    fun subscribe(filter: NostrFilter, relays: List<String>, onEvent: (SignedNostrEvent) -> Unit): RelaySubscription? = null
}

interface StorageIo {
    suspend fun get(key: String): String?
    suspend fun set(key: String, value: String)
}

// dev.forgesworn.signet.contacts.adapters
interface RelayPool {                                       // what you wrap; note relays come first here
    suspend fun get(relay: String, filter: NostrFilter): SignedNostrEvent?
    suspend fun query(relay: String, filter: NostrFilter): List<SignedNostrEvent>? = null
    suspend fun publish(relay: String, event: SignedNostrEvent)     // throws when the relay refuses
    fun subscribe(relays: List<String>, filter: NostrFilter, onEvent: (SignedNostrEvent) -> Unit): RelaySubscription
}

class PoolRelayIo(
    pool: RelayPool,
    timeoutMs: Long = DEFAULT_RELAY_TIMEOUT_MS,             // 8000, per pool call
    verify: (SignedNostrEvent) -> Boolean,                  // required
) : RelayIo
```

`RelayIo.fetchMany` and `subscribe` return `null` by default, meaning "this
transport cannot do it": the client then falls back to `fetchNewest` and to
polling. `PoolRelayIo` implements all four methods. Each of them throws
`IllegalArgumentException` for a relay that is not `wss://` (or `ws://localhost`
/ `ws://127.0.0.1`); inside the client's own calls that reads as a `null` or
`false` result.

## Quick start

`awaitPairingAck`, `fetchProjection` and `load` are `suspend` functions: run the
block below inside a coroutine.

```kotlin
import dev.forgesworn.signet.contacts.ContactsSigner
import dev.forgesworn.signet.contacts.SignetContactsClient
import dev.forgesworn.signet.contacts.StorageIo
import dev.forgesworn.signet.contacts.adapters.PoolRelayIo
import dev.forgesworn.signet.contacts.nostr.NostrEvents   // artefact dev.forgesworn:signet-contacts-nostr
import dev.forgesworn.signet.contacts.wire.Capability
import dev.forgesworn.signet.contacts.wire.DirectoryKind
import dev.forgesworn.signet.contacts.wire.randomHex      // a core export, not a placeholder

val signer: ContactsSigner = yourSigner      // your app's OWN signer: NIP-46, a hardware signer, or a local key
// NostrEvents is in dev.forgesworn:signet-contacts-nostr. A core-only app passes its
// own verifier instead, or verify = { true } if its pool already checks signatures.
val relay = PoolRelayIo(yourRelayPool, verify = NostrEvents::verify)
// `verify` is required, not optional: without it, a relay in the pool could
// forge an event with a far-future created_at and win fetchNewest, hiding an
// honest relay's newer projection, block or revocation. If your pool already
// verifies signatures, pass `verify = { true }` explicitly as a deliberate,
// documented opt-out.

// Storage is where the sticky Blocked set lives. The default is in memory,
// so a client built without one forgets every block on restart.
val storage = object : StorageIo {
    override suspend fun get(key: String) = prefs.getString(key, null)
    override suspend fun set(key: String, value: String) { prefs.edit().putString(key, value).apply() }
}
val client = SignetContactsClient(signer, relay, storage)

val capabilities = listOf(Capability.READ_DIRECTORY, Capability.BLOCKS_READ)
val challenge = randomHex(16)  // 32 lowercase hex chars (128 bits), the length a challenge must be
val uri = client.buildPairingUri(                 // String; throws IllegalArgumentException on bad input
    appName = "My App", capabilities = capabilities, directory = DirectoryKind.OWNER,
    relay = "wss://relay.example.com", nowSec = System.currentTimeMillis() / 1000, challenge = challenge,  // nowSec: Long
)
showQrCode(uri) // the owner scans it in Signet

// Narrowing only: an ack granting anything you did not ask for is refused.
val pairing = client.awaitPairingAck(challenge, listOf("wss://relay.example.com"), requestedCapabilities = capabilities)  // PairingV2?
if (pairing != null) {
    savePairing(pairing.toJson().stringify())      // your own persistence; PairingV2.fromJson reads it back
    client.load(pairing.grantId)                    // ContactsState: rehydrate state, Blocked set included
    val projection = client.fetchProjection(pairing)  // ContactProjectionV2?
    val blocked = client.getBlockedSet()            // Set<String> of pubkeys; apply at ingress AND at display
    val waiting = client.pendingProposals()         // List<PendingProposal>: sent, not yet applied
    val stop = client.start(pairing)                // () -> Unit; live updates + poll fallback
}
```

**Results and failures.** Hostile or malformed relay data and storage failures
never throw out of a public client method: they read as `null` or `false`.
Cancellation still propagates as it does in Kotlin.

- `awaitPairingAck` returns `null` on timeout (default `timeoutMs` is
  `2 * PAIRING_FRESHNESS_SECONDS * 1000`, ten minutes), or once it has opened 32
  distinct candidate acks without finding one for this challenge. There is no
  denial signal: an ack that grants more than `requestedCapabilities`, or that
  names your own key as the rail, is skipped and the wait carries on.
  Cancelling the calling coroutine abandons the wait; it throws rather than
  returning `null`.
- `fetchProjection` returns `ContactProjectionV2?` and throws nothing but
  cancellation. `null` means no acceptable projection: no event found, not
  signed by the grant's rail, a bad envelope, a wrong grant id, a scope the
  grant did not give, a window wider than the grant's `maxStalenessSeconds`, or
  not newer than the one already held. A projection with `revoked = true` is
  returned like any other.
- `start` throws `IllegalStateException("client is closed")` after `close()`.
- `PairingV2.fromJson(text)` returns `null` for anything it cannot validate.
- `propose` returns `Boolean`; `false` leaves `pendingProposals()` untouched.

On every later launch, reload the pairing yourself and call
`client.load(pairing.grantId)` **before** `client.fetchProjection(pairing)`.

### Relaunch, revocation and proposals

Relaunch from a saved pairing. `PairingV2.fromJson` takes the saved string
itself (it parses the JSON for you), so there is no `Json.parse` step:

```kotlin
import dev.forgesworn.signet.contacts.wire.PairingV2

val pairing = PairingV2.fromJson(savedText)    // PairingV2?; null if the text is invalid
    ?: return startPairingAgain()               // your own fallback: pair afresh
client.load(pairing.grantId)                    // BEFORE fetchProjection; returns ContactsState
val projection = client.fetchProjection(pairing)
val stop = client.start(pairing)
```

React to revocation. `onRevoked` fires once per revocation edge and returns an
unsubscribe function. The grant id is the only argument; keep the Blocked set
applied afterwards, because revocation never un-blocks anybody:

```kotlin
val off = client.onRevoked { grantId ->         // cb: (grantId: String) -> Unit; returns () -> Unit
    // runs on the ingest's dispatcher, not necessarily main; must not block
    forgetGrant(grantId)                        // your own cleanup; keep applying getBlockedSet()
}
off()                                           // unsubscribe
```

Send a proposal. The grant must include `Capability.PROPOSE_ADD_KEN` (for
`AddKen`) or `Capability.PROPOSE_RENAME_APP_LABEL` (for `RenameAppLabel`), so
ask for it in `buildPairingUri`. `propose` returns `false`, with nothing
recorded as pending, if a draft needs a capability that was not granted or
anything fails to build, encrypt, sign or publish. It also resends whatever is
still pending for the grant:

```kotlin
import dev.forgesworn.signet.contacts.wire.ContactProposalDraft

val sent: Boolean = client.propose(              // suspend
    pairing,
    listOf(
        ContactProposalDraft.AddKen(pubkey = someHexPubkey, displayName = "Sam"),
        ContactProposalDraft.RenameAppLabel(contactId = someContactId, label = "Sam (work)"), // updatedAt defaults to nowMs()
    ),
)
```

Proposals are requests, not writes: Signet decides. A proposal stays in
`pendingProposals()` until an accepted projection shows it applied (the pubkey
for an add, the label for a rename), or until an accepted projection arrives
after it is older than `maxPendingStalenessSeconds` (constructor parameter,
default `DEFAULT_PENDING_STALENESS_SECONDS`, a week).

### Capability and DirectoryKind values

`Capability` (declaration order is binding: it is the order `scopes` and a
grant screen use). `Capability.fromWire(token)` returns `null` for an unknown
token, and `capability.wire` is the token below.

| Enum value | Wire string |
| --- | --- |
| `READ_DIRECTORY` | `signet.contacts.read:directory` |
| `READ_METHOD_PHONE` | `signet.contacts.read:method:phone` |
| `READ_METHOD_EMAIL` | `signet.contacts.read:method:email` |
| `READ_METHOD_WEBSITE` | `signet.contacts.read:method:website` |
| `READ_METHOD_POSTAL_ADDRESS` | `signet.contacts.read:method:postal-address` |
| `READ_METHOD_OTHER` | `signet.contacts.read:method:other` |
| `READ_TIER` | `signet.contacts.read:tier` |
| `READ_CHECKS` | `signet.contacts.read:checks` |
| `READ_CHECK_RECORDS` | `signet.contacts.read:check-records` |
| `READ_ROLES` | `signet.contacts.read:roles` |
| `BLOCKS_READ` | `signet.contacts.blocks.read` |
| `PROPOSE_ADD_KEN` | `signet.contacts.propose:add-ken` |
| `PROPOSE_RENAME_APP_LABEL` | `signet.contacts.propose:rename-app-label` |
| `INVITES_CREATE` | `signet.contacts.invites:create` |
| `INVITES_RECEIVE` | `signet.contacts.invites:receive` |

`DirectoryKind` (`DirectoryKind.fromWire(token)` returns `null` for an unknown
token):

| Enum value | Wire string |
| --- | --- |
| `OWNER` | `owner` |
| `DEPENDANT` | `dependant` |

`stop` (returned by `start`, or `client.stop()`) cancels the live subscription,
the poll, and every ingest still in flight from that run, so a suspended
ingest can never write state after the caller believed the client had
stopped. It is not a barrier, though: an ingest that had already passed its
final cancellation check - immediately before it commits - completes that
commit in full (state, both storage keys and any revocation announcement)
even though `stop()` has already returned; it is never left half-written. A
caller that needs a hard guarantee no more writes land after `stop()`
returns should cancel its own injected `scope` and join it instead. Call
`client.close()` when the client itself is done for good: it calls `stop()`
and, only if the client created its own `CoroutineScope` (you left the
constructor's `scope` at its default), cancels that scope too - a scope you
inject remains yours to cancel. `close()` is terminal: calling `start()`
afterwards throws `IllegalStateException` rather than opening a subscription
that would leak, since nothing is left running to ever tear it down.

`onRevoked` (and any future listener) fires on whatever coroutine dispatcher
ran the ingest that triggered it - `scope`'s dispatcher for a live push or a
poll tick, your own for a direct `fetchProjection` call - never guaranteed to
be the main thread. On Android, dispatch to main yourself inside the
callback; the callback itself must not block.

`elapsedMs` defaults to a monotonic clock (`System.nanoTime`), not wall-clock
time, so a deadline or a live-delivery gap can never appear to run backward
across a system clock step. On Android, pass `SystemClock::elapsedRealtime`
instead, since it (unlike `nanoTime`) keeps running correctly across doze.

`yourRelayPool` implements `RelayPool`: `get`, optionally `query`, `publish`
and `subscribe`, per relay. Wrap whatever Nostr client the app already uses;
`PoolRelayIo` adds per-call timeouts, deterministic newest-event selection,
author pinning, de-duplication and mandatory signature checks via `verify`.

The rules in the reference README apply unchanged: keep the last projection
until a newer one arrives, treat `isFresh()` as a display hint, never un-block
anyone because a projection expired or the grant was revoked, and remember
that revocation is not recall and Kin means close circle, not family.

## Differences from the TypeScript API

| TypeScript | Kotlin |
| --- | --- |
| `createSignetContactsClient({ ... })` | `SignetContactsClient(...)` with named arguments |
| promises | `suspend` functions |
| `AbortSignal` on `awaitPairingAck` | cancel the calling coroutine; cancellation propagates rather than returning `null` |
| `now`, `nowMs` | the same, plus `elapsedMs` (the clock deadlines and live-delivery gaps are measured on) and `scope` (where `start()` runs), so tests can drive everything from a virtual-time scheduler. The full constructor is `SignetContactsClient(signer: ContactsSigner, relay: RelayIo, storage: StorageIo = MemoryStorage(), now: () -> Long = { System.currentTimeMillis() / 1000 }, nowMs: () -> Long = System::currentTimeMillis, maxPendingStalenessSeconds: Long = DEFAULT_PENDING_STALENESS_SECONDS, elapsedMs: () -> Long = { System.nanoTime() / 1_000_000 }, scope: CoroutineScope? = null)`. `now` is seconds, `nowMs` and `elapsedMs` are milliseconds. `buildPairingUri` takes its own `nowSec: Long`, which is not read from `now` |
| optional `RelayIo.fetchMany` / `subscribe` | default methods that return `null` for "not supported" |
| capability strings | the `Capability` enum (`Capability.fromWire`, `.wire`); every other string union is an enum with a `wire` property |
| `TypeError` from builders | `IllegalArgumentException` |
| `onRevoked` listeners | the same, except a listener that throws cannot stop the others being called |
| no explicit teardown | `close()`: stops the client and, only if it created its own `CoroutineScope` (the constructor default), cancels that scope too - a scope you inject is yours to cancel |
| `unknown` inputs to parsers | `JsonValue`, from this package's JavaScript-semantics JSON (`Json.parse`) |

## Porting notes

Digests on this wire are taken over `JSON.stringify` output, and invite relay
URLs are normalised with the WHATWG URL parser and then hashed, so this port
carries its own small JSON, `URLSearchParams` and WHATWG URL implementations
rather than the JVM's. `docs/PORTING.md` in the conformance repository lists
every trap. Where this port knowingly differs from the reference:

- A field the reference checks with `Number.isInteger` must here be a safe
  integer (at most 2^53 - 1). Only values above 2^53 are affected.
- UTS #46 is not implemented, so relay-host handling branches on whether the
  percent-decoded host is pure ASCII, matching the reference (Node's URL
  implementation takes an ASCII fast path). A pure-ASCII host is only
  lowercased and its `xn--` labels are never Punycode-validated - an
  already-ASCII malformed `xn--` label (e.g. `xn--999999999`, `xn---abc`,
  `xn--abc-`, `xn--`) is kept verbatim, same as the reference.
  A host containing any non-ASCII code point instead goes through
  `java.net.IDN` (IDNA 2003) with no flags, which agrees with UTS #46
  nontransitional processing for ordinary hosts. A host containing U+00DF
  (ß), U+03C2 (ς), U+200C (ZWNJ) or U+200D (ZWJ) - exactly where IDNA 2003
  and UTS #46 disagree - is rejected outright until UTS #46 is implemented.
  With no flags passed, a code point unassigned in Unicode 3.2 is also
  rejected rather than let through. Android's `java.net.IDN` is ICU-backed,
  so results for other exotic inputs may still rarely differ from a desktop
  JVM's; the deviation-character and unassigned-code-point rejections apply
  identically on both. On this non-ASCII path, an `xn--...` (Punycode) label
  is accepted only once a real RFC 3492 decoder confirms it actually
  decodes - and that check runs over IDN's OWN output too, not only over an
  already-ASCII input, since `java.net.IDN` passes an ASCII `xn--` label
  straight through unchecked even when another label in the same host forces
  the domain onto the non-ASCII path. IPv4 and IPv6 hosts otherwise follow
  the standard exactly. The conformance repository's `invite.json` lists
  four known-divergent invite cases from this deviation-character and
  unassigned-code-point gap (`relay "wss://faß.de/"`,
  `relay "wss://ς.example/"`, `relay "wss://ẞ.example/"` and
  `relay "wss://%C3%9F.example/"`); `ConformanceTest`'s `cases - invite`
  test carries the matching `knownInviteDivergences` list.
- A check record's `method` must be a string; the reference also accepts a
  one-element array that stringifies to a valid method.

## Tests

```bash
git clone https://github.com/forgesworn/signet-contacts-conformance ../signet-contacts-conformance
./gradlew build
# or point at another checkout:
./gradlew build -PsignetContactsVectors=/path/to/signet-contacts-conformance/vectors
```

The suite is a port of every reference test plus every conformance vector. A
missing vectors checkout fails the build rather than skipping. CI runs against
the conformance repository's main branch on every push, nightly, and whenever
the conformance vectors change.

## Licence

MIT.
