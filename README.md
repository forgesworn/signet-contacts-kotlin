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
second artefact. If you do use it, add the native half for your platform:
`fr.acinq.secp256k1:secp256k1-kmp-jni-android` on Android,
`secp256k1-kmp-jni-jvm` on a desktop JVM.

## Install

There is no published release yet. Use a Gradle composite build against a
checkout pinned to a commit:

```kotlin
// settings.gradle.kts
includeBuild("../signet-contacts-kotlin")

// build.gradle.kts
dependencies {
    implementation("dev.forgesworn:signet-contacts:0.1.0")
    implementation("dev.forgesworn:signet-contacts-nostr:0.1.0") // optional
}
```

## Quick start

```kotlin
val signer: ContactsSigner = yourSigner      // your app's OWN signer: NIP-46, a hardware signer, or a local key
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
val challenge = randomHex(16)
val uri = client.buildPairingUri(
    appName = "My App", capabilities = capabilities, directory = DirectoryKind.OWNER,
    relay = "wss://relay.example.com", nowSec = System.currentTimeMillis() / 1000, challenge = challenge,
)
showQrCode(uri) // the owner scans it in Signet

// Narrowing only: an ack granting anything you did not ask for is refused.
val pairing = client.awaitPairingAck(challenge, listOf("wss://relay.example.com"), requestedCapabilities = capabilities)
if (pairing != null) {
    savePairing(pairing.toJson().stringify())      // your own persistence; PairingV2.fromJson reads it back
    client.load(pairing.grantId)                    // rehydrate state, Blocked set included
    val projection = client.fetchProjection(pairing)
    val blocked = client.getBlockedSet()            // apply at ingress AND at display
    val waiting = client.pendingProposals()         // proposals sent, not yet applied
    val stop = client.start(pairing)                // live updates + poll fallback
}
```

On every later launch, reload the pairing yourself and call
`client.load(pairing.grantId)` **before** `client.fetchProjection(pairing)`.

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
| `now`, `nowMs` | the same, plus `elapsedMs` (the clock deadlines and live-delivery gaps are measured on) and `scope` (where `start()` runs), so tests can drive everything from a virtual-time scheduler |
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
- UTS #46 is not implemented: a non-ASCII relay host (after percent-decoding)
  goes through `java.net.IDN` (IDNA 2003) with no flags, which agrees with
  UTS #46 nontransitional processing for ordinary hosts. A host containing
  U+00DF (ß), U+03C2 (ς), U+200C (ZWNJ) or U+200D (ZWJ) - exactly where IDNA
  2003 and UTS #46 disagree - is rejected outright until UTS #46 is
  implemented. With no flags passed, a code point unassigned in Unicode 3.2
  is also rejected rather than let through. Android's `java.net.IDN` is
  ICU-backed, so results for other exotic inputs may still rarely differ from
  a desktop JVM's; the deviation-character and unassigned-code-point
  rejections apply identically on both. An `xn--...` (Punycode) label is
  accepted only once a real RFC 3492 decoder confirms it actually decodes -
  and that check runs over IDN's OWN output too, not only over an
  already-ASCII input, since `java.net.IDN` passes an ASCII `xn--` label
  straight through unchecked even when another label in the same host forces
  the domain onto the non-ASCII path. ASCII, IPv4 and IPv6 hosts otherwise
  follow the standard exactly.
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
