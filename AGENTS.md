# AGENTS.md

Kotlin port of the signet-contacts v2 wire and consumer client. Two Gradle
projects: `core` (artefact `dev.forgesworn:signet-contacts`) and `nostr`
(artefact `dev.forgesworn:signet-contacts-nostr`). The TypeScript package is the
reference; this port must match it on every conformance vector.

## Build and test

```bash
git clone https://github.com/forgesworn/signet-contacts-conformance ../signet-contacts-conformance
./gradlew build
# or point at another vectors directory:
./gradlew build -PsignetContactsVectors=/path/to/signet-contacts-conformance/vectors
```

- The build needs the `../signet-contacts-conformance` checkout (the vectors are
  read from `../signet-contacts-conformance/vectors` by default, set in
  `gradle.properties`). A missing vectors checkout fails the build; it never skips.
- JDK: CI builds and tests on Temurin 21, because the `nostr` tests use
  `secp256k1-kmp-jni-jvm`, which publishes for JVM 21. The artefacts themselves
  emit JVM 17 bytecode, and the language and API level is pinned to Kotlin 2.0,
  so consumers need JVM 17 and Kotlin 2.0 or later.
- Both modules use `explicitApi()`: every public declaration needs an explicit
  `public` modifier.
- Keep `core` free of any Nostr or secp256k1 dependency. Anything that needs
  secp256k1 belongs in `nostr`.

## Invariants (do not break)

- Call `client.load(grantId)` BEFORE `client.fetchProjection(pairing)` on every
  launch, so the sticky Blocked set is rehydrated first.
- Never un-block anyone on expiry or revocation. Only a newer, accepted,
  non-revoked projection may shrink the Blocked set. Freshness is a display hint,
  never a permission check.
- `PoolRelayIo` takes a required `verify`. Do not give it a default.
- Hostile or malformed relay data never throws out of a public client method: it
  reads as `null` or `false`. Cancellation still propagates.
- `stop()` cancels the subscription, the poll and in-flight ingests, and is not a
  barrier: an ingest that has passed its last cancellation check completes its
  commit. `close()` calls `stop()`, cancels the scope only if the client created
  it, and is terminal: `start()` afterwards throws `IllegalStateException`.
- Digests are taken over `JSON.stringify` output, so use this package's own
  `Json`, `URLSearchParams` and WHATWG URL code, not the JVM's.

## Known divergences from the reference

Recorded, not hidden. Four relay-host invite cases that need UTS #46 are listed
in `knownInviteDivergences` in
`core/src/test/kotlin/dev/forgesworn/signet/contacts/ConformanceTest.kt`. The
test fails if one of them stops diverging, so remove a case from that set when
the port starts agreeing with the reference. Other deliberate differences are
under "Porting notes" in `README.md`.

## Docs

`README.md` is the user-facing reference and `llms.txt` is its index. When a
public signature, default or error string changes, update both.
