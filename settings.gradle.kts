rootProject.name = "signet-contacts-kotlin"

// `core` is the wire and the client, on the JDK's own crypto alone. `nostr` is
// the optional secp256k1 half (event signing, NIP-44 v2, the invite mailbox
// adapter), kept apart so an app that already has a signer and a relay pool
// never pulls a native library in just to read its contacts. The split mirrors
// the TypeScript package, where nostr-tools is an optional peer dependency.
include(":core", ":nostr")
