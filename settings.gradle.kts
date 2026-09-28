rootProject.name = "signet-contacts-kotlin"

// `core` is the wire and the client, on the JDK's own crypto alone. `nostr` is
// the optional secp256k1 half (event signing, NIP-44 v2, the invite mailbox
// adapter), kept apart so an app that already has a signer and a relay pool
// never pulls a native library in just to read its contacts. The split mirrors
// the TypeScript package, where nostr-tools is an optional peer dependency.
// Each project is NAMED for the artefact it publishes, while its directory
// stays short. A composite build (`includeBuild`) substitutes dependencies by
// group and project name, so `dev.forgesworn:signet-contacts` resolves to
// this checkout only if the project carries that name.
include(":signet-contacts", ":signet-contacts-nostr")
project(":signet-contacts").projectDir = file("core")
project(":signet-contacts-nostr").projectDir = file("nostr")
