package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val NOW = 1_700_000_000L
private val BASE = PairingUriOptionsV2(
    appPubkey = "a".repeat(64),
    appName = "Flock",
    capabilities = listOf(Capability.READ_DIRECTORY, Capability.BLOCKS_READ),
    directory = DirectoryKind.OWNER,
    relay = "wss://relay.example.com",
    nowSec = NOW,
    challenge = "D".repeat(32),
)

/** `application/x-www-form-urlencoded` value encoding, matching the internal
 *  `FormUrl.encode` used by the library, so a test can build the same
 *  percent-encoded substrings the parser under test would see. */
private fun formEncode(s: String): String {
    val sb = StringBuilder()
    for (b in s.toByteArray(Charsets.UTF_8)) {
        val c = b.toInt() and 0xff
        when {
            c == 0x20 -> sb.append('+')
            c in 0x30..0x39 || c in 0x41..0x5a || c in 0x61..0x7a || c == 0x2a || c == 0x2d || c == 0x2e || c == 0x5f -> sb.append(c.toChar())
            else -> sb.append('%').append("0123456789ABCDEF"[c ushr 4]).append("0123456789ABCDEF"[c and 0xf])
        }
    }
    return sb.toString()
}

class PairingTest {
    @Test
    fun `buildPairingUriV2 emits v=2 first and the binding parameter order`() {
        val uri = buildPairingUriV2(BASE)
        assertTrue(uri.startsWith("signet-grant://pair?v=2&app="))
        assertTrue(uri.contains("&caps=signet.contacts.read%3Adirectory%2Csignet.contacts.blocks.read"))
        assertTrue(uri.contains("&dir=owner"))
        assertTrue(uri.indexOf("&relay=") < uri.indexOf("&t="))
        assertTrue(uri.indexOf("&t=") < uri.indexOf("&challenge="))
    }

    @Test
    fun `buildPairingUriV2 refuses a bad pubkey, relay, timestamp or challenge`() {
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(appPubkey = "nope")) }
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(relay = "http://relay.example.com")) }
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(nowSec = -1)) }
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(challenge = "short")) }
    }

    @Test
    fun `buildPairingUriV2 refuses an empty capability list`() {
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(capabilities = emptyList())) }
    }

    // The builder fully controls its own output: an upper-case pubkey is
    // refused rather than silently lowercased, asymmetric with the parser.
    @Test
    fun `rejects a non-lowercase app pubkey - asymmetric with the parser, intentionally`() {
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(appPubkey = BASE.appPubkey.uppercase())) }
    }

    @Test
    fun `does not report truncation for a name that exactly fills the cap in code points`() {
        val astralName = "\ud83d\udf02".repeat(MAX_APP_NAME)
        assertEquals(MAX_APP_NAME, astralName.codePointCount(0, astralName.length))
        assertEquals(MAX_APP_NAME * 2, astralName.length)
        val result = parsePairingRequestV2(buildPairingUriV2(BASE.copy(appName = astralName)), NOW)
        assertFalse(result.warnings.contains("name-truncated"))
        val appName = result.request?.appName ?: ""
        assertEquals(MAX_APP_NAME, appName.codePointCount(0, appName.length))
    }

    @Test
    fun `still reports truncation when a code point really was dropped`() {
        val astralName = "\ud83d\udf02".repeat(MAX_APP_NAME)
        val overLong = astralName + "\ud83d\udf03"
        val result = parsePairingRequestV2(buildPairingUriV2(BASE.copy(appName = overLong)), NOW)
        assertTrue(result.warnings.contains("name-truncated"))
        val appName = result.request?.appName ?: ""
        assertEquals(MAX_APP_NAME, appName.codePointCount(0, appName.length))
        val withoutPairs = appName.replace(Regex("[\uD800-\uDBFF][\uDC00-\uDFFF]"), "")
        assertFalse(Regex("[\uD800-\uDFFF]").containsMatchIn(withoutPairs))
    }

    @Test
    fun `refuses a relay URL longer than MAX_RELAY_LEN, on the way out and the way in`() {
        val longRelay = "wss://${"a".repeat(MAX_RELAY_LEN)}.example"
        assertTrue(longRelay.length > MAX_RELAY_LEN)
        assertFalse(isValidContactsRelayUrl(longRelay))
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(relay = longRelay)) }
        val uri = buildPairingUriV2(BASE).replace(formEncode(BASE.relay), formEncode(longRelay))
        assertTrue(parsePairingRequestV2(uri, NOW).warnings.contains("bad-relay"))
        assertNull(parsePairingRequestV2(uri, NOW).request)
    }

    @Test
    fun `accepts a relay exactly at the cap`() {
        val prefix = "wss://"
        val exact = prefix + "a".repeat(MAX_RELAY_LEN - prefix.length)
        assertEquals(MAX_RELAY_LEN, exact.length)
        assertTrue(isValidContactsRelayUrl(exact))
    }

    @Test
    fun `requires a challenge of exactly CHALLENGE_HEX_CHARS hex characters`() {
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(challenge = "a".repeat(16))) }
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(challenge = "a".repeat(64))) }
        assertFailsWith<IllegalArgumentException> { buildPairingUriV2(BASE.copy(challenge = "z".repeat(CHALLENGE_HEX_CHARS))) }
        buildPairingUriV2(BASE.copy(challenge = "A".repeat(CHALLENGE_HEX_CHARS))) // does not throw
        val short = buildPairingUriV2(BASE).replace(BASE.challenge, "a".repeat(16))
        assertEquals(PairingRequestV2Result(null, listOf("bad-challenge")), parsePairingRequestV2(short, NOW))
        val long = buildPairingUriV2(BASE).replace(BASE.challenge, "a".repeat(64))
        assertEquals(PairingRequestV2Result(null, listOf("bad-challenge")), parsePairingRequestV2(long, NOW))
    }

    @Test
    fun `refuses an input longer than MAX_PAIRING_URI_CHARS without parsing it`() {
        val padded = "${buildPairingUriV2(BASE)}&pad=${"x".repeat(MAX_PAIRING_URI_CHARS)}"
        assertEquals(PairingRequestV2Result(null, listOf("too-long")), parsePairingRequestV2(padded, NOW))
    }

    @Test
    fun `parsePairingRequestV2 round-trips a built URI`() {
        val result = parsePairingRequestV2(buildPairingUriV2(BASE), NOW)
        assertEquals(emptyList(), result.warnings)
        assertEquals(
            PairingRequestV2(
                BASE.appPubkey, "Flock", listOf(Capability.READ_DIRECTORY, Capability.BLOCKS_READ),
                DirectoryKind.OWNER, BASE.relay, NOW, BASE.challenge,
            ),
            result.request,
        )
    }

    @Test
    fun `parses a bare query and an https carrier URL identically`() {
        val uri = buildPairingUriV2(BASE)
        val query = uri.substring(uri.indexOf('?') + 1)
        val carrier = "https://mysignet.app/pair?$query"
        assertEquals(parsePairingRequestV2(carrier, NOW).request, parsePairingRequestV2(query, NOW).request)
    }

    @Test
    fun `rejects a v1 request rather than reading it as v2`() {
        val v1 = "signet-grant://pair?app=" + "a".repeat(64) +
            "&name=Fledgling&scope=kin&relay=wss%3A%2F%2Frelay.example.com&t=" + NOW +
            "&challenge=" + "D".repeat(32)
        val result = parsePairingRequestV2(v1, NOW)
        assertNull(result.request)
        assertEquals(listOf("bad-version"), result.warnings)
    }

    @Test
    fun `drops unknown capability tokens and warns`() {
        val uri = buildPairingUriV2(BASE).replace("&caps=", "&caps=signet.contacts.read%3Aeverything%2C")
        val result = parsePairingRequestV2(uri, NOW)
        assertTrue(result.warnings.contains("caps-unknown-token"))
        assertEquals(listOf(Capability.READ_DIRECTORY, Capability.BLOCKS_READ), result.request?.capabilities)
    }

    @Test
    fun `refuses a request with no recognised capability`() {
        val uri = buildPairingUriV2(BASE).replace(
            "&caps=signet.contacts.read%3Adirectory%2Csignet.contacts.blocks.read",
            "&caps=nonsense",
        )
        val result = parsePairingRequestV2(uri, NOW)
        assertNull(result.request)
        assertTrue(result.warnings.contains("caps-empty"))
    }

    @Test
    fun `rejects a stale timestamp on either side of now`() {
        val uri = buildPairingUriV2(BASE)
        assertEquals(listOf("stale-timestamp"), parsePairingRequestV2(uri, NOW + 301).warnings)
        assertEquals(listOf("stale-timestamp"), parsePairingRequestV2(uri, NOW - 301).warnings)
    }

    @Test
    fun `sanitises and caps the app name, and warns when it truncated`() {
        val uri = buildPairingUriV2(BASE.copy(appName = "F".repeat(120) + "\u202e"))
        val result = parsePairingRequestV2(uri, NOW)
        assertEquals(64, result.request?.appName?.length)
        assertFalse(result.request?.appName?.contains("\u202e") == true)
        assertTrue(result.warnings.contains("name-truncated"))
    }

    @Test
    fun `defaults an absent or unknown dir to owner and warns`() {
        val uri = buildPairingUriV2(BASE).replace("&dir=owner", "&dir=cousin")
        val result = parsePairingRequestV2(uri, NOW)
        assertEquals(DirectoryKind.OWNER, result.request?.directory)
        assertTrue(result.warnings.contains("bad-directory"))
    }

    @Test
    fun `rejects a malformed input outright`() {
        assertNull(parsePairingRequestV2("", NOW).request)
        assertNull(parsePairingRequestV2("not a uri at all", NOW).request)
    }

    @Test
    fun `lowercases an upper-case app pubkey - asymmetric with the builder, intentionally`() {
        val uri = buildPairingUriV2(BASE).replace(BASE.appPubkey, BASE.appPubkey.uppercase())
        val result = parsePairingRequestV2(uri, NOW)
        assertEquals(BASE.appPubkey, result.request?.appPubkey)
        assertEquals(emptyList(), result.warnings)
    }

    @Test
    fun `warns and truncates when the capability list exceeds MAX_CAPABILITIES`() {
        val cycled = (0 until 16).map { CAPABILITIES[it % CAPABILITIES.size] }
        val rawCaps = (cycled.map { it.wire } + listOf("signet.contacts.read:everything")).joinToString(",")
        val uri = buildPairingUriV2(BASE).replace(
            "&caps=signet.contacts.read%3Adirectory%2Csignet.contacts.blocks.read",
            "&caps=${formEncode(rawCaps)}",
        )
        val result = parsePairingRequestV2(uri, NOW)
        assertTrue(result.warnings.contains("caps-truncated"))
        assertFalse(result.warnings.contains("caps-unknown-token"))
        assertEquals(CAPABILITIES, result.request?.capabilities)
    }

    @Test
    fun `isValidContactsRelayUrl requires wss, allowing ws only on loopback`() {
        assertTrue(isValidContactsRelayUrl("wss://relay.example.com"))
        assertTrue(isValidContactsRelayUrl("ws://localhost:7777"))
        assertTrue(isValidContactsRelayUrl("ws://127.0.0.1"))
        assertFalse(isValidContactsRelayUrl("ws://evil.example.com"))
        assertFalse(isValidContactsRelayUrl("https://relay.example.com"))
    }

    @Test
    fun `drops legacy broad method access instead of converting it into new grants`() {
        val uri = buildPairingUriV2(BASE.copy(capabilities = listOf(Capability.READ_DIRECTORY, Capability.READ_METHOD_EMAIL)))
        val old = uri.replace("read%3Amethod%3Aemail", "read%3Amethods")
        assertEquals(listOf(Capability.READ_DIRECTORY), parsePairingRequestV2(old, NOW).request?.capabilities)
        assertEquals(listOf(Capability.READ_DIRECTORY, Capability.READ_METHOD_EMAIL), parsePairingRequestV2(uri, NOW).request?.capabilities)
    }
}
