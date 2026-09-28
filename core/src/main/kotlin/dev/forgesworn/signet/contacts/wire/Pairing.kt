package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.internal.Digest
import dev.forgesworn.signet.contacts.internal.FormUrl
import dev.forgesworn.signet.contacts.internal.Js

/**
 * Pairing v2: the `signet-grant:` URI a consuming app shows as a QR code.
 * `v=2` is the FIRST parameter and is mandatory; parameter order is binding.
 */

private val HEX64 = Regex("^[0-9a-f]{64}$")

/** Exactly [CHALLENGE_HEX_CHARS] hex characters, case-insensitive on the way
 *  in and preserved verbatim on the way out. */
internal val CHALLENGE_HEX = Regex("^[0-9a-fA-F]{$CHALLENGE_HEX_CHARS}$")

private val WSS = Regex("^wss://", RegexOption.IGNORE_CASE)
// `\z`, not `$`: Java's `$` also matches before a trailing newline, so
// `ws://localhost\n` would pass where the reference refuses it.
private val LOOPBACK_WS = Regex("^ws://(localhost|127\\.0\\.0\\.1)([:/]|\\z)", RegexOption.IGNORE_CASE)

/** Production relays require TLS; plaintext is reserved for loopback
 *  development. Capped at [MAX_RELAY_LEN] (C-I7). */
public fun isValidContactsRelayUrl(value: String?): Boolean {
    if (value == null || value.isEmpty() || value.length > MAX_RELAY_LEN) return false
    return WSS.containsMatchIn(value) || LOOPBACK_WS.containsMatchIn(value)
}

/** Build the pairing URI. Throws [IllegalArgumentException] on invalid input. */
public fun buildPairingUriV2(opts: PairingUriOptionsV2): String {
    require(HEX64.matches(opts.appPubkey)) { "signet-contacts: app pubkey must be lowercase 64-hex" }
    require(isValidContactsRelayUrl(opts.relay)) { "signet-contacts: invalid relay URL" }
    require(opts.nowSec >= 0) { "signet-contacts: invalid timestamp" }
    require(CHALLENGE_HEX.matches(opts.challenge)) { "signet-contacts: invalid challenge" }
    val caps = normaliseCapabilities(opts.capabilities)
    require(caps.isNotEmpty()) { "signet-contacts: at least one capability is required" }

    val query = FormUrl.serialize(
        listOf(
            "v" to PAIRING_VERSION.toString(),
            "app" to opts.appPubkey,
            "name" to opts.appName,
            "caps" to caps.joinToString(",") { it.wire },
            "dir" to opts.directory.wire,
            "relay" to opts.relay,
            "t" to opts.nowSec.toString(),
            "challenge" to opts.challenge,
        ),
    )
    return "$PAIRING_SCHEME//pair?$query"
}

/**
 * Parse a pairing URI. Never throws: a request that cannot be trusted is
 * `request = null` with a warning naming why; recoverable oddities (unknown
 * capability tokens, a bad directory, a truncated name) are warnings on a
 * non-null request.
 */
public fun parsePairingRequestV2(
    input: String,
    nowSec: Long? = null,
    freshnessSeconds: Long = PAIRING_FRESHNESS_SECONDS,
): PairingRequestV2Result {
    val warnings = ArrayList<String>()
    if (input.length > MAX_PAIRING_URI_CHARS) return PairingRequestV2Result(null, listOf("too-long"))
    val qIndex = input.indexOf('?')
    val params = FormUrl.parse(if (qIndex >= 0) input.substring(qIndex + 1) else input)
    fun get(name: String) = FormUrl.get(params, name)

    if (get("v") != PAIRING_VERSION.toString()) return PairingRequestV2Result(null, listOf("bad-version"))

    val appPubkey = (get("app") ?: "").lowercase(java.util.Locale.ROOT)
    if (!HEX64.matches(appPubkey)) return PairingRequestV2Result(null, listOf("bad-app-pubkey"))

    val rendezvousRelay = get("relay") ?: ""
    if (!isValidContactsRelayUrl(rendezvousRelay)) return PairingRequestV2Result(null, listOf("bad-relay"))

    val t = jsNumberInteger(get("t"))
    if (t == null || t < 0) return PairingRequestV2Result(null, listOf("bad-timestamp"))
    val now = nowSec ?: (System.currentTimeMillis() / 1000)
    if (Math.abs(now - t) > freshnessSeconds) return PairingRequestV2Result(null, listOf("stale-timestamp"))

    val challenge = get("challenge") ?: ""
    if (!CHALLENGE_HEX.matches(challenge)) return PairingRequestV2Result(null, listOf("bad-challenge"))

    val splitCaps = (get("caps") ?: "").split(',').map { Js.trim(it) }.filter { it.isNotEmpty() }
    if (splitCaps.size > MAX_CAPABILITIES) warnings.add("caps-truncated")
    val rawCaps = splitCaps.take(MAX_CAPABILITIES)
    val known = rawCaps.mapNotNull(Capability::fromWire)
    if (known.size != rawCaps.size) warnings.add("caps-unknown-token")
    if (known.isEmpty()) {
        warnings.add("caps-empty")
        return PairingRequestV2Result(null, warnings)
    }
    val capabilities = normaliseCapabilities(known)

    val directory = DirectoryKind.fromWire(get("dir") ?: "") ?: DirectoryKind.OWNER.also { warnings.add("bad-directory") }

    val rawName = get("name") ?: ""
    val appName = sanitizeWireText(rawName, MAX_APP_NAME)
    if (appName.isEmpty()) return PairingRequestV2Result(null, warnings + "bad-app-name")
    // Counted by code point, the way sanitizeWireText truncates.
    if (Js.codePointLength(sanitizeWireText(rawName, MAX_APP_NAME + 1)) > MAX_APP_NAME) warnings.add("name-truncated")

    return PairingRequestV2Result(
        PairingRequestV2(appPubkey, appName, capabilities, directory, rendezvousRelay, t, challenge),
        warnings,
    )
}

/**
 * `Number(s)` followed by `Number.isInteger`, for the `t` parameter: accepts
 * what JavaScript's string-to-number conversion accepts (surrounding
 * whitespace, `1e3`, `0x10`, an empty string as 0) and requires the result to
 * be a safe integer. Null for anything else.
 */
internal fun jsNumberInteger(raw: String?): Long? {
    // Number(null) is 0: a missing `t` is a valid integer that then fails the
    // freshness check, so it reports `stale-timestamp`, as the reference does.
    val s = Js.trim(raw ?: "")
    val d: Double = when {
        s.isEmpty() -> 0.0
        Regex("^0[xX][0-9a-fA-F]+$").matches(s) -> java.math.BigInteger(s.substring(2), 16).toDouble()
        Regex("^0[oO][0-7]+$").matches(s) -> java.math.BigInteger(s.substring(2), 8).toDouble()
        Regex("^0[bB][01]+$").matches(s) -> java.math.BigInteger(s.substring(2), 2).toDouble()
        Regex("^[+-]?(Infinity|(\\d+\\.?\\d*|\\.\\d+)([eE][+-]?\\d+)?)$").matches(s) ->
            if (s.endsWith("Infinity")) return null else s.toDouble()
        else -> return null
    }
    if (!d.isFinite() || Math.floor(d) != d || Math.abs(d) > 9007199254740991.0) return null
    return d.toLong()
}

// ---------------------------------------------------------------------------
// Pairing verification code (B1, F1). The app shows the code; Signet asks the
// person to TYPE it and compares. Built from grantId and railPubkey, which
// exist only inside the real ack.
// ---------------------------------------------------------------------------

private const val PAIRING_CODE_MODULUS = 1_000_000L
private const val PAIRING_CODE_DIGITS = 6
private val TYPED_CODE = Regex("^[0-9]{6}$")

public data class PairingCodeInput(
    /** 64 hex. */
    val appPubkey: String,
    /** [CHALLENGE_HEX_CHARS] hex, case-insensitive on the way in. */
    val challenge: String,
    /** 32 hex. */
    val grantId: String,
    /** 64 hex. */
    val railPubkey: String,
)

/** Deterministic 6-digit code, e.g. `"042917"`. Throws on invalid input. */
public fun pairingCode(input: PairingCodeInput): String {
    require(
        isHex(input.appPubkey, 64) && isHex(input.grantId, 32) && isHex(input.railPubkey, 64) &&
            CHALLENGE_HEX.matches(input.challenge),
    ) { "signet-contacts: invalid pairing-code input" }
    val payload = "signet-contacts:pairing-code:v1\n${input.appPubkey.lowercase()}\n" +
        "${input.challenge.lowercase()}\n${input.grantId.lowercase()}\n${input.railPubkey.lowercase()}"
    val digest = Digest.sha256(Js.utf8(payload))
    val n = ((digest[0].toLong() and 0xff) shl 24) or ((digest[1].toLong() and 0xff) shl 16) or
        ((digest[2].toLong() and 0xff) shl 8) or (digest[3].toLong() and 0xff)
    return (n % PAIRING_CODE_MODULUS).toString().padStart(PAIRING_CODE_DIGITS, '0')
}

/** Display grouping only, e.g. `"042 917"`. */
public fun formatPairingCode(code: String): String = "${code.take(3)} ${code.drop(3)}"

/**
 * The producer's half of the check. Throws exactly as [pairingCode] does on a
 * bad [input]; NEVER throws on a bad [typed]: ASCII spaces and hyphens are
 * stripped, and anything left that is not exactly 6 digits never matches.
 */
public fun matchesPairingCode(input: PairingCodeInput, typed: String?): Boolean {
    val expected = pairingCode(input)
    if (typed == null) return false
    val stripped = typed.replace(" ", "").replace("-", "")
    return TYPED_CODE.matches(stripped) && stripped == expected
}
