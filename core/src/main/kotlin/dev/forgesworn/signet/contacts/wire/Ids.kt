package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.internal.Digest
import dev.forgesworn.signet.contacts.internal.Hex
import dev.forgesworn.signet.contacts.internal.Js
import dev.forgesworn.signet.contacts.internal.Random
import dev.forgesworn.signet.contacts.json.JsonString
import dev.forgesworn.signet.contacts.json.JsonValue

/**
 * Identifiers and routing tags. Every tag is a domain-separated SHA-256
 * truncated to 128 bits (32 hex), opaque on the relay by design.
 */

private const val PROJECTION_PREFIX = "signet:contacts:proj:"
private const val PROPOSAL_PREFIX = "signet:contacts:prop:"
private const val SCOPED_PREFIX = "signet:contacts:cid:"
private const val ACK_PREFIX = "signet:contacts:ack:"
private const val TAG_HEX_CHARS = 32

/**
 * R-6: byte-identical to signet-app's `sanitizeDisplayName` class. U+0000-001F
 * C0 controls; U+007F-009F DEL + C1; U+200B-200F zero-width + LRM/RLM;
 * U+2028-202E separators + bidi embedding/override; U+2066-2069 bidi isolates.
 */
private val CONTROL_BIDI = Regex("[\\x00-\\x1f\\x7f-\\x9f\\u200b-\\u200f\\u2028-\\u202e\\u2066-\\u2069]")
private val LOWER_HEX = Regex("^[0-9a-f]+$")

private fun digestTag(input: String): String = Digest.sha256Hex(input).substring(0, TAG_HEX_CHARS)

/** Replaceable `d` tag of a grant's projection event. */
public fun projectionTag(grantId: String): String = digestTag("$PROJECTION_PREFIX$grantId")

/** Replaceable `d` tag of one app's proposal event for a grant, bound to the app pubkey. */
public fun proposalTag(grantId: String, appPubkey: String): String = digestTag("$PROPOSAL_PREFIX$grantId:$appPubkey")

/** Replaceable `d` tag of the STORED pairing ack, keyed on the lowercased challenge. */
public fun ackTag(challenge: String): String = digestTag("$ACK_PREFIX${challenge.lowercase(java.util.Locale.ROOT)}")

/**
 * Grant-scoped opaque contact id. Both inputs' lengths (UTF-16 units, as
 * JavaScript counts them) are mixed in so the encoding is unambiguous.
 */
public fun scopedContactId(grantId: String, contactId: String): String =
    digestTag("$SCOPED_PREFIX${grantId.length}:$grantId:${contactId.length}:$contactId")

/** Lowercase-hex guard. With [length], the string must be exactly that long. */
public fun isHex(value: String?, length: Int? = null): Boolean {
    if (value == null) return false
    if (length != null && value.length != length) return false
    if (value.isEmpty() || value.length % 2 != 0) return false
    return LOWER_HEX.matches(value)
}

/** [isHex] over a raw JSON value: a non-string is never hex. */
public fun isHex(value: JsonValue?, length: Int? = null): Boolean = isHex((value as? JsonString)?.value, length)

/** Cryptographically random lowercase hex. */
public fun randomHex(bytes: Int): String = Hex.encode(Random.bytes(bytes))

/**
 * Strip control + bidi/invisible characters, trim (JavaScript's whitespace
 * set), then cap at [maxLen] CODE POINTS. R-6: the only sanitiser on this wire.
 */
public fun sanitizeWireText(raw: String?, maxLen: Int): String {
    if (raw == null) return ""
    val stripped = Js.trim(CONTROL_BIDI.replace(raw, ""))
    return Js.codePointPrefix(stripped, maxLen)
}

/** [sanitizeWireText] over a raw JSON value: a non-string becomes the empty string. */
public fun sanitizeWireText(raw: JsonValue?, maxLen: Int): String = sanitizeWireText((raw as? JsonString)?.value, maxLen)
