package dev.forgesworn.signet.contacts.internal

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/**
 * Review item 6, updated after matching the reference on ASCII "xn--"
 * labels: a pure-ASCII host (after percent-decoding) is only lowercased,
 * matching Node's URL implementation, which takes an ASCII fast path
 * through domain-to-ASCII - so a malformed already-ASCII "xn--" label
 * (`xn--999999999`, `xn---abc`, `xn--abc-`, `xn--`, or any other garbage
 * after the prefix) is kept verbatim, never Punycode-validated.
 *
 * A host containing any non-ASCII character instead goes through
 * `java.net.IDN` (IDNA 2003), which agrees with UTS #46 nontransitional
 * processing for ordinary hosts. A host containing one of the four
 * characters where IDNA 2003 and UTS #46 actually disagree - U+00DF (ß),
 * U+03C2 (ς), U+200C (ZWNJ), U+200D (ZWJ) - is rejected outright rather than
 * risk normalising to something a real UTS #46 implementation would not. On
 * this non-ASCII path, an "xn--" (Punycode) label - whether already-ASCII or
 * produced by `java.net.IDN` - is accepted only once a real RFC 3492 decoder
 * confirms it actually decodes; `java.net.IDN.toUnicode` never throws, so
 * the old "must decode" check was dead code.
 *
 * `invite.json`'s "relay \"wss://xn--nxasmq6b.com\"" (already-valid Punycode)
 * and "relay \"wss://éxample.com/é\"" (an ordinary non-ASCII host) conformance
 * vectors both still pass under this behaviour.
 */
class WhatwgUrlTest {
    @Test
    fun `normalises an ordinary non-ASCII host to Punycode via IDNA 2003`() {
        val url = WhatwgUrl.parse("wss://bücher.example/")
        assertEquals("xn--bcher-kva.example", url?.host)
    }

    @Test
    fun `normalises a mixed-case non-ASCII host to Punycode via IDNA 2003`() {
        val url = WhatwgUrl.parse("wss://Bücher.example/")
        assertEquals("xn--bcher-kva.example", url?.host)
    }

    @Test
    fun `rejects a host containing the sharp s deviation character`() {
        assertNull(WhatwgUrl.parse("wss://straße.example/"))
    }

    @Test
    fun `rejects another host containing the sharp s deviation character`() {
        assertNull(WhatwgUrl.parse("wss://faß.de/"))
    }

    @Test
    fun `rejects a host containing a zero-width joiner deviation character`() {
        assertNull(WhatwgUrl.parse("wss://a‍b.example/"))
    }

    @Test
    fun `accepts an already-Punycode host and keeps it verbatim, never decoded to Unicode`() {
        val url = WhatwgUrl.parse("wss://xn--bcher-kva.example/")
        assertEquals("xn--bcher-kva.example", url?.host)
    }

    @Test
    fun `keeps a malformed already-ASCII xn-- label verbatim - digit sequence never terminates`() {
        // Every character decodes to the punycode digit-value 35 (the
        // maximum), which never satisfies "digit less than threshold", so a
        // real RFC 3492 decoder would never terminate on this label - but
        // this host is pure ASCII, so the reference (and this port) never
        // runs that decoder over it at all; it is lowercased and kept as is.
        val url = WhatwgUrl.parse("wss://xn--999999999.example/")
        assertEquals("xn--999999999.example", url?.host)
    }

    @Test
    fun `keeps a malformed already-ASCII xn-- label verbatim - non-alphanumeric extended code point`() {
        val url = WhatwgUrl.parse("wss://xn--zzz-invalid-!!!.example/")
        assertEquals("xn--zzz-invalid-!!!.example", url?.host)
    }

    @Test
    fun `keeps a bare already-ASCII xn-- label with nothing to decode verbatim`() {
        val url = WhatwgUrl.parse("wss://xn--.example/")
        assertEquals("xn--.example", url?.host)
    }

    // Review item F4: java.net.IDN.toASCII passes an already-ASCII label
    // through unchecked, even when another label in the SAME host forces the
    // whole domain onto the non-ASCII (IDN) path - so the must-actually-decode
    // check has to run over IDN's output too, not only over an all-ASCII input.
    @Test
    fun `rejects an already-ASCII xn-- label that IDN passed through unchecked, alongside a non-ASCII label`() {
        assertNull(WhatwgUrl.parse("wss://xn--999999999.bücher.example/"))
    }

    @Test
    fun `still accepts an ordinary non-ASCII host once the IDN output is xn-- validated`() {
        val url = WhatwgUrl.parse("wss://bücher.example/")
        assertEquals("xn--bcher-kva.example", url?.host)
    }

    // Review item F4: with ALLOW_UNASSIGNED removed, java.net.IDN now fails
    // closed on a code point unassigned in Unicode 3.2 (here, U+1E9E LATIN
    // CAPITAL LETTER SHARP S) instead of silently letting it through.
    @Test
    fun `rejects a host containing a code point unassigned in Unicode 3-2`() {
        assertNull(WhatwgUrl.parse("wss://ẞexample.example/"))
    }

    // Review item F5: RFC 3492 6.2 - a delimiter at index 0 means the basic
    // part is EMPTY and decoding starts at index 0, where the delimiter
    // itself is not a valid digit, so a real decoder would reject this label.
    // It is pure ASCII, though, so - matching the reference - it is never
    // decoded at all, only lowercased and kept verbatim.
    @Test
    fun `keeps a malformed already-ASCII xn-- label verbatim - only delimiter at index 0`() {
        val url = WhatwgUrl.parse("wss://xn---abc.example/")
        assertEquals("xn---abc.example", url?.host)
    }

    // Review item F5: UTS #46 would reject a Punycode label that decodes to
    // purely ASCII output - there was never a reason to Punycode-encode it -
    // but this label is pure ASCII, so, matching the reference, it is never
    // decoded at all, only lowercased and kept verbatim.
    @Test
    fun `keeps a malformed already-ASCII xn-- label verbatim - decodes to purely ASCII output`() {
        val url = WhatwgUrl.parse("wss://xn--abc-.example/")
        assertEquals("xn--abc-.example", url?.host)
    }
}
