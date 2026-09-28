package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private val APP = "a".repeat(64)
private val RAIL = "b".repeat(64)
private val GRANT = "f".repeat(32)
private val CHALLENGE = "d".repeat(32)

class PairingCodeTest {
    @Test
    fun `is deterministic - the same four inputs always produce the same code`() {
        val code = pairingCode(PairingCodeInput(APP, CHALLENGE, GRANT, RAIL))
        assertTrue(Regex("^[0-9]{6}$").matches(code))
        assertEquals(code, pairingCode(PairingCodeInput(APP, CHALLENGE, GRANT, RAIL)))
    }

    @Test
    fun `does not depend on the challenge's case - it is echoed verbatim but hashed lowercase`() {
        val lower = pairingCode(PairingCodeInput(APP, CHALLENGE, GRANT, RAIL))
        val upper = pairingCode(PairingCodeInput(APP, CHALLENGE.uppercase(), GRANT, RAIL))
        assertEquals(lower, upper)
    }

    @Test
    fun `differs when grantId or railPubkey differs, even with appPubkey-challenge unchanged`() {
        val a = pairingCode(PairingCodeInput(APP, CHALLENGE, GRANT, RAIL))
        assertNotEquals(a, pairingCode(PairingCodeInput(APP, CHALLENGE, "0".repeat(32), RAIL)))
        assertNotEquals(a, pairingCode(PairingCodeInput(APP, CHALLENGE, GRANT, "0".repeat(64))))
    }

    // A code built only from what the photographed QR carries (appPubkey,
    // challenge) would be useless; grantId and railPubkey exist only inside the
    // real ack.
    @Test
    fun `is unaffected by appPubkey-challenge alone once grantId and railPubkey are fixed`() {
        val a = pairingCode(PairingCodeInput(APP, CHALLENGE, GRANT, RAIL))
        val b = pairingCode(PairingCodeInput("c".repeat(64), "1".repeat(32), GRANT, RAIL))
        assertNotEquals(a, b)
    }

    @Test
    fun `rejects a malformed appPubkey`() {
        assertFailsWith<IllegalArgumentException> { pairingCode(PairingCodeInput("AB", CHALLENGE, GRANT, RAIL)) }
        assertFailsWith<IllegalArgumentException> { pairingCode(PairingCodeInput(APP.uppercase(), CHALLENGE, GRANT, RAIL)) }
    }

    @Test
    fun `rejects a malformed grantId`() {
        assertFailsWith<IllegalArgumentException> { pairingCode(PairingCodeInput(APP, CHALLENGE, "short", RAIL)) }
    }

    @Test
    fun `rejects a malformed railPubkey`() {
        assertFailsWith<IllegalArgumentException> { pairingCode(PairingCodeInput(APP, CHALLENGE, GRANT, "short")) }
    }

    @Test
    fun `rejects a challenge of the wrong length or shape`() {
        assertFailsWith<IllegalArgumentException> { pairingCode(PairingCodeInput(APP, CHALLENGE.substring(1), GRANT, RAIL)) }
        assertFailsWith<IllegalArgumentException> { pairingCode(PairingCodeInput(APP, "z".repeat(32), GRANT, RAIL)) }
    }

    // "rejects a non-string challenge" (undefined as unknown as string) is
    // skipped: PairingCodeInput.challenge is a non-nullable String, so there is
    // no value that can be passed for it other than a real String.

    @Test
    fun `throws the exact message a caller can match on`() {
        val e = assertFailsWith<IllegalArgumentException> { pairingCode(PairingCodeInput("short", CHALLENGE, GRANT, RAIL)) }
        assertEquals("signet-contacts: invalid pairing-code input", e.message)
    }

    @Test
    fun `formatPairingCode groups the six digits as 'NNN NNN'`() {
        assertEquals("042 917", formatPairingCode("042917"))
        assertEquals("000 000", formatPairingCode("000000"))
    }
}

class MatchesPairingCodeTest {
    private val input = PairingCodeInput(APP, CHALLENGE, GRANT, RAIL)
    private val code = pairingCode(input)
    private val grouped = formatPairingCode(code)

    @Test
    fun `matches the bare code typed back exactly`() {
        assertTrue(matchesPairingCode(input, code))
    }

    @Test
    fun `matches with spaces stripped`() {
        assertTrue(matchesPairingCode(input, grouped))
    }

    @Test
    fun `matches with a hyphen in place of the grouping space`() {
        assertTrue(matchesPairingCode(input, "${code.substring(0, 3)}-${code.substring(3)}"))
    }

    @Test
    fun `rejects one digit short`() {
        assertFalse(matchesPairingCode(input, code.substring(0, 5)))
    }

    @Test
    fun `rejects one digit long`() {
        assertFalse(matchesPairingCode(input, "${code}9"))
    }

    @Test
    fun `rejects non-digit characters left after stripping spaces-hyphens`() {
        assertFalse(matchesPairingCode(input, code.dropLast(1) + "a"))
    }

    @Test
    fun `rejects a well-formed but wrong code`() {
        val wrong = if (code == "000000") "000001" else "000000"
        assertFalse(matchesPairingCode(input, wrong))
    }

    // "never throws on a bad typed value" - only the null case ports:
    // `undefined as unknown as string` has no Kotlin counterpart distinct from
    // null, since `typed` is a single nullable String parameter.
    @Test
    fun `never throws on a bad typed value - returns false instead`() {
        assertFalse(matchesPairingCode(input, ""))
        assertFalse(matchesPairingCode(input, null))
    }

    @Test
    fun `still throws on an invalid input, same as pairingCode`() {
        assertFailsWith<IllegalArgumentException> { matchesPairingCode(input.copy(appPubkey = "short"), code) }
    }
}
