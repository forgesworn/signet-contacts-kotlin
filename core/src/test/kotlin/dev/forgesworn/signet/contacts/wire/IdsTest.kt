package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

private val GRANT = "f".repeat(32)
private val APP = "a".repeat(64)
private val CHALLENGE = "D".repeat(32)
private val HEX32 = Regex("^[0-9a-f]{32}$")

class IdsTest {
    @Test
    fun `routing tags are 32 lowercase hex and deterministic`() {
        val tag = projectionTag(GRANT)
        assertTrue(HEX32.matches(tag))
        assertEquals(tag, projectionTag(GRANT))
    }

    @Test
    fun `routing tags are domain-separated - a projection tag is never a proposal tag`() {
        assertNotEquals(projectionTag(GRANT), proposalTag(GRANT, APP))
    }

    @Test
    fun `proposal tag binds to one app pubkey`() {
        assertNotEquals(proposalTag(GRANT, APP), proposalTag(GRANT, "b".repeat(64)))
    }

    @Test
    fun `routing tags pin the exact frozen digests`() {
        assertEquals("5d65155161ef7e713af3bf7bc7b213d0", projectionTag(GRANT))
        assertEquals("2713fc461de3b92ac3da773f33926f3d", proposalTag(GRANT, APP))
    }

    @Test
    fun `ackTag is 32 lowercase hex and deterministic`() {
        val tag = ackTag(CHALLENGE)
        assertTrue(HEX32.matches(tag))
        assertEquals(tag, ackTag(CHALLENGE))
    }

    @Test
    fun `ackTag normalises case before hashing, so an upper- and lower-case challenge share one tag`() {
        assertEquals(ackTag(CHALLENGE), ackTag(CHALLENGE.lowercase()))
    }

    @Test
    fun `ackTag is domain-separated - an ack tag is never a projection or proposal tag`() {
        assertNotEquals(projectionTag(GRANT), ackTag(GRANT))
        assertNotEquals(proposalTag(GRANT, APP), ackTag(GRANT))
    }

    @Test
    fun `ackTag pins the exact frozen digest`() {
        assertEquals("630f26ef0b0b835998967c711cb7c390", ackTag(CHALLENGE))
    }

    @Test
    fun `scopedContactId is stable per (grant, contact) and differs across grants`() {
        val a = scopedContactId(GRANT, "contact-1")
        assertTrue(HEX32.matches(a))
        assertEquals(a, scopedContactId(GRANT, "contact-1"))
        assertNotEquals(a, scopedContactId("0".repeat(32), "contact-1"))
    }

    @Test
    fun `scopedContactId does not collide on a separator ambiguity`() {
        assertNotEquals(scopedContactId("ab", "c:d"), scopedContactId("ab:c", "d"))
    }

    // isHex(12 as unknown, 2) is skipped: isHex takes a String?, so a number
    // cannot be passed at all.
    @Test
    fun `isHex accepts lowercase hex of the requested length only`() {
        assertTrue(isHex("ab12", 4))
        assertFalse(isHex("AB12", 4))
        assertFalse(isHex("ab12", 6))
        assertFalse(isHex("zz", 2))
        assertTrue(isHex("abcd"))
    }

    @Test
    fun `randomHex returns 2 chars per byte and differs between calls`() {
        assertEquals(32, randomHex(16).length)
        assertNotEquals(randomHex(16), randomHex(16))
    }

    // sanitizeWireText(7, 10) is skipped: sanitizeWireText takes a String?, so a
    // number cannot be passed at all; the null case below covers the same
    // "not a string becomes empty" guarantee.
    @Test
    fun `sanitizeWireText strips control and bidi characters, trims, then caps`() {
        assertEquals("Sam", sanitizeWireText("  Sam\u202e  ", 100))
        assertEquals("abc", sanitizeWireText("abcdef", 3))
        assertEquals("", sanitizeWireText(null as String?, 10))
    }

    @Test
    fun `sanitizeWireText caps by CODE POINT, never splitting a surrogate pair`() {
        // U+1F702 ALCHEMICAL SYMBOL FOR SULFUR is one code point but two UTF-16
        // code units; maxLen=1 keeps only 'x' and drops the whole emoji.
        assertEquals("x", sanitizeWireText("x\ud83d\udf02", 1))
        // maxLen=2 keeps both 'x' and the whole emoji, never half of it.
        val kept = sanitizeWireText("x\ud83d\udf02", 2)
        assertEquals("x\ud83d\udf02", kept)
        assertEquals(2, kept.codePointCount(0, kept.length))
        // No lone surrogate anywhere in the result.
        val withoutPairs = kept.replace(Regex("[\uD800-\uDBFF][\uDC00-\uDFFF]"), "")
        assertFalse(Regex("[\uD800-\uDFFF]").containsMatchIn(withoutPairs))
    }
}
