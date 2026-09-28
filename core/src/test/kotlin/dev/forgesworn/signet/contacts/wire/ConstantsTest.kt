package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ConstantsTest {
    // R-28(d): the description of a capability must say what the producer DOES,
    // not what a reviewer might wish it did.
    @Test
    fun `describes add-ken as adding contacts, never as asking`() {
        val addKen = CAPABILITY_DESCRIPTIONS[Capability.PROPOSE_ADD_KEN]!!
        assertTrue(addKen.contains("Add contacts to your Ken list (recognised only, no access)"))
        assertFalse(Regex("ask", RegexOption.IGNORE_CASE).containsMatchIn(addKen))
        assertFalse(Regex("may accept|approve|propose", RegexOption.IGNORE_CASE).containsMatchIn(addKen))
    }

    @Test
    fun `describes the minimal default and does not promise private links`() {
        assertTrue(Regex("names.*pubkeys only", RegexOption.IGNORE_CASE).containsMatchIn(CAPABILITY_DESCRIPTIONS[Capability.READ_DIRECTORY]!!))
        assertFalse(Regex("linked", RegexOption.IGNORE_CASE).containsMatchIn(CAPABILITY_DESCRIPTIONS[Capability.BLOCKS_READ]!!))
    }

    @Test
    fun `lists field-level capabilities in their consent order`() {
        assertEquals(
            listOf(
                Capability.READ_DIRECTORY,
                Capability.READ_METHOD_PHONE,
                Capability.READ_METHOD_EMAIL,
                Capability.READ_METHOD_WEBSITE,
                Capability.READ_METHOD_POSTAL_ADDRESS,
                Capability.READ_METHOD_OTHER,
                Capability.READ_TIER,
                Capability.READ_CHECKS,
                Capability.READ_CHECK_RECORDS,
                Capability.READ_ROLES,
                Capability.BLOCKS_READ,
                Capability.PROPOSE_ADD_KEN,
                Capability.PROPOSE_RENAME_APP_LABEL,
                Capability.INVITES_CREATE,
                Capability.INVITES_RECEIVE,
            ),
            CAPABILITIES,
        )
    }

    // "does not ship a capability nothing can grant" (R-12: read:avatar) does not
    // port: Capability has no READ_AVATAR entry to construct, so there is no way
    // to ask the enum for one. isCapability("...read:avatar") == false below
    // covers the string-token half of the same guarantee.
    @Test
    fun `does not recognise a capability nothing can grant`() {
        assertFalse(isCapability("signet.contacts.read:avatar"))
    }

    @Test
    fun `describes every capability for consumer documentation`() {
        for (cap in CAPABILITIES) assertTrue(CAPABILITY_DESCRIPTIONS[cap]!!.length > 10)
    }

    // isCapability(42) is skipped: isCapability takes a String in Kotlin, so a
    // number cannot be passed at all.
    @Test
    fun `recognises only known capability tokens`() {
        assertTrue(isCapability("signet.contacts.read:directory"))
        assertFalse(isCapability("signet.contacts.read:everything"))
        assertFalse(isCapability("signet.contacts.read:methods"))
    }

    @Test
    fun `reuses the v1 pairing scheme and ack kind, at version 2`() {
        assertEquals("signet-grant:", PAIRING_SCHEME)
        assertEquals(2, PAIRING_VERSION)
        assertEquals(21237, ACK_KIND)
        assertEquals(30078, PROJECTION_KIND)
        assertEquals(30078, PROPOSAL_KIND)
    }

    @Test
    fun `caps a payload at the vault envelope's top padding bucket`() {
        assertEquals(65532, MAX_WIRE_BYTES)
        assertEquals(50, MAX_PROPOSALS_PER_BATCH)
    }

    @Test
    fun `clampStaleness defaults, floors and ceilings`() {
        assertEquals(DEFAULT_STALENESS_SECONDS, clampStaleness(null as Long?))
        assertEquals(MIN_STALENESS_SECONDS, clampStaleness(10L))
        assertEquals(MAX_STALENESS_SECONDS, clampStaleness(99_999_999L))
        assertEquals(21600L, clampStaleness(21600L))
        assertEquals(DEFAULT_STALENESS_SECONDS, clampStaleness(Double.NaN))
    }
}
