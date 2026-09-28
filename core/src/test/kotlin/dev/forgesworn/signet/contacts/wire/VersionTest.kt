package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals

class VersionTest {
    @Test
    fun `exports the wire version`() {
        assertEquals(2, WIRE_VERSION)
    }
}
