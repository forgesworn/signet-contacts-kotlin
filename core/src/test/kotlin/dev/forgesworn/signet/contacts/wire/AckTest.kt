package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

private val GRANT = "f".repeat(32)
private val APP = "a".repeat(64)
private val CHALLENGE = "D".repeat(32)

private val ACK = PairingAckV2(
    grantId = GRANT,
    railPubkey = "b".repeat(64),
    projectionTag = projectionTag(GRANT),
    proposalTag = proposalTag(GRANT, APP),
    relay = "wss://relay.example.com",
    grantedCapabilities = listOf(Capability.READ_DIRECTORY),
    maxStalenessSeconds = 21600,
    challenge = CHALLENGE,
)

class AckTest {
    @Test
    fun `round-trips`() {
        assertEquals(ACK, parsePairingAckV2(buildPairingAckV2(ACK), CHALLENGE))
    }

    @Test
    fun `rejects a challenge that does not match byte-for-byte`() {
        assertNull(parsePairingAckV2(buildPairingAckV2(ACK), "E".repeat(32)))
        assertNull(parsePairingAckV2(buildPairingAckV2(ACK), CHALLENGE.lowercase()))
    }

    @Test
    fun `rejects v1, a short rail pubkey, a bad tag and a bad relay`() {
        assertNull(parsePairingAckV2(buildPairingAckV2(ACK).replace("\"v\":2", "\"v\":1"), CHALLENGE))
        assertNull(parsePairingAckV2(buildPairingAckV2(ACK.copy(railPubkey = "short")), CHALLENGE))
        assertNull(parsePairingAckV2(buildPairingAckV2(ACK.copy(projectionTag = "nope")), CHALLENGE))
        assertNull(parsePairingAckV2(buildPairingAckV2(ACK.copy(relay = "http://x.example")), CHALLENGE))
        // C-I7: the same 256-character cap the pairing URI enforces.
        assertNull(parsePairingAckV2(buildPairingAckV2(ACK.copy(relay = "wss://${"a".repeat(300)}.example")), CHALLENGE))
    }

    @Test
    fun `rejects non-JSON and a JSON array`() {
        assertNull(parsePairingAckV2("{", CHALLENGE))
        assertNull(parsePairingAckV2("[]", CHALLENGE))
    }

    @Test
    fun `drops unknown granted capabilities rather than trusting them`() {
        val tampered = buildPairingAckV2(ACK).replace(
            "\"signet.contacts.read:directory\"",
            "\"signet.contacts.read:directory\",\"signet.contacts.read:everything\"",
        )
        assertEquals(listOf(Capability.READ_DIRECTORY), parsePairingAckV2(tampered, CHALLENGE)?.grantedCapabilities)
    }

    @Test
    fun `clamps an out-of-band staleness window`() {
        assertEquals(3600L, parsePairingAckV2(buildPairingAckV2(ACK.copy(maxStalenessSeconds = 1)), CHALLENGE)?.maxStalenessSeconds)
        assertEquals(604800L, parsePairingAckV2(buildPairingAckV2(ACK.copy(maxStalenessSeconds = 99_999_999)), CHALLENGE)?.maxStalenessSeconds)
    }

    @Test
    fun `ackEventTemplate is kind 21237 addressed to the app with no other tag`() {
        val tmpl = ackEventTemplate("c".repeat(64), APP, 1_700_000_000, "ciphertext")
        assertEquals(ACK_KIND, tmpl.kind)
        assertEquals(listOf(listOf("p", APP)), tmpl.tags)
        assertEquals("c".repeat(64), tmpl.pubkey)
    }

    @Test
    fun `storedAckEventTemplate is kind 30078, tagged with the ack tag, the app, and a NIP-40 expiration`() {
        val createdAt = 1_700_000_000L
        val tmpl = storedAckEventTemplate("c".repeat(64), APP, createdAt, "ciphertext", CHALLENGE)
        assertEquals(ACK_STORED_KIND, tmpl.kind)
        assertEquals("c".repeat(64), tmpl.pubkey)
        assertEquals(createdAt, tmpl.createdAt)
        assertEquals("ciphertext", tmpl.content)
        assertEquals(
            listOf(listOf("d", ackTag(CHALLENGE)), listOf("p", APP), listOf("expiration", (createdAt + PAIRING_FRESHNESS_SECONDS).toString())),
            tmpl.tags,
        )
    }

    @Test
    fun `storedAckEventTemplate shares the same content as the ephemeral carrier for the same ack`() {
        val ephemeral = ackEventTemplate("c".repeat(64), APP, 1_700_000_000, "ciphertext")
        val stored = storedAckEventTemplate("c".repeat(64), APP, 1_700_000_000, "ciphertext", CHALLENGE)
        assertEquals(ephemeral.content, stored.content)
        assertEquals(false, stored.kind == ephemeral.kind)
    }

    @Test
    fun `storedAckEventTemplate normalises the challenge case the same way ackTag does`() {
        val upper = storedAckEventTemplate("c".repeat(64), APP, 1_700_000_000, "ciphertext", CHALLENGE)
        val lower = storedAckEventTemplate("c".repeat(64), APP, 1_700_000_000, "ciphertext", CHALLENGE.lowercase())
        assertEquals(upper.tags, lower.tags)
    }

    // "'challenge' in pairing" / "'v' in pairing" do not port: PairingV2 is a
    // fixed data class with no `challenge` or `v` property to probe for, so the
    // absence is structural rather than something a test can observe at runtime.
    @Test
    fun `pairingFromAck drops the version and challenge and stamps pairedAt`() {
        val pairing = pairingFromAck(ACK, 1_700_000_005)
        assertEquals(1_700_000_005L, pairing.pairedAt)
        assertEquals(ACK.railPubkey, pairing.railPubkey)
    }
}
