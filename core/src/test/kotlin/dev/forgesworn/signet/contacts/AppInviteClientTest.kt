package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonString
import dev.forgesworn.signet.contacts.wire.AppInviteMode
import dev.forgesworn.signet.contacts.wire.AppInviteStatus
import dev.forgesworn.signet.contacts.wire.Capability
import dev.forgesworn.signet.contacts.wire.ContactInvite
import dev.forgesworn.signet.contacts.wire.NostrFilter
import dev.forgesworn.signet.contacts.wire.PairingV2
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.appInviteTag
import dev.forgesworn.signet.contacts.wire.projectionTag
import dev.forgesworn.signet.contacts.wire.proposalTag
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Ported from app-invite-client.test.ts. */
class AppInviteClientTest {
    private val pairing = PairingV2(
        grantId = "a".repeat(32), railPubkey = "b".repeat(64),
        projectionTag = projectionTag("a".repeat(32)), proposalTag = proposalTag("a".repeat(32), "e".repeat(64)),
        relay = "wss://app.example",
        grantedCapabilities = listOf(Capability.INVITES_CREATE, Capability.INVITES_RECEIVE),
        maxStalenessSeconds = 3600, pairedAt = 100,
    )
    private val invite = ContactInvite(recipient = "c".repeat(64), secret = "d".repeat(64), relays = listOf("wss://contact.example/"))

    private data class Fixture(val signer: FakeSigner, val relay: FakeRelay, val client: AppInviteClient)

    private fun fixture(): Fixture {
        // Identity NIP-44, mirroring the TS fixture's `async (_key, text) => text`:
        // the point of this test is the app-invite framing, not the envelope.
        val signer = FakeSigner(pubkey = "e".repeat(64))
        signer.encryptImpl = { _, text -> text }
        signer.decryptImpl = { _, text -> text }
        var posted: SignedNostrEvent? = null
        val relay = FakeRelay()
        relay.publishImpl = { event, _ -> posted = event; true }
        relay.fetchNewestImpl = { _, _, _ ->
            val request = Json.parse(posted!!.content) as JsonObject
            val requestId = (request["requestId"] as JsonString).value
            val action = (request["action"] as JsonString).value
            val extra = if (action == "create-invite") {
                """"status":"issued","invite":${invite.toJson().stringify()}"""
            } else {
                """"status":"queued""""
            }
            val content = """{"v":1,"grantId":"${pairing.grantId}","requestId":"$requestId","createdAt":100,$extra}"""
            SignedNostrEvent(
                id = "1".repeat(64), kind = 30078, pubkey = pairing.railPubkey, createdAt = 100,
                tags = listOf(listOf("d", appInviteTag(pairing.grantId, requestId))), content = content, sig = "2".repeat(128),
            )
        }
        val client = AppInviteClient(signer, relay, now = { 100 })
        return Fixture(signer, relay, client)
    }

    @Test
    fun `requests an invite and hands one over without requiring directory access`() = runTest {
        val (_, relay, client) = fixture()
        val reply = client.requestInvite(pairing, AppInviteMode.SINGLE_USE, timeoutMs = 0)
        assertEquals(invite, reply?.invite)
        val handOver = client.handOverInvite(pairing, invite, timeoutMs = 0)
        assertEquals(AppInviteStatus.QUEUED, handOver?.status)
        assertEquals(2, relay.publishCalls)
    }

    @Test
    fun `rejects missing consent locally and refuses a reply from another author before decrypting`() = runTest {
        val (signer, relay, client) = fixture()
        assertNull(client.requestInvite(pairing.copy(grantedCapabilities = emptyList())))
        assertEquals(0, signer.signEventCalls)

        relay.fetchNewestImpl = { _, _, _ ->
            SignedNostrEvent(
                id = "8".repeat(64), kind = 30078, pubkey = "9".repeat(64), createdAt = 100,
                tags = emptyList(), content = "forged", sig = "7".repeat(128),
            )
        }
        assertNull(client.requestInvite(pairing, AppInviteMode.SINGLE_USE, timeoutMs = 0))
        assertEquals(0, signer.decryptCalls)
        assertTrue(relay.fetchNewestCalls > 0)
    }
}
