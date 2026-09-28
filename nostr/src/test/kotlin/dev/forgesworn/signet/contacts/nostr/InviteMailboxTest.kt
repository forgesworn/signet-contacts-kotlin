package dev.forgesworn.signet.contacts.nostr

import dev.forgesworn.signet.contacts.wire.ContactMailbox
import dev.forgesworn.signet.contacts.wire.SignedNostrEvent
import dev.forgesworn.signet.contacts.wire.UnsignedNostrEvent
import dev.forgesworn.signet.contacts.wire.createContactRequest
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull

/** A [ContactIdentitySigner] over a local key that counts calls, the way the
 *  TypeScript reference's `vi.fn` mocks do. */
private class CountingSigner(secretKey: ByteArray) : ContactIdentitySigner {
    private val inner = LocalKeySigner(secretKey)
    override val publicKey: String = inner.pubkey
    var signEventCalls = 0
        private set
    var decryptCalls = 0
        private set

    override suspend fun signEvent(event: UnsignedNostrEvent): SignedNostrEvent {
        signEventCalls++
        return inner.signEvent(event)
    }

    override suspend fun decrypt(senderPubkey: String, ciphertext: String): String {
        decryptCalls++
        return inner.nip44Decrypt(senderPubkey, ciphertext)
    }
}

class InviteMailboxTest {
    @Test
    fun `hides both identity keys from the relay and sender identity from another invite holder`() = runTest {
        val sender = CountingSigner(NostrKeys.unhex("01".repeat(32)))
        val receiver = CountingSigner(NostrKeys.unhex("02".repeat(32)))
        val stranger = CountingSigner(NostrKeys.unhex("03".repeat(32)))
        val secret = "04".repeat(32)
        val request = createContactRequest(
            id = "05".repeat(16), from = sender.publicKey, to = receiver.publicKey,
            nonce = "06".repeat(32), reply = ContactMailbox("07".repeat(32), listOf("wss://relay.example")), now = 1_700_000_000,
        )
        val wrap = InviteMailbox.wrap(request, secret, sender)
        assertEquals(1, sender.signEventCalls)
        val publicRouting = "${wrap.pubkey}${wrap.tags}"
        assertFalse(publicRouting.contains(sender.publicKey))
        assertFalse(publicRouting.contains(receiver.publicKey))
        val opaque = InviteMailbox.openMailboxWrap(wrap, secret)
        assertNotNull(opaque)
        assertFalse(opaque.toJson().stringify().contains(sender.publicKey))
        assertEquals(0, receiver.decryptCalls)
        assertFailsWith<Exception> { InviteMailbox.openIdentityPacket(opaque, stranger) }
        assertEquals(request, InviteMailbox.openIdentityPacket(opaque, receiver))
        assertEquals(1, receiver.decryptCalls)
        assertNull(InviteMailbox.openMailboxWrap(wrap, "08".repeat(32)))
        assertNull(InviteMailbox.openMailboxWrap(wrap.copy(content = wrap.content + "x"), secret))
    }

    @Test
    fun `rejects malformed packets without asking the identity to decrypt`() = runTest {
        val receiver = CountingSigner(NostrKeys.unhex("02".repeat(32)))
        assertNull(InviteMailbox.openIdentityPacket(SealedContactPacket("invalid", "x"), receiver))
        assertEquals(0, receiver.decryptCalls)
    }
}
