package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

private val NONCE = "3".repeat(64)
private const val NOW = 1_700_000_000L
private val REQUEST = createContactRequest(
    id = "4".repeat(32), from = "1".repeat(64), to = "2".repeat(64), nonce = NONCE,
    reply = ContactMailbox("5".repeat(64), listOf("wss://relay.example")), now = NOW,
)

class ContactExchangeStateTest {
    @Test
    fun `pins acceptance before revealing and is idempotent on retransmission`() {
        val sender = beginContactExchange(REQUEST, NONCE)
        val receiver = acceptContactExchange(REQUEST, "6".repeat(64), NOW + 1)
        val revealed = receiveContactAcceptance(sender, receiver.acceptance!!, NOW + 2)
        assertEquals(ExchangePhase.REVEAL_PENDING, revealed.phase)
        assertSame(revealed, receiveContactAcceptance(revealed, receiver.acceptance!!, NOW + 3))
        val replacement = createContactAcceptance(REQUEST, "7".repeat(64), NOW + 3)
        val pinned = assertFailsWith<IllegalArgumentException> { receiveContactAcceptance(revealed, replacement, NOW + 4) }
        assertTrue(pinned.message!!.contains("pinned"))
        val completed = receiveContactReveal(receiver, revealed.reveal!!, NOW + 3)
        assertEquals(ExchangePhase.COMPLETE, completed.phase)
        assertEquals(ExchangePhase.COMPLETE, confirmContactRevealSent(revealed).phase)
        assertSame(completed, receiveContactReveal(completed, revealed.reveal!!, NOW + 4))
        assertFailsWith<IllegalArgumentException> {
            receiveContactReveal(receiver, createContactReveal(REQUEST, receiver.acceptance!!, NONCE, NOW + 2), REQUEST.expiresAt)
        }
    }

    @Test
    fun `caps identity decrypt attempts across invites for the whole unlock`() {
        val budget = ContactIdentityDecryptBudget()
        repeat(32) { assertTrue(budget.consume()) }
        assertEquals(0, budget.remaining)
        assertFalse(budget.consume())
    }
}
