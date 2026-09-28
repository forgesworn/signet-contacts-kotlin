package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.Vectors
import dev.forgesworn.signet.contacts.get
import dev.forgesworn.signet.contacts.string
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.toJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

private val FROM = "1".repeat(64)
private val TO = "2".repeat(64)
private val NONCE = "3".repeat(64)

private fun exchange(): Triple<ContactRequest, ContactAcceptance, ContactReveal> {
    val request = createContactRequest(
        id = "4".repeat(32), from = FROM, to = TO, nonce = NONCE,
        reply = ContactMailbox("5".repeat(64), listOf("wss://relay.example")), now = 1_700_000_000,
    )
    val acceptance = createContactAcceptance(request, "6".repeat(64), request.createdAt + 1)
    val reveal = createContactReveal(request, acceptance, NONCE, request.createdAt + 2)
    return Triple(request, acceptance, reveal)
}

class InviteTest {
    // The "encoded output must not contain the private `name` field" half of
    // this TS case does not port: ContactInvite has no `name` property to
    // attach in the first place, so a leaked field is structurally impossible
    // rather than something a test can provoke and then check for.
    @Test
    fun `round trips an allowlisted invite and rejects unsafe routing, expired and oversized inputs`() {
        val invite = ContactInvite(recipient = TO, secret = "7".repeat(64), relays = listOf("wss://relay.example"), caption = "Conference")
        val encoded = encodeContactInvite(invite)
        assertEquals(
            ContactInvite(recipient = TO, secret = "7".repeat(64), relays = listOf("wss://relay.example/"), caption = "Conference"),
            parseContactInvite(encoded),
        )
        val badRelays = listOf("https://relay.example", "wss://user:secret@relay.example", "wss://relay.example/#secret", "ws://relay.example")
        for (relay in badRelays) {
            val json = """{"v":1,"recipient":"$TO","secret":"${"7".repeat(64)}","relays":["$relay"],"caption":"Conference"}"""
            assertNull(parseContactInvite(json))
        }
        val expiredJson = """{"v":1,"recipient":"$TO","secret":"${"7".repeat(64)}","relays":["wss://relay.example"],"caption":"Conference","expiresAt":100}"""
        assertNull(parseContactInvite(expiredJson, 100))
        assertNull(parseContactInvite("x".repeat(8193)))
    }

    @Test
    fun `pins mailbox-commitment-transcript and directional word vectors`() {
        val vector = Vectors.load("contact-invite-v1.json")
        val (request, acceptance, reveal) = exchange()
        val secret = deriveContactMailboxSecret(vector["inviteSecret"].string)
        try {
            assertEquals(vector["mailboxPrivateKey"].string, secret.joinToString("") { "%02x".format(it) })
        } finally {
            secret.fill(0)
        }
        assertEquals(vector["commitment"].string, request.commitment)
        assertEquals(vector["requestHash"].string, contactMessageHash(request))
        assertEquals(vector["acceptanceHash"].string, contactMessageHash(acceptance))
        val requesterWords = contactVerificationWords(request, acceptance, reveal, FROM)
        assertEquals(vector["requesterWords"]["youSay"].string, requesterWords.youSay)
        assertEquals(vector["requesterWords"]["theySay"].string, requesterWords.theySay)
        val recipientWords = contactVerificationWords(request, acceptance, reveal, TO)
        assertEquals(requesterWords.theySay, recipientWords.youSay)
        assertEquals(requesterWords.youSay, recipientWords.theySay)
    }

    @Test
    fun `binds both keys and both random contributions - rejects substituted accept-reveal and expiry`() {
        val (request, acceptance, reveal) = exchange()
        assertNotEquals(request.commitment, contactCommitment(request.id, request.from, "8".repeat(64), NONCE))
        assertFailsWith<IllegalArgumentException> { createContactReveal(request, acceptance, "9".repeat(64), reveal.createdAt) }
        assertFailsWith<IllegalArgumentException> {
            contactVerificationWords(request, acceptance.copy(nonce = "9".repeat(64)), reveal, FROM)
        }
        assertFailsWith<IllegalArgumentException> {
            contactVerificationWords(request, acceptance, reveal.copy(from = TO), FROM)
        }
        assertFailsWith<IllegalArgumentException> { createContactAcceptance(request, NONCE, request.expiresAt) }
        val json = request.toJson()
        val withBadExpiry = LinkedHashMap(json.fields)
        withBadExpiry["expiresAt"] = (request.createdAt + CONTACT_REQUEST_TTL + 1).toJson()
        assertNull(parseContactExchangeMessage(JsonObject(withBadExpiry).stringify()))
        assertFailsWith<IllegalArgumentException> { contactVerificationWords(request, acceptance, reveal, "8".repeat(64)) }
    }

    @Test
    fun `uses canonical field order and gives no word-grinding freedom in reveal timestamps`() {
        val (request, acceptance, reveal) = exchange()
        val json = request.toJson()
        val reversedFields = LinkedHashMap<String, JsonValue>()
        for ((k, v) in json.fields.entries.reversed()) reversedFields[k] = v
        val reordered = parseContactExchangeMessage(JsonObject(reversedFields).stringify())!!
        assertEquals(contactMessageHash(request), contactMessageHash(reordered))
        val delayed = createContactReveal(request, acceptance, NONCE, reveal.createdAt + 500)
        assertEquals(contactVerificationWords(request, acceptance, reveal, FROM), contactVerificationWords(request, acceptance, delayed, FROM))
    }
}
