package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.Vectors
import dev.forgesworn.signet.contacts.get
import dev.forgesworn.signet.contacts.string
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.toJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

private val ID = "1".repeat(32)
private val CONTEXT = "2".repeat(64)
private val FROM = "3".repeat(64)
private val TO = "4".repeat(64)
private val NONCE = "5".repeat(64)
private const val NOW = 1_800_000_000L

private fun exchange(): Triple<ChannelCheckRequest, ChannelCheckAcceptance, ChannelCheckReveal> {
    val request = createChannelCheckRequest(ID, CONTEXT, FROM, TO, NONCE, NOW)
    val acceptance = createChannelCheckAcceptance(request, "6".repeat(64), NOW + 1)
    val reveal = createChannelCheckReveal(request, acceptance, NONCE, NOW + 2)
    return Triple(request, acceptance, reveal)
}

private fun mutateJson(json: JsonObject, mutate: (LinkedHashMap<String, JsonValue>) -> Unit): String {
    val fields = LinkedHashMap(json.fields)
    mutate(fields)
    return JsonObject(fields).stringify()
}

class ChannelCheckTest {
    @Test
    fun `pins the separate channel profile and three-word directional vectors`() {
        val vector = Vectors.load("channel-check-v1.json")
        val (request, acceptance, reveal) = exchange()
        assertEquals(vector["request"], request.toJson())
        assertEquals(vector["acceptance"], acceptance.toJson())
        assertEquals(vector["reveal"], reveal.toJson())
        assertEquals(vector["requestHash"].string, channelCheckHash(request))
        assertEquals(vector["acceptanceHash"].string, channelCheckHash(acceptance))
        val requesterWords = channelCheckWords(request, acceptance, reveal, FROM)
        assertEquals(vector["requesterWords"]["youSay"].string, requesterWords.youSay)
        assertEquals(vector["requesterWords"]["theySay"].string, requesterWords.theySay)
        assertEquals(3, requesterWords.youSay.split(" ").size)
        val recipientWords = channelCheckWords(request, acceptance, reveal, TO)
        assertEquals(requesterWords.theySay, recipientWords.youSay)
        assertEquals(requesterWords.youSay, recipientWords.theySay)
    }

    @Test
    fun `binds the channel context, both participants, both nonces and every transcript message`() {
        val (request, acceptance, reveal) = exchange()
        assertNotEquals(request.commitment, channelCheckCommitment(ID, "7".repeat(64), FROM, TO, NONCE))
        assertNotEquals(request.commitment, channelCheckCommitment(ID, CONTEXT, FROM, "7".repeat(64), NONCE))
        assertNotEquals(request.commitment, channelCheckCommitment(ID, CONTEXT, "7".repeat(64), TO, NONCE))
        assertNotEquals(request.commitment, channelCheckCommitment(ID, CONTEXT, FROM, TO, "7".repeat(64)))
        val altered = listOf(
            acceptance.copy(context = "7".repeat(64)),
            acceptance.copy(requestHash = "7".repeat(64)),
            acceptance.copy(from = FROM),
            acceptance.copy(nonce = "7".repeat(64)),
        )
        for (a in altered) assertFailsWith<IllegalArgumentException> { channelCheckWords(request, a, reveal, FROM) }
        assertFailsWith<IllegalArgumentException> { channelCheckWords(request, acceptance, reveal.copy(nonce = "7".repeat(64)), FROM) }
        assertFailsWith<IllegalArgumentException> { channelCheckWords(request, acceptance, reveal, "7".repeat(64)) }
    }

    @Test
    fun `pins the first acceptance before revealing, rejects substitution after restart and completes both sides`() {
        val (request, acceptance, reveal) = exchange()
        val initial = beginChannelCheck(request, NONCE)
        val pinned = receiveChannelCheckAcceptance(initial, acceptance, reveal.createdAt)
        // Simulates a reload from persisted state: a fresh, structurally equal
        // instance rather than the same object reference.
        val restored = pinned.copy()
        assertEquals(pinned, receiveChannelCheckAcceptance(restored, acceptance, reveal.createdAt + 1))
        val pinnedError = assertFailsWith<IllegalArgumentException> {
            receiveChannelCheckAcceptance(restored, acceptance.copy(nonce = "7".repeat(64)), reveal.createdAt + 1)
        }
        assertTrue(pinnedError.message!!.contains("pinned"))
        assertEquals(ExchangePhase.COMPLETE, confirmChannelCheckRevealSent(restored).phase)
        val recipient = acceptChannelCheck(request, acceptance.nonce, acceptance.createdAt)
        val complete = receiveChannelCheckReveal(recipient, reveal, reveal.createdAt)
        assertEquals(ExchangePhase.COMPLETE, complete.phase)
        assertEquals(complete, receiveChannelCheckReveal(complete, reveal, reveal.createdAt))
        val revealPinnedError = assertFailsWith<IllegalArgumentException> {
            receiveChannelCheckReveal(complete, reveal.copy(createdAt = reveal.createdAt + 1), reveal.createdAt + 1)
        }
        assertTrue(revealPinnedError.message!!.contains("pinned"))
        assertFailsWith<IllegalArgumentException> {
            receiveChannelCheckAcceptance(initial.copy(phase = ExchangePhase.DECLINED), acceptance, reveal.createdAt)
        }
    }

    @Test
    fun `bounds input, lifetime and clocks while retaining already-completed words after expiry`() {
        val (request, acceptance, reveal) = exchange()
        val badExpiry = mutateJson(request.toJson()) { it["expiresAt"] = (request.createdAt + CHANNEL_CHECK_TTL + 1).toJson() }
        val badContext = mutateJson(request.toJson()) { it["context"] = "".toJson() }
        val badFrom = mutateJson(request.toJson()) { it["from"] = request.to.toJson() }
        for (raw in listOf("null", "[]", "x".repeat(2049), badExpiry, badContext, badFrom)) {
            assertNull(parseChannelCheckMessage(raw))
        }
        assertFailsWith<IllegalArgumentException> { createChannelCheckAcceptance(request, acceptance.nonce, request.expiresAt) }
        assertFailsWith<IllegalArgumentException> { createChannelCheckReveal(request, acceptance, NONCE, NOW) }
        assertFailsWith<IllegalArgumentException> {
            receiveChannelCheckReveal(acceptChannelCheck(request, acceptance.nonce, acceptance.createdAt), reveal, request.expiresAt)
        }
        assertTrue(channelCheckWords(request, acceptance, reveal, FROM).youSay.isNotEmpty())
    }

    @Test
    fun `canonicalises field order and excludes reveal timestamps from the words`() {
        val (request, acceptance, reveal) = exchange()
        val reversedFields = LinkedHashMap<String, JsonValue>()
        for ((k, v) in request.toJson().fields.entries.reversed()) reversedFields[k] = v
        val reordered = parseChannelCheckMessage(JsonObject(reversedFields).stringify())!!
        assertEquals(channelCheckHash(request), channelCheckHash(reordered))
        val withExtraField = mutateJson(request.toJson()) { it["reply"] = jsonObject("secret" to "secret".toJson()) }
        assertEquals(request, parseChannelCheckMessage(withExtraField))
        val delayed = createChannelCheckReveal(request, acceptance, NONCE, reveal.createdAt + 100)
        assertEquals(channelCheckWords(request, acceptance, reveal, FROM), channelCheckWords(request, acceptance, delayed, FROM))
    }
}
