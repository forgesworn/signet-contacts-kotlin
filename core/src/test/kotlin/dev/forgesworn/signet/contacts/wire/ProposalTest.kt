package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

private val GRANT = "f".repeat(32)
private val APP = "a".repeat(64)

private fun addKen(
    grantId: String = GRANT,
    operationId: String = "9".repeat(32),
    value: ProposalValue = AddKenValue("c".repeat(64), "Ada"),
    createdAt: Long = 1_700_000_000,
): ContactProposalV1 = ContactProposalV1(grantId, operationId, value, createdAt)

private fun rename(
    grantId: String = GRANT,
    operationId: String = "8".repeat(32),
    value: ProposalValue = RenameAppLabelValue("a".repeat(32), "Coach", 1_700_000_000_000),
    createdAt: Long = 1_700_000_000,
): ContactProposalV1 = ContactProposalV1(grantId, operationId, value, createdAt)

class ProposalTest {
    @Test
    fun `round-trips both actions`() {
        val batch = parseProposalBatch(buildProposalBatch(listOf(addKen(), rename())))
        assertEquals(listOf(addKen(), rename()), batch?.proposals)
    }

    @Test
    fun `throws on an over-cap batch rather than truncating silently`() {
        val many = (0..MAX_PROPOSALS_PER_BATCH).map { addKen(operationId = it.toString(16).padStart(32, '0')) }
        val e = assertFailsWith<IllegalArgumentException> { buildProposalBatch(many) }
        assertTrue(e.message!!.contains("50"))
    }

    @Test
    fun `throws on an empty batch`() {
        assertFailsWith<IllegalArgumentException> { buildProposalBatch(emptyList()) }
    }

    @Test
    fun `throws when a proposal would be rewritten in transit`() {
        assertFailsWith<IllegalArgumentException> { buildProposalBatch(listOf(addKen(value = AddKenValue("nope", "Ada")))) }
        assertFailsWith<IllegalArgumentException> { buildProposalBatch(listOf(addKen(operationId = "short"))) }
        assertFailsWith<IllegalArgumentException> {
            buildProposalBatch(listOf(rename(value = RenameAppLabelValue("a".repeat(32), "x".repeat(200), 1_700_000_000_000))))
        }
        assertFailsWith<IllegalArgumentException> { buildProposalBatch(listOf(addKen(value = AddKenValue("c".repeat(64), "   ")))) }
    }

    @Test
    fun `drops an individually invalid proposal on parse and keeps the rest`() {
        val json = """{"v":1,"proposals":[${addKen().toJson().stringify()},{"v":1,"action":"nonsense"}]}"""
        assertEquals(1, parseProposalBatch(json)?.proposals?.size)
    }

    @Test
    fun `drops a rename-app-label with a missing or malformed updatedAt (R-7) and keeps the rest`() {
        val missingJson =
            """{"v":1,"grantId":"$GRANT","operationId":"${"7".repeat(32)}","action":"rename-app-label","value":{"contactId":"${"a".repeat(32)}","label":"Coach"},"createdAt":1700000000}"""
        val negative = rename(operationId = "6".repeat(32), value = RenameAppLabelValue("a".repeat(32), "Coach", -1))
        val nonIntegerJson =
            """{"v":1,"grantId":"$GRANT","operationId":"${"5".repeat(32)}","action":"rename-app-label","value":{"contactId":"${"a".repeat(32)}","label":"Coach","updatedAt":1.5},"createdAt":1700000000}"""
        val nonNumericJson =
            """{"v":1,"grantId":"$GRANT","operationId":"${"4".repeat(32)}","action":"rename-app-label","value":{"contactId":"${"a".repeat(32)}","label":"Coach","updatedAt":"1700000000000"},"createdAt":1700000000}"""
        val json = """{"v":1,"proposals":[${addKen().toJson().stringify()},$missingJson,${negative.toJson().stringify()},$nonIntegerJson,$nonNumericJson]}"""
        assertEquals(listOf(addKen()), parseProposalBatch(json)?.proposals)
    }

    @Test
    fun `caps the parsed batch at 50`() {
        val many = (0 until 80).map { addKen(operationId = it.toString(16).padStart(32, '0')) }
        val json = """{"v":1,"proposals":[${many.joinToString(",") { it.toJson().stringify() }}]}"""
        assertEquals(50, parseProposalBatch(json)?.proposals?.size)
    }

    @Test
    fun `returns null on a broken envelope`() {
        assertNull(parseProposalBatch("{"))
        assertNull(parseProposalBatch("[]"))
        assertNull(parseProposalBatch("""{"v":2,"proposals":[]}"""))
        assertNull(parseProposalBatch("""{"v":1}"""))
    }

    @Test
    fun `draftToProposal mints a 32-hex operation id and stamps the grant`() {
        val p = draftToProposal(ContactProposalDraft.AddKen("c".repeat(64), "Ada"), GRANT, 1_700_000_000)
        assertTrue(Regex("^[0-9a-f]{32}$").matches(p.operationId))
        assertEquals(GRANT, p.grantId)
        assertEquals(1_700_000_000L, p.createdAt)
    }

    @Test
    fun `R-7 - stamps a rename draft's updatedAt from the draft when given`() {
        val p = draftToProposal(ContactProposalDraft.RenameAppLabel("a".repeat(32), "Coach", 1_700_000_000_000), GRANT, 1_700_000_000)
        assertEquals(RenameAppLabelValue("a".repeat(32), "Coach", 1_700_000_000_000), p.value)
    }

    @Test
    fun `R-7 - defaults a rename draft's updatedAt to now() when omitted`() {
        val before = System.currentTimeMillis()
        val p = draftToProposal(ContactProposalDraft.RenameAppLabel("a".repeat(32), "Coach"), GRANT, 1_700_000_000)
        val after = System.currentTimeMillis()
        val value = p.value as RenameAppLabelValue
        assertTrue(value.updatedAt >= before)
        assertTrue(value.updatedAt <= after)
    }

    @Test
    fun `proposalEventTemplate is a replaceable kind-30078 under the app-bound proposal tag`() {
        val tmpl = proposalEventTemplate(APP, GRANT, 1_700_000_000, "ciphertext")
        assertEquals(PROPOSAL_KIND, tmpl.kind)
        assertEquals(APP, tmpl.pubkey)
        assertEquals(listOf(listOf("d", proposalTag(GRANT, APP))), tmpl.tags)
    }

    @Test
    fun `proposalFilter builds the matching producer-side filter pinned to the app author`() {
        assertEquals(
            NostrFilter(kinds = listOf(PROPOSAL_KIND), authors = listOf(APP), limit = 1, tags = mapOf("#d" to listOf(proposalTag(GRANT, APP)))),
            proposalFilter(APP, GRANT),
        )
    }
}
