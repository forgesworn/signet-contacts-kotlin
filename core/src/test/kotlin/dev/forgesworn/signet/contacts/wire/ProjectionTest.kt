package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonNull
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.jsonArray
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.jsonStrings
import dev.forgesworn.signet.contacts.json.toJson
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

private val GRANT = "f".repeat(32)
private val DEVICE = "2".repeat(32)
private val DIR = Capability.READ_DIRECTORY

/** Every read capability, so a fixture carrying any covered field is in contract. */
private val FULL_SCOPES: List<Capability> = listOf(
    Capability.READ_DIRECTORY, Capability.READ_METHOD_PHONE, Capability.READ_METHOD_EMAIL,
    Capability.READ_METHOD_WEBSITE, Capability.READ_METHOD_POSTAL_ADDRESS, Capability.READ_METHOD_OTHER,
    Capability.READ_TIER, Capability.READ_CHECKS, Capability.READ_CHECK_RECORDS,
    Capability.READ_ROLES, Capability.BLOCKS_READ,
)

private fun contact(
    contactId: String = "a".repeat(32),
    identities: List<ProjectedIdentity>? = listOf(ProjectedIdentity("b".repeat(64), ProjectedVerification.PROVEN)),
    displayName: String? = "Sam",
    effectiveTier: ProjectedTier? = ProjectedTier.KITH,
    tierSource: ProjectedTierSource? = ProjectedTierSource.DIRECT,
    blocked: Boolean? = false,
    roles: List<String>? = null,
    contactMethods: List<ProjectedMethod>? = null,
    checks: List<ProjectedCheck>? = null,
    avatar: ProjectedAvatar? = null,
    type: ProjectedType? = null,
    linkedPubkeys: List<String>? = null,
): ProjectedContact = ProjectedContact(
    contactId = contactId, type = type, effectiveTier = effectiveTier, tierSource = tierSource, blocked = blocked,
    identities = identities, displayName = displayName, avatar = avatar, roles = roles, contactMethods = contactMethods,
    checks = checks, linkedPubkeys = linkedPubkeys,
)

private fun projection(
    grantId: String = GRANT,
    scopes: List<Capability> = FULL_SCOPES,
    frontier: ProjectionFrontier = ProjectionFrontier(7, 12, 1_700_000_000, DEVICE),
    issuedAt: Long = 1_700_000_000,
    expiresAt: Long = 1_700_021_600,
    contacts: List<ProjectedContact> = listOf(contact()),
    revoked: Boolean = false,
    truncated: Boolean = false,
): ContactProjectionV2 = ContactProjectionV2(grantId, scopes, frontier, issuedAt, expiresAt, contacts, revoked, truncated)

/** Replace one top-level field of a projection's canonical JSON. */
private fun ContactProjectionV2.jsonWith(vararg overrides: Pair<String, JsonValue>): String {
    val fields = LinkedHashMap(toJson().fields)
    for ((k, v) in overrides) fields[k] = v
    return JsonObject(fields).stringify()
}

class ProjectionTest {
    @Test
    fun `round-trips a full projection`() {
        val p = projection(
            contacts = listOf(
                contact(
                    roles = listOf("coach"),
                    contactMethods = listOf(ProjectedMethod(ProjectedMethodKind.EMAIL, "sam@example.com", MethodVerification.UNVERIFIED)),
                    checks = listOf(ProjectedCheck("b".repeat(64), CheckMethod.WORDS, 1000)),
                ),
            ),
        )
        assertEquals(p, parseProjection(buildProjection(p)))
    }

    // "produces byte-identical JSON regardless of caller key insertion order
    // (I1)" does not port: a Kotlin data class has no notion of "key insertion
    // order" distinct from its fixed constructor/field order, so the
    // guarantee this TS test exercises (JSON.stringify output independent of
    // an object literal's declared key order) is structural here, not
    // something varying a call site's named-argument order could fail to meet.

    @Test
    fun `does not throw when an optional contact field is explicitly null (I2)`() {
        val withNulls = contact(roles = null, avatar = null)
        val built = buildProjection(projection(contacts = listOf(withNulls)))
        val parsed = parseProjection(built)
        assertNull(parsed?.contacts?.get(0)?.roles)
        assertNull(parsed?.contacts?.get(0)?.avatar)
    }

    @Test
    fun `round-trips a revocation with no contacts`() {
        val p = projection(contacts = emptyList(), revoked = true)
        val parsed = parseProjection(buildProjection(p))
        assertEquals(true, parsed?.revoked)
        assertEquals(emptyList(), parsed?.contacts)
    }

    @Test
    fun `round-trips the truncated marker`() {
        val p = projection(truncated = true)
        assertEquals(true, parseProjection(buildProjection(p))?.truncated)
        assertEquals(false, parseProjection(buildProjection(projection()))?.truncated)
    }

    @Test
    fun `rejects a frontier with no publisher or no moment`() {
        val json = buildProjection(projection())
        assertNull(parseProjection(json.replace("\"deviceId\":\"$DEVICE\"", "\"deviceId\":\"nope\"")))
        assertNull(parseProjection(json.replace("\"publishedAt\":1700000000", "\"publishedAt\":\"soon\"")))
    }

    @Test
    fun `measures and refuses a body over the wire cap`() {
        val small = projection()
        assertTrue(projectionByteLength(small) < MAX_WIRE_BYTES)
        // ~400 bytes each, so 400 contacts is comfortably over 65532.
        val many = (0 until 400).map { i ->
            contact(
                contactId = i.toString(16).padStart(32, '0'),
                displayName = "N".repeat(100),
                roles = listOf("r".repeat(40), "s".repeat(40)),
                contactMethods = listOf(
                    ProjectedMethod(ProjectedMethodKind.EMAIL, "e".repeat(64) + "@example.com"),
                    ProjectedMethod(ProjectedMethodKind.OTHER, "f".repeat(64)),
                ),
            )
        }
        val big = projection(contacts = many)
        assertTrue(projectionByteLength(big) > MAX_WIRE_BYTES)
        val e = assertFailsWith<IllegalArgumentException> { buildProjection(big) }
        assertTrue(e.message!!.contains("65532"))
    }

    @Test
    fun `omits absent optional fields rather than emitting undefined`() {
        assertFalse(buildProjection(projection()).contains("\"roles\""))
        assertFalse(buildProjection(projection()).contains("\"avatar\""))
    }

    @Test
    fun `throws when an input contact would not survive its own parser`() {
        assertFailsWith<IllegalArgumentException> { buildProjection(projection(contacts = listOf(contact(contactId = "not-hex")))) }
        assertFailsWith<IllegalArgumentException> { buildProjection(projection(contacts = listOf(contact(displayName = "x".repeat(200))))) }
        assertFailsWith<IllegalArgumentException> { buildProjection(projection(contacts = listOf(contact(roles = List(20) { "r" })))) }
    }

    @Test
    fun `throws on a grant id or expiry that is not well formed`() {
        assertFailsWith<IllegalArgumentException> { buildProjection(projection(grantId = "short")) }
        assertFailsWith<IllegalArgumentException> { buildProjection(projection(expiresAt = 1_600_000_000)) }
    }

    // R-31: the directory owner's persona pubkey is NOT on this wire.
    // M8: the parser's own cap used to be silent; a cut the READER makes is
    // exactly as much a truncation as one the producer made.
    @Test
    fun `sets truncated when it caps the contacts list itself`() {
        val many = (0 until MAX_CONTACTS_PER_PROJECTION + 3).map { i ->
            jsonObject("contactId" to i.toString(16).padStart(32, '0').toJson())
        }
        val overSent = jsonObject(
            "v" to 2.toJson(), "grantId" to GRANT.toJson(), "scopes" to jsonStrings(FULL_SCOPES.map { it.wire }),
            "frontier" to jsonObject("maxClock" to 1.toJson(), "opCount" to 1.toJson(), "publishedAt" to 1.toJson(), "deviceId" to DEVICE.toJson()),
            "issuedAt" to 1.toJson(), "expiresAt" to 2.toJson(), "contacts" to jsonArray(many),
        ).stringify()
        val parsed = parseProjection(overSent)
        assertEquals(MAX_CONTACTS_PER_PROJECTION, parsed?.contacts?.size)
        assertEquals(true, parsed?.truncated)
    }

    @Test
    fun `leaves truncated unset when nothing was cut`() {
        assertEquals(false, parseProjection(buildProjection(projection()))?.truncated)
    }

    // "'ownerPubkey' in parsed" does not port: ContactProjectionV2 is a fixed
    // data class with no ownerPubkey property, so its absence is structural
    // rather than something a smuggled field could ever produce.
    @Test
    fun `does not carry an owner pubkey, and drops one a producer tries to smuggle in`() {
        val body = buildProjection(projection())
        assertFalse(body.contains("ownerPubkey"))
        val smuggled = projection().jsonWith("ownerPubkey" to "1".repeat(64).toJson())
        assertNotNull(parseProjection(smuggled))
    }

    @Test
    fun `parses a projection that never had an owner pubkey at all`() {
        val body = Json.parse(buildProjection(projection())) as JsonObject
        assertNull(body.fields["ownerPubkey"])
        assertEquals(GRANT, parseProjection(body.stringify())?.grantId)
    }

    // "throws when a scope would be silently narrowed in transit" does not
    // port: buildProjection takes `List<Capability>`, an enum, so there is no
    // way to construct a bogus scope value to pass it in the first place -
    // the TS case relies on `as unknown as ContactProjectionV2['scopes']` to
    // smuggle a non-capability string past the type system.

    @Test
    fun `does not throw when the same scope set is given in a different order`() {
        val a = buildProjection(projection(scopes = FULL_SCOPES))
        val b = buildProjection(projection(scopes = FULL_SCOPES.reversed()))
        assertEquals(a, b)
    }

    @Test
    fun `drops an individually invalid contact and keeps the rest`() {
        val good = buildProjection(projection(contacts = listOf(contact(), contact(contactId = "9".repeat(32)))))
        val tampered = good.replace("\"" + "9".repeat(32) + "\"", "\"bad\"")
        val parsed = parseProjection(tampered)
        assertEquals(1, parsed?.contacts?.size)
        assertEquals("a".repeat(32), parsed?.contacts?.get(0)?.contactId)
    }

    @Test
    fun `returns null on a structurally broken envelope`() {
        assertNull(parseProjection("{"))
        assertNull(parseProjection("[]"))
        assertNull(parseProjection(buildProjection(projection()).replace("\"v\":2", "\"v\":1")))
        assertNull(parseProjection("{\"v\":2,\"grantId\":\"$GRANT\"}"))
    }

    @Test
    fun `caps the contacts list`() {
        val many = (0 until 2100).map { i -> contact(contactId = i.toString(16).padStart(32, '0')).toJson() }
        val json = projection().jsonWith("contacts" to jsonArray(many))
        assertEquals(MAX_CONTACTS_PER_PROJECTION, parseProjection(json)?.contacts?.size)
    }

    @Test
    fun `refuses a projection carrying an avatar, type or linked pubkeys - no capability covers them`() {
        // avatar
        assertNull(parseProjection(projection().jsonWith("contacts" to jsonArray(listOf(contact(avatar = ProjectedAvatar("https://x.example/a", "c".repeat(64))).toJson())))))
        val avatarError = assertFailsWith<IllegalArgumentException> {
            buildProjection(projection(contacts = listOf(contact(avatar = ProjectedAvatar("https://x.example/a", "c".repeat(64))))))
        }
        assertTrue(avatarError.message!!.contains("do not cover"))
        // type
        assertNull(parseProjection(projection().jsonWith("contacts" to jsonArray(listOf(contact(type = ProjectedType.PERSON).toJson())))))
        val typeError = assertFailsWith<IllegalArgumentException> { buildProjection(projection(contacts = listOf(contact(type = ProjectedType.PERSON)))) }
        assertTrue(typeError.message!!.contains("do not cover"))
        // linkedPubkeys
        assertNull(parseProjection(projection().jsonWith("contacts" to jsonArray(listOf(contact(linkedPubkeys = listOf("e".repeat(64))).toJson())))))
        val linkedError = assertFailsWith<IllegalArgumentException> {
            buildProjection(projection(contacts = listOf(contact(linkedPubkeys = listOf("e".repeat(64))))))
        }
        assertTrue(linkedError.message!!.contains("do not cover"))
    }

    @Test
    fun `refuses a contact carrying an avatar even under every read scope`() {
        val withAvatar = contact(avatar = ProjectedAvatar("https://x.example/a", "c".repeat(64)))
        assertNull(parseProjectedContact(withAvatar.toJson(), FULL_SCOPES))
        assertNotNull(parseProjectedContact(contact().toJson(), FULL_SCOPES))
    }

    // "keys not containing sharedSecret/notes/..." does not port beyond
    // confirming the contact still parses: ProjectedContact is a fixed data
    // class with no such properties, so an unknown field leaking through is
    // structurally impossible rather than something the parser could fail to
    // strip.
    @Test
    fun `strips fields outside the allowlist from a wire contact`() {
        val contactFields = LinkedHashMap(contact().toJson().fields)
        contactFields["sharedSecret"] = "topsecret".toJson()
        contactFields["notes"] = "private notes".toJson()
        contactFields["itemId"] = "internal-id".toJson()
        contactFields["actorPubkey"] = "z".repeat(64).toJson()
        contactFields["reason"] = "because".toJson()
        val json = projection().jsonWith("contacts" to jsonArray(listOf(JsonObject(contactFields))))
        val parsed = parseProjection(json)
        assertEquals(1, parsed?.contacts?.size)
        assertEquals(contact(), parsed?.contacts?.get(0))
    }

    @Test
    fun `caps identities and contact methods per contact on parse`() {
        val manyIdentities = (0 until MAX_IDENTITIES_PER_CONTACT + 4).map { i ->
            jsonObject("pubkey" to i.toString(16).padStart(64, '0').toJson(), "verification" to "proven".toJson())
        }
        val manyMethods = (0 until MAX_METHODS_PER_CONTACT + 4).map { i ->
            jsonObject("kind" to "email".toJson(), "value" to "a$i@example.com".toJson(), "verification" to "unverified".toJson())
        }
        val contactFields = LinkedHashMap(contact().toJson().fields)
        contactFields["identities"] = jsonArray(manyIdentities)
        contactFields["contactMethods"] = jsonArray(manyMethods)
        val json = projection().jsonWith("contacts" to jsonArray(listOf(JsonObject(contactFields))))
        val parsed = parseProjection(json)
        assertEquals(MAX_IDENTITIES_PER_CONTACT, parsed?.contacts?.get(0)?.identities?.size)
        assertEquals(MAX_METHODS_PER_CONTACT, parsed?.contacts?.get(0)?.contactMethods?.size)
    }

    @Test
    fun `sanitises control-bidi characters in displayName and method values on parse`() {
        val poisonedFields = LinkedHashMap(contact().toJson().fields)
        poisonedFields["displayName"] = "Sam\u200b\u202e evil".toJson()
        poisonedFields["contactMethods"] = jsonArray(
            listOf(jsonObject("kind" to "email".toJson(), "value" to "sam\u200b@example.com".toJson(), "verification" to "unverified".toJson())),
        )
        val json = projection().jsonWith("contacts" to jsonArray(listOf(JsonObject(poisonedFields))))
        val parsed = parseProjection(json)
        assertEquals("Sam evil", parsed?.contacts?.get(0)?.displayName)
        assertEquals("sam@example.com", parsed?.contacts?.get(0)?.contactMethods?.get(0)?.value)
    }

    @Test
    fun `drops a later duplicate contactId, keeping the first (M5)`() {
        val json = projection().jsonWith(
            "contacts" to jsonArray(listOf(contact(displayName = "First").toJson(), contact(displayName = "Second").toJson())),
        )
        val parsed = parseProjection(json)
        assertEquals(1, parsed?.contacts?.size)
        assertEquals("First", parsed?.contacts?.get(0)?.displayName)
    }

    @Test
    fun `caps scopes before filtering (M3)`() {
        val scopes = (0 until MAX_CAPABILITIES + 10).map { i -> if (i == MAX_CAPABILITIES + 5) "signet.contacts.read:directory" else "bogus" }
        val json = projection().jsonWith("scopes" to jsonStrings(scopes), "contacts" to jsonArray(emptyList()))
        assertEquals(emptyList(), parseProjection(json)?.scopes)
    }

    @Test
    fun `filters unknown scope strings`() {
        val json = projection().jsonWith(
            "scopes" to jsonStrings(listOf("signet.contacts.read:directory", "signet.contacts.read:bogus", "not-a-capability")),
            "contacts" to jsonArray(listOf(jsonObject("contactId" to "a".repeat(32).toJson(), "displayName" to "Sam".toJson()))),
        )
        assertEquals(listOf(Capability.READ_DIRECTORY), parseProjection(json)?.scopes)
    }

    @Test
    fun `never throws on hostile contact nesting`() {
        val json = projection().jsonWith("contacts" to jsonArray(listOf(JsonNull, 1.toJson(), "x".toJson(), jsonObject("weird" to true.toJson()))))
        val parsed = parseProjection(json)
        assertEquals(emptyList(), parsed?.contacts)
    }

    @Test
    fun `projectionEventTemplate addresses the replaceable projection by opaque d tag with no p tag`() {
        val tmpl = projectionEventTemplate("b".repeat(64), GRANT, 1_700_000_000, "ciphertext")
        assertEquals(PROJECTION_KIND, tmpl.kind)
        assertEquals(listOf(listOf("d", projectionTag(GRANT))), tmpl.tags)
        assertFalse(tmpl.tags.any { it.firstOrNull() == "p" })
    }

    @Test
    fun `projectionFilter builds the matching consumer filter`() {
        assertEquals(
            NostrFilter(kinds = listOf(PROJECTION_KIND), authors = listOf("b".repeat(64)), limit = 1, tags = mapOf("#d" to listOf(projectionTag(GRANT)))),
            projectionFilter("b".repeat(64), GRANT),
        )
    }

    @Test
    fun `round-trips name and public key without inventing a tier, block state or checks`() {
        val minimal = ProjectedContact(contactId = "a".repeat(32), displayName = "Ada", identities = listOf(ProjectedIdentity("b".repeat(64))))
        val read = parseProjection(buildProjection(projection(contacts = listOf(minimal))))!!
        assertEquals(listOf(minimal), read.contacts)
        assertNull(read.contacts[0].effectiveTier)
        assertNull(read.contacts[0].blocked)
        assertNull(read.contacts[0].identities?.get(0)?.verification)
    }

    @Test
    fun `round-trips a method value without requiring a verification disclosure`() {
        val minimal = ProjectedContact(contactId = "a".repeat(32), contactMethods = listOf(ProjectedMethod(ProjectedMethodKind.EMAIL, "ada@example.com")))
        val result = parseProjection(buildProjection(projection(scopes = listOf(DIR, Capability.READ_METHOD_EMAIL), contacts = listOf(minimal))))
        assertEquals(listOf(minimal), result?.contacts)
    }

    @Test
    fun `allowlists check summaries and strips private sources and evidence`() {
        val contactJson = jsonObject(
            "contactId" to "a".repeat(32).toJson(),
            "checks" to jsonArray(
                listOf(
                    jsonObject(
                        "pubkey" to "b".repeat(64).toJson(), "method" to "words".toJson(), "checkedAt" to 1000.toJson(),
                        "source" to "website".toJson(), "evidence" to "private link".toJson(), "ownerIdentityPubkey" to "c".repeat(64).toJson(),
                    ),
                    jsonObject("pubkey" to "b".repeat(64).toJson(), "method" to "invented".toJson(), "checkedAt" to 1000.toJson()),
                ),
            ),
        )
        val parsed = parseProjectedContact(contactJson, listOf(DIR, Capability.READ_CHECK_RECORDS))
        assertEquals(listOf(ProjectedCheck("b".repeat(64), CheckMethod.WORDS, 1000)), parsed?.checks)
    }
}

// Consent (WIRE.md \u00a710): a field the projection's scopes do not cover is
// broader sharing than the owner approved. The builder throws, the parser
// refuses the whole projection - both from the one coverage table.
private data class CoverageCase(val label: String, val scopes: List<Capability>, val contact: ProjectedContact)

private val COVERAGE_CASES = listOf(
    CoverageCase("tier without read:tier", listOf(DIR), ProjectedContact(contactId = "a".repeat(32), effectiveTier = ProjectedTier.KITH)),
    CoverageCase("tier source without read:tier", listOf(DIR), ProjectedContact(contactId = "a".repeat(32), tierSource = ProjectedTierSource.DIRECT)),
    CoverageCase("roles without read:roles", listOf(DIR), ProjectedContact(contactId = "a".repeat(32), roles = listOf("coach"))),
    CoverageCase(
        "identity verification without read:checks", listOf(DIR),
        ProjectedContact(contactId = "a".repeat(32), identities = listOf(ProjectedIdentity("b".repeat(64), ProjectedVerification.PROVEN))),
    ),
    CoverageCase(
        "a phone method under an email grant", listOf(DIR, Capability.READ_METHOD_EMAIL),
        ProjectedContact(contactId = "a".repeat(32), contactMethods = listOf(ProjectedMethod(ProjectedMethodKind.PHONE, "+441234"))),
    ),
    CoverageCase(
        "method verification without read:checks", listOf(DIR, Capability.READ_METHOD_EMAIL),
        ProjectedContact(contactId = "a".repeat(32), contactMethods = listOf(ProjectedMethod(ProjectedMethodKind.EMAIL, "a@b.example", MethodVerification.PROVEN))),
    ),
    CoverageCase(
        "check records under read:checks only", listOf(DIR, Capability.READ_CHECKS),
        ProjectedContact(contactId = "a".repeat(32), checks = listOf(ProjectedCheck("b".repeat(64), CheckMethod.WORDS, 1))),
    ),
    CoverageCase("block state without blocks.read", listOf(DIR), ProjectedContact(contactId = "a".repeat(32), blocked = false)),
    CoverageCase(
        "tier with read:tier but no directory", listOf(Capability.READ_TIER, Capability.BLOCKS_READ),
        ProjectedContact(contactId = "a".repeat(32), blocked = true, effectiveTier = ProjectedTier.KIN),
    ),
    CoverageCase("an unblocked contact under blocks.read only", listOf(Capability.BLOCKS_READ), ProjectedContact(contactId = "a".repeat(32), blocked = false)),
    CoverageCase(
        "a display name under blocks.read only", listOf(Capability.BLOCKS_READ),
        ProjectedContact(contactId = "a".repeat(32), blocked = true, displayName = "Mallory"),
    ),
)

class ProjectionFieldCoverageTest {
    @Test
    fun `refuses every uncovered case`() {
        for (case in COVERAGE_CASES) {
            val e = assertFailsWith<IllegalArgumentException>("refuses ${case.label}") {
                buildProjection(projection(scopes = case.scopes, contacts = listOf(case.contact)))
            }
            assertTrue(e.message!!.contains("do not cover"), "refuses ${case.label}: ${e.message}")
            val json = projection().jsonWith("scopes" to jsonStrings(case.scopes.map { it.wire }), "contacts" to jsonArray(listOf(case.contact.toJson())))
            assertNull(parseProjection(json), "refuses ${case.label} (parse)")
            assertNull(parseProjectedContact(case.contact.toJson(), case.scopes), "refuses ${case.label} (contact)")
        }
    }

    @Test
    fun `accepts a blocked contact and its identity pubkeys under blocks_read alone`() {
        val c = ProjectedContact(contactId = "a".repeat(32), identities = listOf(ProjectedIdentity("b".repeat(64))), blocked = true)
        val p = projection(scopes = listOf(Capability.BLOCKS_READ), contacts = listOf(c))
        assertEquals(p, parseProjection(buildProjection(p)))
    }

    @Test
    fun `accepts each method kind under its own capability`() {
        val c = ProjectedContact(contactId = "a".repeat(32), contactMethods = listOf(ProjectedMethod(ProjectedMethodKind.POSTAL_ADDRESS, "1 High St")))
        val p = projection(scopes = listOf(DIR, Capability.READ_METHOD_POSTAL_ADDRESS), contacts = listOf(c))
        assertEquals(p, parseProjection(buildProjection(p)))
    }

    @Test
    fun `refuses the whole projection, not just the offending contact`() {
        val json = projection().jsonWith(
            "scopes" to jsonStrings(listOf(DIR.wire)),
            "contacts" to jsonArray(
                listOf(
                    jsonObject("contactId" to "a".repeat(32).toJson(), "displayName" to "Fine".toJson()),
                    jsonObject("contactId" to "b".repeat(32).toJson(), "effectiveTier" to "kin".toJson()),
                ),
            ),
        )
        assertNull(parseProjection(json))
    }
}
