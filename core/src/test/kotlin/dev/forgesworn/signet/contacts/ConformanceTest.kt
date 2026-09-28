package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonArray
import dev.forgesworn.signet.contacts.json.JsonBool
import dev.forgesworn.signet.contacts.json.JsonNull
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonString
import dev.forgesworn.signet.contacts.json.jsonStrings
import dev.forgesworn.signet.contacts.json.toJson
import dev.forgesworn.signet.contacts.wire.AppInviteAction
import dev.forgesworn.signet.contacts.wire.AppInviteMode
import dev.forgesworn.signet.contacts.wire.AppInviteRequest
import dev.forgesworn.signet.contacts.wire.Capability
import dev.forgesworn.signet.contacts.wire.ChannelCheckAcceptance
import dev.forgesworn.signet.contacts.wire.ChannelCheckRequest
import dev.forgesworn.signet.contacts.wire.ChannelCheckReveal
import dev.forgesworn.signet.contacts.wire.ContactAcceptance
import dev.forgesworn.signet.contacts.wire.ContactProjectionV2
import dev.forgesworn.signet.contacts.wire.ContactRequest
import dev.forgesworn.signet.contacts.wire.ContactReveal
import dev.forgesworn.signet.contacts.wire.DirectoryKind
import dev.forgesworn.signet.contacts.wire.MAX_DISPLAY_NAME
import dev.forgesworn.signet.contacts.wire.PairingAckV2
import dev.forgesworn.signet.contacts.wire.PairingCodeInput
import dev.forgesworn.signet.contacts.wire.PairingUriOptionsV2
import dev.forgesworn.signet.contacts.wire.ackTag
import dev.forgesworn.signet.contacts.wire.applyProjection
import dev.forgesworn.signet.contacts.wire.buildPairingAckV2
import dev.forgesworn.signet.contacts.wire.buildPairingUriV2
import dev.forgesworn.signet.contacts.wire.buildProjection
import dev.forgesworn.signet.contacts.wire.buildProposalBatch
import dev.forgesworn.signet.contacts.wire.channelCheckCommitment
import dev.forgesworn.signet.contacts.wire.channelCheckHash
import dev.forgesworn.signet.contacts.wire.channelCheckWords
import dev.forgesworn.signet.contacts.wire.contactCommitment
import dev.forgesworn.signet.contacts.wire.contactMessageHash
import dev.forgesworn.signet.contacts.wire.contactVerificationWords
import dev.forgesworn.signet.contacts.wire.createChannelCheckAcceptance
import dev.forgesworn.signet.contacts.wire.createChannelCheckRequest
import dev.forgesworn.signet.contacts.wire.createChannelCheckReveal
import dev.forgesworn.signet.contacts.wire.createContactAcceptance
import dev.forgesworn.signet.contacts.wire.createContactRequest
import dev.forgesworn.signet.contacts.wire.createContactReveal
import dev.forgesworn.signet.contacts.wire.deriveContactMailboxSecret
import dev.forgesworn.signet.contacts.wire.emptyContactsState
import dev.forgesworn.signet.contacts.wire.isFresh
import dev.forgesworn.signet.contacts.wire.isValidContactsRelayUrl
import dev.forgesworn.signet.contacts.wire.pairingCode
import dev.forgesworn.signet.contacts.wire.parseAppInviteReply
import dev.forgesworn.signet.contacts.wire.parseAppInviteRequest
import dev.forgesworn.signet.contacts.wire.parseChannelCheckMessage
import dev.forgesworn.signet.contacts.wire.parseContactExchangeMessage
import dev.forgesworn.signet.contacts.wire.parseContactInvite
import dev.forgesworn.signet.contacts.wire.parsePairingAckV2
import dev.forgesworn.signet.contacts.wire.parsePairingRequestV2
import dev.forgesworn.signet.contacts.wire.parseProjection
import dev.forgesworn.signet.contacts.wire.parseProposalBatch
import dev.forgesworn.signet.contacts.wire.parseVaultEnvelope
import dev.forgesworn.signet.contacts.wire.projectionTag
import dev.forgesworn.signet.contacts.wire.proposalTag
import dev.forgesworn.signet.contacts.wire.sanitizeWireText
import dev.forgesworn.signet.contacts.wire.visibleContacts
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Every vector file in signet-contacts-conformance, run against this port.
 * The frozen upstream files are checked byte for byte where the reference
 * checks them byte for byte; the generated `cases/` files compare parsed
 * shapes structurally.
 */
class ConformanceTest {
    @Test
    fun `manifest hashes match the files on disk`() {
        val manifest = Vectors.load("manifest.json")
        val files = manifest["files"] as JsonObject
        val m = Mismatches("manifest.json")
        for ((path, sha) in files.fields) {
            val file = File(Vectors.dir.parentFile, path)
            val actual = MessageDigest.getInstance("SHA-256").digest(file.readBytes()).joinToString("") { "%02x".format(it) }
            m.checkEquals(path, sha.string, actual)
        }
        m.done()
        // Every vector file is listed, so a new one cannot be silently skipped by a port.
        val onDisk = (Vectors.dir.listFiles()!!.filter { it.name.endsWith(".json") && it.name != "manifest.json" }.map { "vectors/${it.name}" } +
            File(Vectors.dir, "cases").listFiles()!!.filter { it.name.endsWith(".json") }.map { "vectors/cases/${it.name}" }).toSet()
        assertEquals(onDisk, files.fields.keys)
    }

    // ------------------------------------------------------------------
    // Upstream frozen vectors
    // ------------------------------------------------------------------

    @Test
    fun `pairing v2`() {
        val v = Vectors.load("pairing.v2.json")
        val now = v["nowSec"].long
        val parsed = v["request"]["parsed"]
        val uri = buildPairingUriV2(
            PairingUriOptionsV2(
                parsed["appPubkey"].string, parsed["appName"].string,
                parsed["capabilities"].items.map { Capability.fromWire(it.string)!! },
                DirectoryKind.fromWire(parsed["directory"].string)!!, parsed["rendezvousRelay"].string, now, parsed["challenge"].string,
            ),
        )
        assertEquals(v["request"]["uri"].string, uri)
        assertEquals(parsed, parsePairingRequestV2(uri, now).request!!.toJson())

        val ack = v["ack"]
        val challenge = ack["parsed"]["challenge"].string
        val parsedAck = parsePairingAckV2(ack["plaintext"].string, challenge)!!
        assertEquals(ack["parsed"], parsedAck.toJson())
        assertEquals(ack["plaintext"].string, buildPairingAckV2(parsedAck))
        assertEquals(null, parsePairingAckV2(ack["v1Plaintext"].string, challenge))
        assertEquals(null, parsePairingAckV2(ack["plaintext"].string, ack["wrongChallenge"].string))

        val tags = v["tags"]
        assertEquals(tags["projectionTag"].string, projectionTag(parsedAck.grantId))
        assertEquals(tags["proposalTag"].string, proposalTag(parsedAck.grantId, parsed["appPubkey"].string))
        assertEquals(tags["ackTag"].string, ackTag(challenge))
    }

    @Test
    fun `projection v2`() {
        val v = Vectors.load("projection.v2.json")
        for (name in listOf("full", "blocksOnly", "revocation", "truncated")) {
            val plaintext = v[name]["plaintext"].string
            val parsed = parseProjection(plaintext)!!
            assertEquals(v[name]["parsed"], parsed.toJson(), name)
            assertEquals(plaintext, buildProjection(parsed), name)
        }
        // Not all of `malformed` is refused: what each returns is in cases/upstream-malformed.json.
        v["uncovered"].items.forEach { assertEquals(null, parseProjection(it["plaintext"].string), it["reason"].string) }
    }

    @Test
    fun `proposal v1`() {
        val v = Vectors.load("proposal.v1.json")
        val batch = parseProposalBatch(v["batch"]["plaintext"].string)!!
        assertEquals(v["batch"]["parsed"], batch.toJson())
        assertEquals(v["batch"]["plaintext"].string, buildProposalBatch(batch.proposals))
    }

    @Test
    fun sanitise() {
        val v = Vectors.load("sanitise.json")
        val max = v["maxLen"].long.toInt()
        assertEquals(MAX_DISPLAY_NAME, max)
        val m = Mismatches("sanitise.json")
        v["pairs"].items.forEach { m.checkEquals(it["input"].string, it["output"].string, sanitizeWireText(it["input"].string, max)) }
        m.done()
    }

    @Test
    fun `pairing code`() {
        val v = Vectors.load("pairing-code.json")
        val m = Mismatches("pairing-code.json")
        for (c in v["cases"].items) {
            val i = c["input"]
            val code = pairingCode(PairingCodeInput(i["appPubkey"].string, i["challenge"].string, i["grantId"].string, i["railPubkey"].string))
            m.checkEquals(c["description"].string, c["code"].string, code)
        }
        m.done()
    }

    @Test
    fun `contact invite v1`() {
        val v = Vectors.load("contact-invite-v1.json")
        val request = parseContactExchangeMessage(v["request"]!!.stringify()) as ContactRequest
        val acceptance = parseContactExchangeMessage(v["acceptance"]!!.stringify()) as ContactAcceptance
        val reveal = parseContactExchangeMessage(v["reveal"]!!.stringify()) as ContactReveal
        val mailbox = deriveContactMailboxSecret(v["inviteSecret"].string)
        assertEquals(v["mailboxPrivateKey"].string, mailbox.joinToString("") { "%02x".format(it) })
        assertEquals(v["commitment"].string, request.commitment)
        assertEquals(v["commitment"].string, contactCommitment(request.id, request.from, request.to, reveal.nonce))
        assertEquals(v["requestHash"].string, contactMessageHash(request))
        assertEquals(v["acceptanceHash"].string, contactMessageHash(acceptance))

        // Rebuild the transcript from its inputs and compare.
        val rebuilt = createContactRequest(request.id, request.from, request.to, reveal.nonce, request.reply, request.createdAt, request.expiresAt)
        assertEquals(request, rebuilt)
        assertEquals(acceptance, createContactAcceptance(request, acceptance.nonce, acceptance.createdAt))
        assertEquals(reveal, createContactReveal(request, acceptance, reveal.nonce, reveal.createdAt))

        val words = contactVerificationWords(request, acceptance, reveal, request.from)
        assertEquals(v["requesterWords"]["youSay"].string, words.youSay)
        assertEquals(v["requesterWords"]["theySay"].string, words.theySay)
        val theirs = contactVerificationWords(request, acceptance, reveal, request.to)
        assertEquals(words.youSay, theirs.theySay)
        assertEquals(words.theySay, theirs.youSay)
    }

    @Test
    fun `channel check v1`() {
        val v = Vectors.load("channel-check-v1.json")
        val request = parseChannelCheckMessage(v["request"]!!.stringify()) as ChannelCheckRequest
        val acceptance = parseChannelCheckMessage(v["acceptance"]!!.stringify()) as ChannelCheckAcceptance
        val reveal = parseChannelCheckMessage(v["reveal"]!!.stringify()) as ChannelCheckReveal
        assertEquals(v["requestHash"].string, channelCheckHash(request))
        assertEquals(v["acceptanceHash"].string, channelCheckHash(acceptance))
        assertEquals(request.commitment, channelCheckCommitment(request.id, request.context, request.from, request.to, reveal.nonce))
        assertEquals(request, createChannelCheckRequest(request.id, request.context, request.from, request.to, reveal.nonce, request.createdAt))
        assertEquals(acceptance, createChannelCheckAcceptance(request, acceptance.nonce, acceptance.createdAt))
        assertEquals(reveal, createChannelCheckReveal(request, acceptance, reveal.nonce, reveal.createdAt))
        val words = channelCheckWords(request, acceptance, reveal, request.from)
        assertEquals(v["requesterWords"]["youSay"].string, words.youSay)
        assertEquals(v["requesterWords"]["theySay"].string, words.theySay)
    }

    @Test
    fun `envelope v2 framing`() {
        // The crypto half of this vector runs in the nostr module, with real NIP-44.
        val v = Vectors.load("envelope.v2.json")
        assertEquals(v["parsed"], parseVaultEnvelope(v["sealed"].string)!!.toJson())
    }

    // ------------------------------------------------------------------
    // Generated cases
    // ------------------------------------------------------------------

    @Test
    fun `cases - upstream malformed`() {
        val v = Vectors.load("cases/upstream-malformed.json")
        val m = Mismatches("cases/upstream-malformed.json")
        for (c in v["projection"].items) m.check(c["plaintext"].string, c["expected"], parseProjection(c["plaintext"].string)?.toJson())
        for (c in v["proposal"].items) m.check(c["plaintext"].string, c["expected"], parseProposalBatch(c["plaintext"].string)?.toJson())
        m.done()
    }

    @Test
    fun `cases - relay url`() {
        val m = Mismatches("cases/relay-url.json")
        for (c in Vectors.load("cases/relay-url.json")["cases"].items) {
            m.checkEquals(c["input"].string, (c["valid"] as JsonBool).value, isValidContactsRelayUrl(c["input"].string))
        }
        m.done()
    }

    @Test
    fun `cases - pairing uri`() {
        val v = Vectors.load("cases/pairing-uri.json")
        val now = v["nowSec"].long
        val m = Mismatches("cases/pairing-uri.json")
        for (c in v["cases"].items) m.check(c["name"].string, c["expected"], parsePairingRequestV2(c["input"].string, now).toJson())
        m.done()
    }

    @Test
    fun `cases - ack`() {
        val v = Vectors.load("cases/ack.json")
        val challenge = v["expectedChallenge"].string
        val m = Mismatches("cases/ack.json")
        for (c in v["cases"].items) m.check(c["name"].string, c["expected"], parsePairingAckV2(c["plaintext"].string, challenge)?.toJson())
        m.done()
    }

    @Test
    fun `cases - projection parse`() {
        val m = Mismatches("cases/projection-parse.json")
        for (c in Vectors.load("cases/projection-parse.json")["cases"].items) {
            m.check(c["name"].string, c["expected"], parseProjection(c["plaintext"].string)?.toJson())
        }
        m.done()
    }

    @Test
    fun `cases - projection build`() {
        val m = Mismatches("cases/projection-build.json")
        for (c in Vectors.load("cases/projection-build.json")["cases"].items) {
            val input: ContactProjectionV2 = parseProjection(c["input"])!!
            val expected = c["built"]
            val actual = runCatching { buildProjection(input) }
            if (expected["throws"] != null) {
                m.checkEquals(c["name"].string, "throws", if (actual.isFailure) "throws" else actual.getOrNull())
            } else {
                m.checkEquals(c["name"].string, expected["value"].string, actual.getOrElse { "threw: $it" })
            }
        }
        m.done()
    }

    @Test
    fun `cases - proposal parse`() {
        val m = Mismatches("cases/proposal-parse.json")
        for (c in Vectors.load("cases/proposal-parse.json")["cases"].items) {
            m.check(c["name"].string, c["expected"], parseProposalBatch(c["plaintext"].string)?.toJson())
        }
        m.done()
    }

    @Test
    fun `cases - invite`() {
        val v = Vectors.load("cases/invite.json")
        val now = v["now"].long
        val m = Mismatches("cases/invite.json")
        for (c in v["cases"].items) m.check(c["name"].string, c["expected"], parseContactInvite(c["raw"].string, now)?.toJson())
        m.done()
    }

    @Test
    fun `cases - contact exchange`() {
        val m = Mismatches("cases/contact-exchange.json")
        for (c in Vectors.load("cases/contact-exchange.json")["cases"].items) {
            val parsed = parseContactExchangeMessage(c["raw"].string)
            m.check(c["name"].string, c["expected"], parsed?.toJson())
            m.check("${c["name"].string} (hash)", c["hash"], parsed?.let { contactMessageHash(it).toJson() })
        }
        m.done()
    }

    @Test
    fun `cases - stringify`() {
        val m = Mismatches("cases/stringify.json")
        for (c in Vectors.load("cases/stringify.json")["cases"].items) {
            m.checkEquals(c["input"].string, c["output"].string, Json.parse(c["input"].string).stringify())
        }
        m.done()
    }

    @Test
    fun `cases - envelope parse`() {
        val m = Mismatches("cases/envelope-parse.json")
        for (c in Vectors.load("cases/envelope-parse.json")["cases"].items) {
            m.check(c["name"].string, c["expected"], parseVaultEnvelope(c["content"].string)?.toJson())
        }
        m.done()
    }

    @Test
    fun `cases - state`() {
        val m = Mismatches("cases/state.json")
        var state = emptyContactsState()
        for (step in Vectors.load("cases/state.json")["steps"].items) {
            val name = step["name"].string
            val projection = parseProjection(step["projection"]) ?: error("$name: step projection does not parse")
            val now = step["nowSec"].long
            val next = applyProjection(state, projection, now)
            m.checkEquals("$name (accepted)", (step["accepted"] as JsonBool).value, next !== state)
            m.check("$name (state)", step["state"], next.toJson())
            m.checkEquals("$name (fresh)", (step["fresh"] as JsonBool).value, isFresh(next, now))
            m.check("$name (visible)", step["visible"], jsonStrings(visibleContacts(next).map { it.contactId }))
            state = next
        }
        m.done()
    }

    @Test
    fun `cases - app invite`() {
        val v = Vectors.load("cases/app-invite.json")
        val m = Mismatches("cases/app-invite.json")
        for (c in v["requests"].items) {
            m.check(c["name"].string, c["expected"], parseAppInviteRequest(c["json"].string, c["now"].long)?.toJson())
        }
        for (c in v["replies"].items) {
            val r = c["request"]
            val request = AppInviteRequest(
                r["grantId"].string, r["requestId"].string, r["createdAt"].long,
                if (r["action"].string == "create-invite") AppInviteAction.CREATE_INVITE else AppInviteAction.RECEIVE_INVITE,
                r["mode"]?.let { AppInviteMode.fromWire(it.string) },
                r["invite"]?.let { parseContactInvite(it.stringify()) },
            )
            m.check(c["name"].string, c["expected"], parseAppInviteReply(c["json"].string, request, c["now"].long)?.toJson())
        }
        m.done()
    }

    @Test
    fun `vector files carry no raw non-ASCII or control bytes`() {
        val files = Vectors.dir.walkTopDown().filter { it.isFile && it.name.endsWith(".json") }.toList()
        assertTrue(files.isNotEmpty())
        for (f in files) {
            f.readBytes().forEachIndexed { i, b ->
                val u = b.toInt() and 0xff
                assertTrue(u < 0x7f && (u >= 0x20 || u == 0x09 || u == 0x0a || u == 0x0d), "${f.name} byte $i is 0x${u.toString(16)}")
            }
        }
    }

}
