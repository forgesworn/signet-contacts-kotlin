package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonArray
import dev.forgesworn.signet.contacts.json.JsonNull
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.jsonStrings
import dev.forgesworn.signet.contacts.json.toJson
import dev.forgesworn.signet.contacts.wire.PairingAckV2
import dev.forgesworn.signet.contacts.wire.PairingRequestV2
import dev.forgesworn.signet.contacts.wire.PairingRequestV2Result
import dev.forgesworn.signet.contacts.wire.ProposalBatch
import java.io.File
import kotlin.test.fail

/**
 * Loads the language-neutral vectors from the signet-contacts-conformance
 * checkout named by the `signetContacts.vectors` system property (set by the
 * Gradle build from `-PsignetContactsVectors`). A missing checkout is a hard
 * failure, never a skip: a build that did not run conformance must not pass.
 */
object Vectors {
    val dir: File by lazy {
        val path = System.getProperty("signetContacts.vectors")
            ?: fail("signetContacts.vectors is not set; run the tests through Gradle")
        File(path).also {
            if (!File(it, "manifest.json").isFile) {
                fail("no conformance vectors at $path: check out signet-contacts-conformance beside this repository or pass -PsignetContactsVectors=<dir>")
            }
        }
    }

    fun load(name: String): JsonObject = Json.parse(File(dir, name).readText()) as JsonObject
}

operator fun JsonValue?.get(key: String): JsonValue? = (this as? JsonObject)?.get(key)
val JsonValue?.string: String get() = (this as dev.forgesworn.signet.contacts.json.JsonString).value
val JsonValue?.long: Long get() = (this as dev.forgesworn.signet.contacts.json.JsonNumber).value.toLong()
val JsonValue?.items: List<JsonValue> get() = (this as JsonArray).items

/** Collects every mismatch in a vector file, so one run reports them all. */
class Mismatches(private val file: String) {
    private val found = ArrayList<String>()

    fun check(name: String, expected: JsonValue?, actual: JsonValue?) {
        val e = expected ?: JsonNull
        val a = actual ?: JsonNull
        if (e != a) found.add("$name\n    expected: ${e.stringify()}\n    actual:   ${a.stringify()}")
    }

    fun checkEquals(name: String, expected: Any?, actual: Any?) {
        if (expected != actual) found.add("$name\n    expected: $expected\n    actual:   $actual")
    }

    fun done() {
        if (found.isNotEmpty()) fail("$file: ${found.size} conformance mismatch(es)\n  " + found.joinToString("\n  "))
    }
}

// The reference's object shapes, for comparing against `expected` values.

fun PairingRequestV2.toJson(): JsonObject = jsonObject(
    "v" to 2.toJson(), "appPubkey" to appPubkey.toJson(), "appName" to appName.toJson(),
    "capabilities" to jsonStrings(capabilities.map { it.wire }), "directory" to directory.wire.toJson(),
    "rendezvousRelay" to rendezvousRelay.toJson(), "t" to t.toJson(), "challenge" to challenge.toJson(),
)

fun PairingRequestV2Result.toJson(): JsonObject =
    jsonObject("request" to (request?.toJson() ?: JsonNull), "warnings" to jsonStrings(warnings))

fun PairingAckV2.toJson(): JsonObject = jsonObject(
    "v" to 2.toJson(), "grantId" to grantId.toJson(), "railPubkey" to railPubkey.toJson(),
    "projectionTag" to projectionTag.toJson(), "proposalTag" to proposalTag.toJson(), "relay" to relay.toJson(),
    "grantedCapabilities" to jsonStrings(grantedCapabilities.map { it.wire }),
    "maxStalenessSeconds" to maxStalenessSeconds.toJson(), "challenge" to challenge.toJson(),
)

fun ProposalBatch.toJson(): JsonObject =
    jsonObject("v" to 1.toJson(), "proposals" to JsonArray(proposals.map { it.toJson() }))
