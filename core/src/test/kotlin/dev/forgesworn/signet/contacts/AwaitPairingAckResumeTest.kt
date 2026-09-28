package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.wire.ACK_STORED_KIND
import dev.forgesworn.signet.contacts.wire.Capability
import dev.forgesworn.signet.contacts.wire.PAIRING_FRESHNESS_SECONDS
import dev.forgesworn.signet.contacts.wire.PairingAckV2
import dev.forgesworn.signet.contacts.wire.buildPairingAckV2
import dev.forgesworn.signet.contacts.wire.projectionTag
import dev.forgesworn.signet.contacts.wire.proposalTag
import dev.forgesworn.signet.contacts.wire.storedAckEventTemplate
import kotlinx.coroutines.async
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * client.test.ts: "resumes from a frozen/late timer and still finds a stored
 * ack that arrived while suspended". The wall clock ([SignetContactsClient]'s
 * `now` and `elapsedMs`) jumps past the whole pairing window while the
 * pending poll timer has not fired, the way a suspended app's clock runs on
 * while its timers do not. When the timer does fire, the loop must poll once
 * more before its deadline check, and find the ack.
 */
class AwaitPairingAckResumeTest {
    @Test
    fun `resumes from a frozen or late timer and still finds a stored ack that arrived while suspended`() {
        val scope = TestScope(StandardTestDispatcher())
        scope.runTest {
            var wallMs = 1_700_000_000_000L
            val signer = FakeSigner()
            val ackPlain = buildPairingAckV2(
                PairingAckV2(
                    GRANT, RAIL, projectionTag(GRANT), proposalTag(GRANT, APP), RELAYS[0],
                    listOf(Capability.READ_DIRECTORY), 21600, CHALLENGE,
                ),
            )
            val content = signer.nip44Encrypt(APP, ackPlain)
            var ackAvailable = false
            val relay = FakeRelay().apply {
                fetchNewestImpl = { filter, _, _ ->
                    if (!ackAvailable || filter.kinds?.contains(ACK_STORED_KIND) != true) {
                        null
                    } else {
                        asSigned(
                            storedAckEventTemplate("9".repeat(64), APP, wallMs / 1000, content, CHALLENGE),
                            "4".repeat(64), "5".repeat(128),
                        )
                    }
                }
            }
            val client = SignetContactsClient(
                signer = signer, relay = relay, now = { wallMs / 1000 }, elapsedMs = { wallMs }, scope = this,
            )
            val pollMs = 10_000L
            val waiting = async { client.awaitPairingAck(CHALLENGE, RELAYS, pollMs = pollMs) }
            runCurrent() // the first, immediate poll pass; the loop is now asleep

            // Suspended: the wall clock runs far past the default deadline,
            // no timer fires, and the ack arrives meanwhile.
            wallMs += 2 * PAIRING_FRESHNESS_SECONDS * 1000 + 60_000
            ackAvailable = true

            // The overdue timer fires on resume.
            advanceTimeBy(pollMs + 1)
            assertEquals(GRANT, waiting.await()?.grantId)
        }
    }
}
