package dev.forgesworn.signet.contacts

import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.toJson
import dev.forgesworn.signet.contacts.wire.APP_INVITE_RECEIVE_CAPABILITY
import dev.forgesworn.signet.contacts.wire.APP_INVITE_REQUEST_CAPABILITY
import dev.forgesworn.signet.contacts.wire.AppInviteMode
import dev.forgesworn.signet.contacts.wire.AppInviteReply
import dev.forgesworn.signet.contacts.wire.ContactInvite
import dev.forgesworn.signet.contacts.wire.NostrFilter
import dev.forgesworn.signet.contacts.wire.PairingV2
import dev.forgesworn.signet.contacts.wire.UnsignedNostrEvent
import dev.forgesworn.signet.contacts.wire.appInviteTag
import dev.forgesworn.signet.contacts.wire.parseAppInviteReply
import dev.forgesworn.signet.contacts.wire.parseAppInviteRequest
import dev.forgesworn.signet.contacts.wire.randomHex
import kotlinx.coroutines.delay
import java.util.Collections
import kotlin.coroutines.cancellation.CancellationException

private const val APP_INVITE_KIND = 30078
private const val MAX_REPLY_CONTENT = 16384
private const val MAX_WAIT_MS = 300_000L

/**
 * App introductions over a grant rail. One request at a time per grant. The
 * [relay] must authenticate event signatures. A reply never reveals whether
 * two people actually connected; it acknowledges issuance or queueing only.
 */
public class AppInviteClient(
    private val signer: ContactsSigner,
    private val relay: RelayIo,
    private val now: () -> Long = { System.currentTimeMillis() / 1000 },
    private val elapsedMs: () -> Long = System::currentTimeMillis,
) {
    private val active: MutableSet<String> = Collections.synchronizedSet(HashSet())

    /** Ask Signet to issue an invite for the paired identity. Needs `invites:create`. */
    public suspend fun requestInvite(
        pairing: PairingV2,
        mode: AppInviteMode = AppInviteMode.SINGLE_USE,
        timeoutMs: Long = 120_000,
    ): AppInviteReply? = send(pairing, "create-invite", mode, null, timeoutMs)

    /** Hand an invite to Signet to send a request from the paired identity. Needs `invites:receive`. */
    public suspend fun handOverInvite(pairing: PairingV2, invite: ContactInvite, timeoutMs: Long = 120_000): AppInviteReply? =
        send(pairing, "receive-invite", null, invite, timeoutMs)

    private suspend fun send(
        pairing: PairingV2,
        action: String,
        mode: AppInviteMode?,
        invite: ContactInvite?,
        timeoutMs: Long,
    ): AppInviteReply? {
        val capability = if (action == "create-invite") APP_INVITE_REQUEST_CAPABILITY else APP_INVITE_RECEIVE_CAPABILITY
        if (capability !in pairing.grantedCapabilities || !active.add(pairing.grantId)) return null
        try {
            val draft = jsonObject(
                "v" to 1.toJson(), "grantId" to pairing.grantId.toJson(), "requestId" to randomHex(16).toJson(),
                "createdAt" to now().toJson(), "action" to action.toJson(),
                "mode" to mode?.wire?.toJson(), "invite" to invite?.toJson(),
            )
            val request = parseAppInviteRequest(draft.stringify(), now()) ?: return null
            val content = signer.nip44Encrypt(pairing.railPubkey, request.toJson().stringify())
            val event = signer.signEvent(
                UnsignedNostrEvent(APP_INVITE_KIND, signer.pubkey, request.createdAt, listOf(listOf("d", appInviteTag(pairing.grantId))), content),
            )
            if (!relay.publish(event, listOf(pairing.relay))) return null
            val tag = appInviteTag(pairing.grantId, request.requestId)
            val filter = NostrFilter(kinds = listOf(APP_INVITE_KIND), authors = listOf(pairing.railPubkey), tags = mapOf("#d" to listOf(tag)), limit = 1)
            val deadline = elapsedMs() + minOf(MAX_WAIT_MS, maxOf(0, timeoutMs))
            do {
                val reply = relay.fetchNewest(filter, listOf(pairing.relay), pairing.railPubkey)
                if (reply != null && reply.kind == APP_INVITE_KIND && reply.pubkey == pairing.railPubkey &&
                    reply.content.length <= MAX_REPLY_CONTENT && reply.tags.count { it.firstOrNull() == "d" } == 1 &&
                    reply.tags.any { it.firstOrNull() == "d" && it.getOrNull(1) == tag }
                ) {
                    val plaintext = signer.nip44Decrypt(pairing.railPubkey, reply.content)
                    val result = parseAppInviteReply(plaintext, request, now())
                    if (result != null && result.createdAt == reply.createdAt) return result
                }
                if (elapsedMs() >= deadline) return null
                delay(minOf(1000, deadline - elapsedMs()))
            } while (elapsedMs() <= deadline)
            return null
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            return null
        } finally {
            active.remove(pairing.grantId)
        }
    }
}
