package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.MAX_SAFE_INTEGER_LONG
import dev.forgesworn.signet.contacts.json.isNumber
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.nonNegativeSafeLong
import dev.forgesworn.signet.contacts.json.str
import dev.forgesworn.signet.contacts.json.toJson

/**
 * App-introduction transport (v1, WIRE.md "App introductions"). The `d` tags
 * are readable; each grant has one outstanding request slot. Payloads are
 * NIP-44 between the app key and its grant rail. Replies acknowledge
 * issuance or queueing only, never connection completion.
 */

public const val APP_INVITE_REQUEST_SECONDS: Long = 300
public val APP_INVITE_REQUEST_CAPABILITY: Capability = Capability.INVITES_CREATE
public val APP_INVITE_RECEIVE_CAPABILITY: Capability = Capability.INVITES_RECEIVE
private const val MAX_APP_INVITE_JSON = 8192

public enum class AppInviteAction(public val wire: String) { CREATE_INVITE("create-invite"), RECEIVE_INVITE("receive-invite") }

public enum class AppInviteMode(public val wire: String) {
    SINGLE_USE("single-use"), STANDING("standing");

    public companion object {
        public fun fromWire(value: String?): AppInviteMode? = entries.firstOrNull { it.wire == value }
    }
}

public enum class AppInviteStatus(public val wire: String) { ISSUED("issued"), QUEUED("queued") }

public data class AppInviteRequest(
    val grantId: String,
    val requestId: String,
    val createdAt: Long,
    val action: AppInviteAction,
    val mode: AppInviteMode? = null,
    val invite: ContactInvite? = null,
) {
    public val v: Int get() = 1

    public fun toJson(): JsonObject = jsonObject(
        "v" to 1.toJson(), "grantId" to grantId.toJson(), "requestId" to requestId.toJson(),
        "createdAt" to createdAt.toJson(), "action" to action.wire.toJson(),
        "mode" to mode?.wire?.toJson(), "invite" to invite?.toJson(),
    )
}

public data class AppInviteReply(
    val grantId: String,
    val requestId: String,
    val createdAt: Long,
    val status: AppInviteStatus,
    val invite: ContactInvite? = null,
) {
    public val v: Int get() = 1

    public fun toJson(): JsonObject = jsonObject(
        "v" to 1.toJson(), "grantId" to grantId.toJson(), "requestId" to requestId.toJson(),
        "createdAt" to createdAt.toJson(), "status" to status.wire.toJson(), "invite" to invite?.toJson(),
    )
}

private fun stamp(n: Long): Boolean = n in 0..MAX_SAFE_INTEGER_LONG

private class Base(val grantId: String, val requestId: String, val createdAt: Long, val o: JsonObject)

private fun base(json: String): Base? {
    val o = Json.parseOrNull(json) as? JsonObject ?: return null
    if (!o["v"].isNumber(1) || !isHex(o["grantId"], 32) || !isHex(o["requestId"], 32)) return null
    val createdAt = o["createdAt"].nonNegativeSafeLong() ?: return null
    return Base(o["grantId"].str()!!, o["requestId"].str()!!, createdAt, o)
}

public fun parseAppInviteRequest(json: String, now: Long): AppInviteRequest? {
    if (json.length > MAX_APP_INVITE_JSON || !stamp(now)) return null
    val b = base(json) ?: return null
    if (b.createdAt > now || b.createdAt + APP_INVITE_REQUEST_SECONDS <= now) return null
    val action = b.o["action"].str()
    val modeRaw = b.o["mode"]
    val inviteRaw = b.o["invite"]
    if (action == "create-invite" && inviteRaw == null) {
        val mode = AppInviteMode.fromWire(modeRaw.str()) ?: return null
        return AppInviteRequest(b.grantId, b.requestId, b.createdAt, AppInviteAction.CREATE_INVITE, mode = mode)
    }
    if (action == "receive-invite" && modeRaw == null && inviteRaw != null) {
        val invite = parseContactInvite(inviteRaw.stringify(), now) ?: return null
        return AppInviteRequest(b.grantId, b.requestId, b.createdAt, AppInviteAction.RECEIVE_INVITE, invite = invite)
    }
    return null
}

public fun parseAppInviteReply(json: String, request: AppInviteRequest, now: Long): AppInviteReply? {
    if (json.length > MAX_APP_INVITE_JSON || !stamp(now)) return null
    val b = base(json) ?: return null
    if (b.grantId != request.grantId || b.requestId != request.requestId || b.createdAt < request.createdAt ||
        b.createdAt > now || now >= request.createdAt + APP_INVITE_REQUEST_SECONDS
    ) return null
    val status = b.o["status"].str()
    val inviteRaw = b.o["invite"]
    if (request.action == AppInviteAction.RECEIVE_INVITE && status == "queued" && inviteRaw == null) {
        return AppInviteReply(b.grantId, b.requestId, b.createdAt, AppInviteStatus.QUEUED)
    }
    if (request.action == AppInviteAction.CREATE_INVITE && status == "issued" && inviteRaw != null) {
        val invite = parseContactInvite(inviteRaw.stringify(), now) ?: return null
        return AppInviteReply(b.grantId, b.requestId, b.createdAt, AppInviteStatus.ISSUED, invite)
    }
    return null
}

/** The readable `d` tag of a grant's request slot, or of one reply to it. */
public fun appInviteTag(grantId: String, replyId: String? = null): String {
    require(isHex(grantId, 32) && (replyId == null || isHex(replyId, 32))) { "Invalid app invite id" }
    return "signet:contacts:app-invite:$grantId${if (replyId != null) ":$replyId" else ""}"
}
