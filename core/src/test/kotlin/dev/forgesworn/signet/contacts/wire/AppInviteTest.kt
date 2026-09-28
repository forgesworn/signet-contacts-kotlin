package dev.forgesworn.signet.contacts.wire

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertNull

private val GRANT_ID = "a".repeat(32)
private val REQUEST_ID = "b".repeat(32)
private val RECIPIENT = "c".repeat(64)
private val SECRET = "d".repeat(64)
private val REQUEST = AppInviteRequest(GRANT_ID, REQUEST_ID, 100, AppInviteAction.CREATE_INVITE, AppInviteMode.SINGLE_USE)
private val INVITE = ContactInvite(RECIPIENT, SECRET, listOf("wss://relay.example/"))
private val REQUEST_JSON = """{"v":1,"grantId":"$GRANT_ID","requestId":"$REQUEST_ID","createdAt":100,"action":"create-invite","mode":"single-use"}"""
private val INVITE_JSON = """{"v":1,"recipient":"$RECIPIENT","secret":"$SECRET","relays":["wss://relay.example/"]}"""

class AppInviteTest {
    @Test
    fun `bounds request lifetime and rejects ambiguous actions`() {
        assertEquals(REQUEST, parseAppInviteRequest(REQUEST_JSON, 100))
        assertNull(parseAppInviteRequest(REQUEST_JSON, 400))
        assertNull(parseAppInviteRequest(REQUEST_JSON, 99))
        val withInvite = """{"v":1,"grantId":"$GRANT_ID","requestId":"$REQUEST_ID","createdAt":100,"action":"create-invite","mode":"single-use","invite":$INVITE_JSON}"""
        assertNull(parseAppInviteRequest(withInvite, 100))
    }

    @Test
    fun `pins replies to request, action and freshness without revealing completion`() {
        val replyJson = """{"v":1,"grantId":"$GRANT_ID","requestId":"$REQUEST_ID","createdAt":101,"status":"issued","invite":$INVITE_JSON}"""
        assertEquals(INVITE, parseAppInviteReply(replyJson, REQUEST, 101)?.invite)
        val otherId = "e".repeat(32)
        val replyWrongRequestId = """{"v":1,"grantId":"$GRANT_ID","requestId":"$otherId","createdAt":101,"status":"issued","invite":$INVITE_JSON}"""
        assertNull(parseAppInviteReply(replyWrongRequestId, REQUEST, 101))
        assertNull(parseAppInviteReply(replyJson, REQUEST, 400))
        val replyComplete = """{"v":1,"grantId":"$GRANT_ID","requestId":"$REQUEST_ID","createdAt":101,"status":"complete","invite":$INVITE_JSON}"""
        assertNull(parseAppInviteReply(replyComplete, REQUEST, 101))
        assertNotEquals(appInviteTag(REQUEST.grantId), appInviteTag(REQUEST.grantId, REQUEST.requestId))
    }
}
