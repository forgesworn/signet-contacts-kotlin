package dev.forgesworn.signet.contacts.wire

import dev.forgesworn.signet.contacts.json.JsonArray
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonValue
import dev.forgesworn.signet.contacts.json.Json
import dev.forgesworn.signet.contacts.json.arr
import dev.forgesworn.signet.contacts.json.jsonArray
import dev.forgesworn.signet.contacts.json.jsonObject
import dev.forgesworn.signet.contacts.json.jsonStrings
import dev.forgesworn.signet.contacts.json.nonNegativeSafeLong
import dev.forgesworn.signet.contacts.json.num
import dev.forgesworn.signet.contacts.json.str
import dev.forgesworn.signet.contacts.json.toJson

/**
 * Contacts app-access wire v2 - type surface. Every shape here is a WIRE shape,
 * with one documented exception ([PairingV2.pairedAt]). `toJson()` emits each
 * shape with its keys in the order the TypeScript reference's parser builds
 * them, which is the order every digest and frozen vector is taken over.
 */

public enum class DirectoryKind(public val wire: String) {
    OWNER("owner"), DEPENDANT("dependant");

    public companion object {
        public fun fromWire(value: String?): DirectoryKind? = entries.firstOrNull { it.wire == value }
    }
}

public enum class ProjectedTier(public val wire: String) {
    KIN("kin"), KITH("kith"), KEN("ken"), NONE("none");

    public companion object {
        public fun fromWire(value: String?): ProjectedTier? = entries.firstOrNull { it.wire == value }
    }
}

public enum class ProjectedTierSource(public val wire: String) {
    DIRECT("direct"), GUARDIAN_VOUCHED("guardian-vouched"), GUARDIAN_LIMITED("guardian-limited");

    public companion object {
        public fun fromWire(value: String?): ProjectedTierSource? = entries.firstOrNull { it.wire == value }
    }
}

public enum class ProjectedType(public val wire: String) {
    PERSON("person"), ORGANISATION("organisation");

    public companion object {
        public fun fromWire(value: String?): ProjectedType? = entries.firstOrNull { it.wire == value }
    }
}

public enum class ProjectedVerification(public val wire: String) {
    UNVERIFIED("unverified"), PROVEN("proven"), MUTUAL("mutual");

    public companion object {
        public fun fromWire(value: String?): ProjectedVerification? = entries.firstOrNull { it.wire == value }
    }
}

/** A contact method's verification: `mutual` is not a value a method can carry. */
public enum class MethodVerification(public val wire: String) {
    UNVERIFIED("unverified"), PROVEN("proven");

    public companion object {
        public fun fromWire(value: String?): MethodVerification? = entries.firstOrNull { it.wire == value }
    }
}

public enum class ProjectedMethodKind(public val wire: String) {
    PHONE("phone"), EMAIL("email"), WEBSITE("website"), POSTAL_ADDRESS("postal-address"), OTHER("other");

    public companion object {
        public fun fromWire(value: String?): ProjectedMethodKind? = entries.firstOrNull { it.wire == value }
    }
}

public enum class CheckMethod(public val wire: String) {
    WORDS("words"), IN_PERSON("in-person"), NIP05("nip05"), APP_ATTESTED("app-attested");

    public companion object {
        public fun fromWire(value: String?): CheckMethod? = entries.firstOrNull { it.wire == value }
    }
}

// ---------------------------------------------------------------------------
// Minimal Nostr shapes, so the wire layer depends on no Nostr library.
// ---------------------------------------------------------------------------

public data class UnsignedNostrEvent(
    val kind: Int,
    val pubkey: String,
    val createdAt: Long,
    val tags: List<List<String>>,
    val content: String,
)

public data class SignedNostrEvent(
    val id: String,
    val kind: Int,
    val pubkey: String,
    val createdAt: Long,
    val tags: List<List<String>>,
    val content: String,
    val sig: String,
) {
    public fun toJson(): JsonObject = jsonObject(
        "id" to id.toJson(), "pubkey" to pubkey.toJson(), "created_at" to createdAt.toJson(),
        "kind" to kind.toJson(), "tags" to jsonArray(tags.map(::jsonStrings)),
        "content" to content.toJson(), "sig" to sig.toJson(),
    )

    public companion object {
        /** The NIP-01 JSON form, shape-checked; null for anything malformed. */
        public fun fromJson(value: JsonValue?): SignedNostrEvent? {
            val o = value as? JsonObject ?: return null
            val id = o["id"].str() ?: return null
            val pubkey = o["pubkey"].str() ?: return null
            val sig = o["sig"].str() ?: return null
            val content = o["content"].str() ?: return null
            val kind = o["kind"].nonNegativeSafeLong()?.takeIf { it <= Int.MAX_VALUE } ?: return null
            val createdAt = o["created_at"].nonNegativeSafeLong() ?: return null
            val tags = o["tags"].arr()?.map { tag -> tag.arr()?.map { it.str() ?: return null } ?: return null } ?: return null
            return SignedNostrEvent(id, kind.toInt(), pubkey, createdAt, tags, content, sig)
        }
    }
}

/**
 * A NIP-01 filter. [tags] holds the tag queries keyed with their `#` prefix,
 * e.g. `"#d"` to a list of values.
 */
public data class NostrFilter(
    val kinds: List<Int>? = null,
    val authors: List<String>? = null,
    val limit: Int? = null,
    val until: Long? = null,
    val since: Long? = null,
    val tags: Map<String, List<String>> = emptyMap(),
) {
    public fun toJson(): JsonObject {
        val fields = LinkedHashMap<String, JsonValue>()
        kinds?.let { fields["kinds"] = JsonArray(it.map { k -> k.toJson() }) }
        authors?.let { fields["authors"] = jsonStrings(it) }
        for ((k, v) in tags) fields[k] = jsonStrings(v)
        since?.let { fields["since"] = it.toJson() }
        until?.let { fields["until"] = it.toJson() }
        limit?.let { fields["limit"] = it.toJson() }
        return JsonObject(fields)
    }
}

// ---------------------------------------------------------------------------
// Pairing
// ---------------------------------------------------------------------------

public data class PairingUriOptionsV2(
    val appPubkey: String,
    val appName: String,
    val capabilities: List<Capability>,
    val directory: DirectoryKind,
    val relay: String,
    val nowSec: Long,
    val challenge: String,
)

public data class PairingRequestV2(
    val appPubkey: String,
    val appName: String,
    val capabilities: List<Capability>,
    val directory: DirectoryKind,
    val rendezvousRelay: String,
    val t: Long,
    val challenge: String,
) {
    public val v: Int get() = 2
}

public data class PairingRequestV2Result(val request: PairingRequestV2?, val warnings: List<String>)

public data class PairingAckV2(
    val grantId: String,
    val railPubkey: String,
    val projectionTag: String,
    val proposalTag: String,
    val relay: String,
    val grantedCapabilities: List<Capability>,
    val maxStalenessSeconds: Long,
    val challenge: String,
) {
    public val v: Int get() = 2
}

/** Consumer-side persisted pairing. [pairedAt] is local metadata, never wire. */
public data class PairingV2(
    val grantId: String,
    val railPubkey: String,
    val projectionTag: String,
    val proposalTag: String,
    val relay: String,
    val grantedCapabilities: List<Capability>,
    val maxStalenessSeconds: Long,
    val pairedAt: Long,
) {
    /** Plain JSON for the app's own persistence. */
    public fun toJson(): JsonObject = jsonObject(
        "grantId" to grantId.toJson(), "railPubkey" to railPubkey.toJson(),
        "projectionTag" to projectionTag.toJson(), "proposalTag" to proposalTag.toJson(),
        "relay" to relay.toJson(), "grantedCapabilities" to jsonStrings(grantedCapabilities.map { it.wire }),
        "maxStalenessSeconds" to maxStalenessSeconds.toJson(), "pairedAt" to pairedAt.toJson(),
    )

    public companion object {
        /** Reads back what [toJson] wrote, re-validating it as the ack parser would. */
        public fun fromJson(text: String): PairingV2? {
            val o = Json.parseOrNull(text) as? JsonObject ?: return null
            val grantId = o["grantId"].str()?.takeIf { isHex(it, 32) } ?: return null
            val rail = o["railPubkey"].str()?.takeIf { isHex(it, 64) } ?: return null
            val pTag = o["projectionTag"].str()?.takeIf { isHex(it, 32) } ?: return null
            val qTag = o["proposalTag"].str()?.takeIf { isHex(it, 32) } ?: return null
            val relay = o["relay"].str()?.takeIf { isValidContactsRelayUrl(it) } ?: return null
            val caps = normaliseCapabilities(o["grantedCapabilities"].arr().orEmpty().mapNotNull { it.str()?.let(Capability::fromWire) })
            if (caps.isEmpty()) return null
            val pairedAt = o["pairedAt"].nonNegativeSafeLong() ?: return null
            return PairingV2(grantId, rail, pTag, qTag, relay, caps, clampStaleness(o["maxStalenessSeconds"].num()), pairedAt)
        }
    }
}

// ---------------------------------------------------------------------------
// Projection
// ---------------------------------------------------------------------------

public data class ProjectedIdentity(val pubkey: String, val verification: ProjectedVerification? = null) {
    public fun toJson(): JsonObject = jsonObject("pubkey" to pubkey.toJson(), "verification" to verification?.wire?.toJson())
}

public data class ProjectedMethod(
    val kind: ProjectedMethodKind,
    val value: String,
    val verification: MethodVerification? = null,
) {
    public fun toJson(): JsonObject = jsonObject(
        "kind" to kind.wire.toJson(), "value" to value.toJson(), "verification" to verification?.wire?.toJson(),
    )
}

public data class ProjectedAvatar(val url: String, val hash: String, val key: String? = null) {
    public fun toJson(): JsonObject = jsonObject("url" to url.toJson(), "hash" to hash.toJson(), "key" to key?.toJson())
}

public data class ProjectedCheck(val pubkey: String, val method: CheckMethod, val checkedAt: Long) {
    public fun toJson(): JsonObject = jsonObject(
        "pubkey" to pubkey.toJson(), "method" to method.wire.toJson(), "checkedAt" to checkedAt.toJson(),
    )
}

public data class ProjectedContact(
    /** Grant-scoped opaque id, 32 lowercase hex. */
    val contactId: String,
    /** Legacy. No capability covers it, so a projection carrying it is refused. */
    val type: ProjectedType? = null,
    /** Present only with read:tier. Absence is not Ken. */
    val effectiveTier: ProjectedTier? = null,
    val tierSource: ProjectedTierSource? = null,
    /** Present only with blocks.read. Absence says nothing about block state. */
    val blocked: Boolean? = null,
    val identities: List<ProjectedIdentity>? = null,
    val displayName: String? = null,
    val avatar: ProjectedAvatar? = null,
    val roles: List<String>? = null,
    val contactMethods: List<ProjectedMethod>? = null,
    /** Method/date only, with explicit read:check-records consent. */
    val checks: List<ProjectedCheck>? = null,
    /** Legacy. No capability covers it, so a projection carrying it is refused. */
    val linkedPubkeys: List<String>? = null,
) {
    public fun toJson(): JsonObject = jsonObject(
        "contactId" to contactId.toJson(),
        "type" to type?.wire?.toJson(),
        "effectiveTier" to effectiveTier?.wire?.toJson(),
        "tierSource" to tierSource?.wire?.toJson(),
        "blocked" to blocked?.toJson(),
        "identities" to identities?.let { l -> jsonArray(l.map { it.toJson() }) },
        "displayName" to displayName?.toJson(),
        "avatar" to avatar?.toJson(),
        "roles" to roles?.let(::jsonStrings),
        "contactMethods" to contactMethods?.let { l -> jsonArray(l.map { it.toJson() }) },
        "checks" to checks?.let { l -> jsonArray(l.map { it.toJson() }) },
        "linkedPubkeys" to linkedPubkeys?.let(::jsonStrings),
    )
}

/** C13/R-30: newest wins by `(publishedAt, maxClock)`. */
public data class ProjectionFrontier(
    val maxClock: Long,
    val opCount: Long,
    val publishedAt: Long,
    /** 32 hex. */
    val deviceId: String,
) {
    public fun toJson(): JsonObject = jsonObject(
        "maxClock" to maxClock.toJson(), "opCount" to opCount.toJson(),
        "publishedAt" to publishedAt.toJson(), "deviceId" to deviceId.toJson(),
    )
}

/** R-31: deliberately no `ownerPubkey`. */
public data class ContactProjectionV2(
    val grantId: String,
    val scopes: List<Capability>,
    val frontier: ProjectionFrontier,
    val issuedAt: Long,
    val expiresAt: Long,
    val contacts: List<ProjectedContact>,
    val revoked: Boolean = false,
    /** R-5: the producer (or this parser, at its cap) dropped contacts. */
    val truncated: Boolean = false,
) {
    public val v: Int get() = 2

    /** The wire body, in canonical key order. */
    public fun toJson(): JsonObject = jsonObject(
        "v" to 2.toJson(),
        "grantId" to grantId.toJson(),
        "scopes" to jsonStrings(scopes.map { it.wire }),
        "frontier" to frontier.toJson(),
        "issuedAt" to issuedAt.toJson(),
        "expiresAt" to expiresAt.toJson(),
        "contacts" to jsonArray(contacts.map { it.toJson() }),
        "revoked" to if (revoked) true.toJson() else null,
        "truncated" to if (truncated) true.toJson() else null,
    )
}

// ---------------------------------------------------------------------------
// Proposals
// ---------------------------------------------------------------------------

public enum class ProposalAction(public val wire: String, public val capability: Capability) {
    ADD_KEN("add-ken", Capability.PROPOSE_ADD_KEN),
    RENAME_APP_LABEL("rename-app-label", Capability.PROPOSE_RENAME_APP_LABEL),
    ;

    public companion object {
        public fun fromWire(value: String?): ProposalAction? = entries.firstOrNull { it.wire == value }
    }
}

public sealed class ProposalValue {
    public abstract val action: ProposalAction
    public abstract fun toJson(): JsonObject
}

public data class AddKenValue(val pubkey: String, val displayName: String) : ProposalValue() {
    override val action: ProposalAction get() = ProposalAction.ADD_KEN
    override fun toJson(): JsonObject = jsonObject("pubkey" to pubkey.toJson(), "displayName" to displayName.toJson())
}

/** R-7: [updatedAt] (ms epoch) is the last-writer-wins clock for a rename. */
public data class RenameAppLabelValue(val contactId: String, val label: String, val updatedAt: Long) : ProposalValue() {
    override val action: ProposalAction get() = ProposalAction.RENAME_APP_LABEL
    override fun toJson(): JsonObject = jsonObject(
        "contactId" to contactId.toJson(), "label" to label.toJson(), "updatedAt" to updatedAt.toJson(),
    )
}

public data class ContactProposalV1(
    val grantId: String,
    val operationId: String,
    val value: ProposalValue,
    val createdAt: Long,
) {
    public val v: Int get() = 1
    val action: ProposalAction get() = value.action

    public fun toJson(): JsonObject = jsonObject(
        "v" to 1.toJson(), "grantId" to grantId.toJson(), "operationId" to operationId.toJson(),
        "action" to action.wire.toJson(), "value" to value.toJson(), "createdAt" to createdAt.toJson(),
    )
}

public data class ProposalBatch(val proposals: List<ContactProposalV1>) {
    public val v: Int get() = 1
}

/** What a consumer passes to `client.propose`; `operationId` is minted for it. */
public sealed class ContactProposalDraft {
    public abstract val action: ProposalAction

    public data class AddKen(val value: AddKenValue) : ContactProposalDraft() {
        public constructor(pubkey: String, displayName: String) : this(AddKenValue(pubkey, displayName))
        override val action: ProposalAction get() = ProposalAction.ADD_KEN
    }

    /** [updatedAt] is optional: when null it is stamped at mint time (R-7). */
    public data class RenameAppLabel(val contactId: String, val label: String, val updatedAt: Long? = null) : ContactProposalDraft() {
        override val action: ProposalAction get() = ProposalAction.RENAME_APP_LABEL
    }
}

// ---------------------------------------------------------------------------
// Consumer state
// ---------------------------------------------------------------------------

public data class ContactsState(
    val grantId: String?,
    val projection: ContactProjectionV2?,
    val receivedAt: Long,
    /** Sticky: survives expiry AND revocation. */
    val blockedPubkeys: List<String>,
    val revoked: Boolean,
) {
    public fun toJson(): JsonObject = jsonObject(
        "grantId" to (grantId?.toJson() ?: dev.forgesworn.signet.contacts.json.JsonNull),
        "projection" to (projection?.toJson() ?: dev.forgesworn.signet.contacts.json.JsonNull),
        "receivedAt" to receivedAt.toJson(),
        "blockedPubkeys" to jsonStrings(blockedPubkeys),
        "revoked" to revoked.toJson(),
    )
}

/** R-9: consumer-side only; never on the wire. F2: [grantId] scopes the entry. */
public data class PendingProposal(
    val grantId: String,
    val operationId: String,
    val value: ProposalValue,
    val sentAt: Long,
) {
    val action: ProposalAction get() = value.action

    public fun toJson(): JsonObject = jsonObject(
        "grantId" to grantId.toJson(), "operationId" to operationId.toJson(),
        "action" to action.wire.toJson(), "value" to value.toJson(), "sentAt" to sentAt.toJson(),
    )
}
