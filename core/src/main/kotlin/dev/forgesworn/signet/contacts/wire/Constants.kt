package dev.forgesworn.signet.contacts.wire

/**
 * Frozen constants for the contacts app-access wire v2 (`docs/WIRE.md` in
 * signet-contacts). The pairing scheme and the 21237 ack kind are reused from
 * the v1 companion rail; the `v=2` marker is what separates the two.
 */

/** Major version of the contacts app-access wire. A bump requires a fresh pairing. */
public const val WIRE_VERSION: Int = 2

public const val PAIRING_SCHEME: String = "signet-grant:"
public const val PAIRING_VERSION: Int = 2
public const val ACK_KIND: Int = 21237
public const val PROJECTION_KIND: Int = 30078
public const val PROPOSAL_KIND: Int = 30078

/** The STORED copy of the pairing ack, addressed by [ackTag] and NIP-40-expired,
 *  so a consumer that was backgrounded through the ephemeral ack can still poll it. */
public const val ACK_STORED_KIND: Int = 30078
public const val PAIRING_FRESHNESS_SECONDS: Long = 300

/** How many ack candidates a consumer considers per filter (I3): junk addressed
 *  to the app pubkey printed in the QR must not crowd the genuine ack out. */
public const val ACK_CANDIDATE_LIMIT: Int = 10

/**
 * A capability an app can be granted. [wire] is the exact token on the wire.
 * Declaration order is binding: it is the order a grant screen lists them in,
 * and the order `scopes` is normalised to.
 *
 * There is no `read:avatar` in v2 (R-12).
 */
public enum class Capability(public val wire: String) {
    READ_DIRECTORY("signet.contacts.read:directory"),
    READ_METHOD_PHONE("signet.contacts.read:method:phone"),
    READ_METHOD_EMAIL("signet.contacts.read:method:email"),
    READ_METHOD_WEBSITE("signet.contacts.read:method:website"),
    READ_METHOD_POSTAL_ADDRESS("signet.contacts.read:method:postal-address"),
    READ_METHOD_OTHER("signet.contacts.read:method:other"),
    READ_TIER("signet.contacts.read:tier"),
    READ_CHECKS("signet.contacts.read:checks"),
    READ_CHECK_RECORDS("signet.contacts.read:check-records"),
    READ_ROLES("signet.contacts.read:roles"),
    BLOCKS_READ("signet.contacts.blocks.read"),
    PROPOSE_ADD_KEN("signet.contacts.propose:add-ken"),
    PROPOSE_RENAME_APP_LABEL("signet.contacts.propose:rename-app-label"),
    INVITES_CREATE("signet.contacts.invites:create"),
    INVITES_RECEIVE("signet.contacts.invites:receive"),
    ;

    override fun toString(): String = wire

    public companion object {
        private val BY_WIRE = entries.associateBy { it.wire }

        /** The capability for a wire token, or null for anything unknown. */
        public fun fromWire(value: String): Capability? = BY_WIRE[value]
    }
}

/** Every capability, in binding order. */
public val CAPABILITIES: List<Capability> = Capability.entries.toList()

public fun isCapability(value: String): Boolean = Capability.fromWire(value) != null

/** Sort an arbitrary capability list into [CAPABILITIES] order, deduped. */
public fun normaliseCapabilities(input: Iterable<Capability>): List<Capability> {
    val present = input.toSet()
    return CAPABILITIES.filter { it in present }
}

/**
 * One machine-readable line per capability, for documentation. Not the copy
 * a person approves against - that lives in signet-app (C10).
 */
public val CAPABILITY_DESCRIPTIONS: Map<Capability, String> = mapOf(
    Capability.INVITES_CREATE to "Issue named contact invites for the paired identity; eligible single-use requests may be accepted automatically for five minutes.",
    Capability.INVITES_RECEIVE to "Hand over a contact invite and send a request from the paired identity; no connection result is returned.",
    Capability.READ_DIRECTORY to "Read contact ids, display names and identity pubkeys only.",
    Capability.READ_METHOD_PHONE to "Read shareable phone contact methods.",
    Capability.READ_METHOD_EMAIL to "Read shareable email contact methods.",
    Capability.READ_METHOD_WEBSITE to "Read shareable website contact methods.",
    Capability.READ_METHOD_POSTAL_ADDRESS to "Read shareable postal-address contact methods.",
    Capability.READ_METHOD_OTHER to "Read shareable other contact methods.",
    Capability.READ_TIER to "Read Kin, Kith or Ken labels and whether a guardian set or limited them.",
    Capability.READ_CHECK_RECORDS to "Read check methods and dates for shared public keys. Private sources and evidence stay private.",
    Capability.READ_CHECKS to "Read verification status on the keys and contact methods already granted.",
    Capability.READ_ROLES to "Read the owner-assigned role labels on each contact.",
    Capability.BLOCKS_READ to "Read blocked contacts, including their identity pubkeys, so the app can filter them.",
    Capability.PROPOSE_ADD_KEN to "Add contacts to your Ken list (recognised only, no access). Links to an existing contact under another identity need your confirmation.",
    Capability.PROPOSE_RENAME_APP_LABEL to "Propose a rename that applies only inside this grant\u2019s own projection.",
)

public const val DEFAULT_STALENESS_SECONDS: Long = 21600 // 6 h
public const val MIN_STALENESS_SECONDS: Long = 3600 // 1 h
public const val MAX_STALENESS_SECONDS: Long = 604800 // 7 d

/** Hard plaintext ceiling for anything this wire seals (R-5). */
public const val MAX_WIRE_BYTES: Int = 65532

public const val MAX_APP_NAME: Int = 64
public const val MAX_CAPABILITIES: Int = 16
public const val MAX_CONTACTS_PER_PROJECTION: Int = 2000
public const val MAX_IDENTITIES_PER_CONTACT: Int = 16
public const val MAX_METHODS_PER_CONTACT: Int = 16
public const val MAX_ROLES_PER_CONTACT: Int = 8
public const val MAX_LINKED_PUBKEYS: Int = 16
public const val MAX_DISPLAY_NAME: Int = 100
public const val MAX_APP_LABEL: Int = 100
public const val MAX_ROLE_LEN: Int = 40
public const val MAX_METHOD_VALUE: Int = 320
public const val MAX_URL_LEN: Int = 512
public const val MAX_PROPOSALS_PER_BATCH: Int = 50

/** C-I7: signet-app's own storage bound for a relay URL. A hard failure, never a truncation. */
public const val MAX_RELAY_LEN: Int = 256

/** A challenge is exactly 32 hex characters (128 bits). */
public const val CHALLENGE_HEX_CHARS: Int = 32

/** Ceiling on a raw pairing URI a parser will even look at. */
public const val MAX_PAIRING_URI_CHARS: Int = 2048

/**
 * Clamp a requested staleness window into the permitted band. Anything that
 * is not a finite positive number resolves to the default rather than 0.
 */
public fun clampStaleness(seconds: Double?): Long {
    if (seconds == null || !seconds.isFinite() || seconds <= 0) return DEFAULT_STALENESS_SECONDS
    val whole = Math.floor(seconds)
    if (whole < MIN_STALENESS_SECONDS) return MIN_STALENESS_SECONDS
    if (whole > MAX_STALENESS_SECONDS) return MAX_STALENESS_SECONDS
    return whole.toLong()
}

public fun clampStaleness(seconds: Long?): Long = clampStaleness(seconds?.toDouble())
