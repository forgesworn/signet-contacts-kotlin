package dev.forgesworn.signet.contacts.internal

/**
 * The slice of spoken-token 2.1.0 this wire uses: `deriveDirectionalPair`
 * with the default en-v1 wordlist and the `words` encoding.
 *
 *   token(role) = words(HMAC-SHA256(secret, utf8("pair\0" + ns + "\0" + role) || be32(counter)))
 *   word i      = wordlist[readUint16BE(bytes, 2i) % 2048]
 *
 * The wordlist is a resource, checked against its SHA-256 on first use so a
 * corrupted or edited copy fails loudly instead of producing other words.
 */
internal object SpokenToken {
    private const val WORDLIST_SHA256 = "9409ba756191078cde6699a63d58b0de15f4d064acc0a3193d230ba8981ac696"

    val wordlist: List<String> by lazy {
        val bytes = SpokenToken::class.java
            .getResourceAsStream("/dev/forgesworn/signet/contacts/spoken-token-en-v1.txt")
            ?.use { it.readBytes() }
            ?: error("spoken-token wordlist resource is missing")
        check(Hex.encode(Digest.sha256(bytes)) == WORDLIST_SHA256) { "spoken-token wordlist does not match en-v1" }
        val words = String(bytes, Charsets.UTF_8).split('\n').filter { it.isNotEmpty() }
        check(words.size == 2048) { "spoken-token wordlist must hold 2048 words" }
        words
    }

    /** `deriveDirectionalPair(secret, namespace, roles, counter, { format: 'words', count })`. */
    fun directionalPair(secret: ByteArray, namespace: String, roles: Pair<String, String>, counter: Long, count: Int): Map<String, String> {
        require(Js.trim(namespace).isNotEmpty()) { "namespace must be a non-empty string" }
        require('\u0000' !in namespace) { "namespace must not contain null bytes" }
        require(Js.trim(roles.first).isNotEmpty() && Js.trim(roles.second).isNotEmpty()) { "Both roles must be non-empty strings" }
        require('\u0000' !in roles.first && '\u0000' !in roles.second) { "Roles must not contain null bytes" }
        require(roles.first != roles.second) { "Roles must be distinct" }
        require(secret.size >= 16) { "Secret must be at least 16 bytes" }
        require(counter in 0..0xFFFFFFFFL) { "Counter must be a uint32" }
        require(count in 1..16) { "Word count must be an integer 1-16" }
        fun token(role: String): String {
            val be = byteArrayOf((counter ushr 24).toByte(), (counter ushr 16).toByte(), (counter ushr 8).toByte(), counter.toByte())
            val bytes = Digest.hmacSha256(secret, Js.utf8("pair\u0000$namespace\u0000$role") + be)
            return (0 until count).joinToString(" ") { i ->
                val index = ((bytes[i * 2].toInt() and 0xff) shl 8) or (bytes[i * 2 + 1].toInt() and 0xff)
                wordlist[index % wordlist.size]
            }
        }
        return mapOf(roles.first to token(roles.first), roles.second to token(roles.second))
    }
}
