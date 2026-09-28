package dev.forgesworn.signet.contacts.internal

import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * The handful of JavaScript built-ins whose exact behaviour the wire depends
 * on, reproduced rather than approximated by their nearest JVM relative.
 */
internal object Js {
    /** ECMA-262 WhiteSpace and LineTerminator, which is what `String#trim`
     *  removes. `Char.isWhitespace` is a different set (it includes U+001C..1F
     *  and excludes U+FEFF), so it is not used. */
    fun isTrimmable(c: Char): Boolean = when (c) {
        '\t', '\u000b', '\u000c', ' ', '\u00a0', '\ufeff', '\n', '\r', '\u2028', '\u2029',
        '\u1680', '\u202f', '\u205f', '\u3000' -> true
        in '\u2000'..'\u200a' -> true
        else -> false
    }

    fun trim(s: String): String {
        var start = 0
        var end = s.length
        while (start < end && isTrimmable(s[start])) start++
        while (end > start && isTrimmable(s[end - 1])) end--
        return s.substring(start, end)
    }

    /** `String#toWellFormed`: every lone surrogate becomes U+FFFD. */
    fun toWellFormed(s: String): String {
        var sb: StringBuilder? = null
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                sb?.append(c)?.append(s[i + 1])
                i += 2
                continue
            }
            if (Character.isSurrogate(c)) {
                if (sb == null) sb = StringBuilder(s.substring(0, i))
                sb.append('\ufffd')
            } else {
                sb?.append(c)
            }
            i++
        }
        return sb?.toString() ?: s
    }

    /** `new TextEncoder().encode(s)` - lone surrogates encode as U+FFFD
     *  (EF BF BD), where `String.toByteArray` would write `?`. */
    fun utf8(s: String): ByteArray = toWellFormed(s).toByteArray(Charsets.UTF_8)

    /** `new TextDecoder().decode(bytes)`: non-fatal UTF-8, and a leading BOM
     *  removed unless [stripBom] is false (WHATWG "UTF-8 decode without BOM"). */
    fun utf8Decode(bytes: ByteArray, offset: Int = 0, length: Int = bytes.size - offset, stripBom: Boolean = true): String {
        val decoder = Charsets.UTF_8.newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPLACE)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPLACE)
        val text = decoder.decode(java.nio.ByteBuffer.wrap(bytes, offset, length)).toString()
        return if (stripBom && text.startsWith('\ufeff')) text.substring(1) else text
    }

    /** `Array.from(s).length` - code points, a lone surrogate counting as one. */
    fun codePointLength(s: String): Int = s.codePointCount(0, s.length)

    /** `Array.from(s).slice(0, n).join('')` */
    fun codePointPrefix(s: String, n: Int): String {
        if (n <= 0) return ""
        if (codePointLength(s) <= n) return s
        return s.substring(0, s.offsetByCodePoints(0, n))
    }

    /** `btoa` over bytes (standard alphabet, padded). */
    fun base64(bytes: ByteArray): String = java.util.Base64.getEncoder().encodeToString(bytes)

    /**
     * `atob`, which is the WHATWG forgiving-base64 decode: ASCII whitespace is
     * ignored, padding is optional, stray bits in the last character are
     * ignored, and anything else outside the alphabet is an error (null here,
     * where `atob` throws).
     */
    fun forgivingBase64(input: String): ByteArray? {
        val sb = StringBuilder(input.length)
        for (c in input) if (c != '\t' && c != '\n' && c != '\u000c' && c != '\r' && c != ' ') sb.append(c)
        var data = sb.toString()
        if (data.length % 4 == 0) {
            if (data.endsWith("==")) data = data.dropLast(2) else if (data.endsWith("=")) data = data.dropLast(1)
        }
        if (data.length % 4 == 1) return null
        val out = java.io.ByteArrayOutputStream(data.length * 3 / 4)
        var buffer = 0
        var bits = 0
        for (c in data) {
            val v = when (c) {
                in 'A'..'Z' -> c - 'A'
                in 'a'..'z' -> c - 'a' + 26
                in '0'..'9' -> c - '0' + 52
                '+' -> 62
                '/' -> 63
                else -> return null
            }
            buffer = (buffer shl 6) or v
            bits += 6
            if (bits >= 8) {
                bits -= 8
                out.write((buffer shr bits) and 0xff)
            }
        }
        return out.toByteArray()
    }
}

internal object Hex {
    private val DIGITS = "0123456789abcdef".toCharArray()

    fun encode(bytes: ByteArray): String {
        val out = CharArray(bytes.size * 2)
        for (i in bytes.indices) {
            val b = bytes[i].toInt() and 0xff
            out[i * 2] = DIGITS[b ushr 4]
            out[i * 2 + 1] = DIGITS[b and 0x0f]
        }
        return String(out)
    }

    /** Lowercase or uppercase hex of even length, else IllegalArgumentException. */
    fun decode(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "hex string must have even length" }
        return ByteArray(hex.length / 2) { i ->
            val hi = Character.digit(hex[i * 2], 16)
            val lo = Character.digit(hex[i * 2 + 1], 16)
            require(hi >= 0 && lo >= 0 && hex[i * 2].code < 0x80 && hex[i * 2 + 1].code < 0x80) { "invalid hex" }
            ((hi shl 4) or lo).toByte()
        }
    }
}

internal object Digest {
    fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

    fun sha256Hex(text: String): String = Hex.encode(sha256(Js.utf8(text)))

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        // A zero-length HMAC key is legal (RFC 2104) but SecretKeySpec refuses
        // it; an all-zero block-length key is the same key under HMAC's padding.
        val spec = SecretKeySpec(if (key.isEmpty()) ByteArray(64) else key, "HmacSHA256")
        return Mac.getInstance("HmacSHA256").run {
            init(spec)
            doFinal(data)
        }
    }

    /** RFC 5869 HKDF-SHA256, as `@noble/hashes` `hkdf(sha256, ikm, salt, info, length)`. */
    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length in 1..255 * 32) { "invalid HKDF length" }
        val prk = hmacSha256(if (salt.isEmpty()) ByteArray(32) else salt, ikm)
        val out = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        try {
            while (offset < length) {
                val t = hmacSha256(prk, previous + info + byteArrayOf(counter.toByte()))
                previous.fill(0)
                previous = t
                val n = minOf(t.size, length - offset)
                System.arraycopy(t, 0, out, offset, n)
                offset += n
                counter++
            }
        } finally {
            prk.fill(0)
            previous.fill(0)
        }
        return out
    }
}

internal object Random {
    private val rng = SecureRandom()

    fun bytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }
}
