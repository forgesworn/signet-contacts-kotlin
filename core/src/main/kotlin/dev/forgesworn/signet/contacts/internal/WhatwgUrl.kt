package dev.forgesworn.signet.contacts.internal

/**
 * The part of the WHATWG URL Standard this wire depends on: parsing an
 * absolute `https:` or `wss:` URL (no base) and serialising its `href`.
 *
 * Invite relay URLs are normalised through `new URL(raw).href` in the
 * reference, and that normalised string is then hashed into every contact
 * exchange transcript, so "close enough" would split transcripts between
 * implementations. Every other scheme returns null here, which is what both
 * callers need: they accept exactly one scheme each and reject the rest.
 *
 * Known gap: UTS #46 (the standard's own IDNA processing) is not
 * implemented. A non-ASCII host, after percent-decoding, instead goes
 * through `java.net.IDN` (IDNA 2003) with no flags, which agrees with UTS #46
 * nontransitional processing for ordinary hosts. It disagrees on exactly
 * four "deviation" characters (U+00DF ß, U+03C2 ς, U+200C ZWNJ, U+200D ZWJ),
 * so a host containing any of those is rejected outright rather than risk
 * normalising to something a real UTS #46 implementation would not. With no
 * flags passed, `java.net.IDN` is also fail-closed on a code point unassigned
 * in Unicode 3.2 (`IllegalArgumentException`), rather than letting it through
 * via `ALLOW_UNASSIGNED`. Android's `java.net.IDN` is ICU-backed, so results
 * for exotic (non-deviation) inputs may still differ in rare cases from a
 * desktop JVM's; the deviation-character and unassigned-code-point
 * rejections themselves apply identically on both. An `xn--...` (Punycode)
 * label - whether it arrived already-ASCII or came out of `java.net.IDN`,
 * which passes an ASCII label through unchecked - is accepted only once a
 * real RFC 3492 decoder confirms it actually decodes; `java.net.IDN.toUnicode`
 * never throws, so it could not be trusted to reject a malformed one. ASCII
 * hosts, IPv4 (including the hex and octal forms) and IPv6 follow the
 * standard exactly.
 */
internal class WhatwgUrl private constructor(
    val scheme: String,
    val username: String,
    val password: String,
    val host: String,
    val port: Int?,
    val path: List<String>,
    val query: String?,
    val fragment: String?,
) {
    val protocol: String get() = "$scheme:"
    val hash: String get() = if (fragment.isNullOrEmpty()) "" else "#$fragment"

    val href: String
        get() = buildString {
            append(scheme).append("://")
            if (username.isNotEmpty() || password.isNotEmpty()) {
                append(username)
                if (password.isNotEmpty()) append(':').append(password)
                append('@')
            }
            append(host)
            if (port != null) append(':').append(port)
            append('/').append(path.joinToString("/"))
            if (query != null) append('?').append(query)
            if (fragment != null) append('#').append(fragment)
        }

    companion object {
        private val DEFAULT_PORTS = mapOf("https" to 443, "wss" to 443)

        /** Parse [raw] as an absolute https: or wss: URL, or null. */
        fun parse(raw: String): WhatwgUrl? = try {
            Parser(prepare(raw)).run()
        } catch (_: Failure) {
            null
        }

        private fun prepare(raw: String): String {
            var s = Js.toWellFormed(raw)
            var start = 0
            var end = s.length
            while (start < end && s[start] <= ' ') start++
            while (end > start && s[end - 1] <= ' ') end--
            s = s.substring(start, end)
            return s.filterNot { it == '\t' || it == '\n' || it == '\r' }
        }

        private class Failure : Exception() {
            override fun fillInStackTrace(): Throwable = this
        }

        private fun fail(): Nothing = throw Failure()

        // Percent-encode sets (URL Standard \u00a71.3), beyond "C0 control or > U+007E".
        private const val FRAGMENT_SET = " \"<>`"
        private const val SPECIAL_QUERY_SET = " \"#<>'"
        private const val PATH_SET = " \"#<>?^`{}"

        private fun percentEncode(s: String, extra: String): String {
            val sb = StringBuilder()
            var i = 0
            while (i < s.length) {
                val cp = s.codePointAt(i)
                val n = Character.charCount(cp)
                if (cp < 0x20 || cp > 0x7e || extra.indexOf(cp.toChar()) >= 0) {
                    for (b in String(Character.toChars(cp)).toByteArray(Charsets.UTF_8)) {
                        val v = b.toInt() and 0xff
                        sb.append('%').append("0123456789ABCDEF"[v ushr 4]).append("0123456789ABCDEF"[v and 0xf])
                    }
                } else {
                    sb.append(cp.toChar())
                }
                i += n
            }
            return sb.toString()
        }

        private class Parser(private val s: String) {
            fun run(): WhatwgUrl {
                val colon = s.indexOf(':')
                if (colon <= 0 || !s[0].isAsciiLetter()) fail()
                val schemeRaw = s.substring(0, colon)
                if (!schemeRaw.all { it.isAsciiLetter() || it in '0'..'9' || it == '+' || it == '-' || it == '.' }) fail()
                val scheme = schemeRaw.lowercase()
                if (scheme != "https" && scheme != "wss") fail()

                // Special authority (ignore) slashes: any run of / and \.
                var i = colon + 1
                while (i < s.length && (s[i] == '/' || s[i] == '\\')) i++

                // Authority: up to the first / \ ? # or the end.
                var end = i
                while (end < s.length && s[end] != '/' && s[end] != '\\' && s[end] != '?' && s[end] != '#') end++
                val authority = s.substring(i, end)
                val at = authority.lastIndexOf('@')
                var username = ""
                var password = ""
                val hostPort: String
                if (at >= 0) {
                    val userinfo = authority.substring(0, at).replace("@", "%40")
                    val c = userinfo.indexOf(':')
                    val userSet = "$PATH_SET/:;=@[\\]|"
                    if (c >= 0) {
                        username = percentEncode(userinfo.substring(0, c), userSet)
                        password = percentEncode(userinfo.substring(c + 1), userSet)
                    } else {
                        username = percentEncode(userinfo, userSet)
                    }
                    hostPort = authority.substring(at + 1)
                    if (hostPort.isEmpty()) fail()
                } else {
                    hostPort = authority
                }

                // Host and port: the port starts at the first ':' outside brackets.
                var inBrackets = false
                var portAt = -1
                for (k in hostPort.indices) {
                    when (hostPort[k]) {
                        '[' -> inBrackets = true
                        ']' -> inBrackets = false
                        ':' -> if (!inBrackets) { portAt = k; break }
                    }
                }
                val hostRaw = if (portAt >= 0) hostPort.substring(0, portAt) else hostPort
                if (hostRaw.isEmpty()) fail()
                val host = parseHost(hostRaw)
                var port: Int? = null
                if (portAt >= 0) {
                    val portRaw = hostPort.substring(portAt + 1)
                    if (!portRaw.all { it in '0'..'9' }) fail()
                    if (portRaw.isNotEmpty()) {
                        val value = portRaw.trimStart('0').ifEmpty { "0" }
                        if (value.length > 5 || value.toInt() > 65535) fail()
                        port = value.toInt().takeIf { it != DEFAULT_PORTS[scheme] }
                    }
                }

                // Path, query, fragment.
                var rest = s.substring(end)
                var fragment: String? = null
                val hashAt = rest.indexOf('#')
                if (hashAt >= 0) {
                    fragment = percentEncode(rest.substring(hashAt + 1), FRAGMENT_SET)
                    rest = rest.substring(0, hashAt)
                }
                var query: String? = null
                val qAt = rest.indexOf('?')
                if (qAt >= 0) {
                    query = percentEncode(rest.substring(qAt + 1), SPECIAL_QUERY_SET)
                    rest = rest.substring(0, qAt)
                }
                return WhatwgUrl(scheme, username, password, host, port, parsePath(rest), query, fragment)
            }
        }

        private fun Char.isAsciiLetter(): Boolean = this in 'a'..'z' || this in 'A'..'Z'

        private fun isSingleDot(seg: String) = seg == "." || seg.equals("%2e", ignoreCase = true)
        private fun isDoubleDot(seg: String) = when (seg.lowercase()) {
            "..", ".%2e", "%2e.", "%2e%2e" -> true
            else -> false
        }

        /** Path state for a special URL: `raw` is everything between the host and ? or #. */
        private fun parsePath(raw: String): List<String> {
            // Path start state: a leading / or \ is consumed; otherwise the
            // first segment starts at once. Both produce the same segments.
            val body = if (raw.startsWith("/") || raw.startsWith("\\")) raw.substring(1) else raw
            val segments = body.split('/', '\\')
            val path = ArrayList<String>()
            for ((index, seg) in segments.withIndex()) {
                val last = index == segments.size - 1
                when {
                    isDoubleDot(seg) -> {
                        if (path.isNotEmpty()) path.removeAt(path.size - 1)
                        if (last) path.add("")
                    }
                    isSingleDot(seg) -> if (last) path.add("")
                    else -> path.add(percentEncode(seg, PATH_SET))
                }
            }
            return path
        }

        // ------------------------------------------------------------------
        // Host parsing
        // ------------------------------------------------------------------

        private const val FORBIDDEN_DOMAIN = "\u0000\t\n\r #/:<>?@[\\]^|%\u007f"

        private fun parseHost(input: String): String {
            if (input.startsWith("[")) {
                if (!input.endsWith("]")) fail()
                return "[" + serializeIpv6(parseIpv6(input.substring(1, input.length - 1))) + "]"
            }
            val domain = percentDecodeUtf8(input)
            val ascii = domainToAscii(domain)
            if (ascii.isEmpty()) fail()
            if (ascii.any { it < ' ' || FORBIDDEN_DOMAIN.indexOf(it) >= 0 }) fail()
            if (endsInANumber(ascii)) return serializeIpv4(parseIpv4(ascii))
            return ascii
        }

        private fun percentDecodeUtf8(s: String): String {
            val bytes = s.toByteArray(Charsets.UTF_8)
            val out = java.io.ByteArrayOutputStream(bytes.size)
            var i = 0
            while (i < bytes.size) {
                val b = bytes[i]
                if (b == '%'.code.toByte() && i + 2 < bytes.size) {
                    val hi = Character.digit(bytes[i + 1].toInt().toChar(), 16)
                    val lo = Character.digit(bytes[i + 2].toInt().toChar(), 16)
                    if (hi >= 0 && lo >= 0 && bytes[i + 1] >= 0 && bytes[i + 2] >= 0) {
                        out.write((hi shl 4) or lo)
                        i += 3
                        continue
                    }
                }
                out.write(b.toInt())
                i++
            }
            return Js.utf8Decode(out.toByteArray(), stripBom = false)
        }

        // The four code points where IDNA 2003 (java.net.IDN) disagrees with
        // UTS #46 nontransitional processing: see the class doc.
        private val UTS46_DEVIATION_CHARS = charArrayOf('ß', 'ς', '‌', '‍')

        private fun domainToAscii(domain: String): String {
            // Fail closed on exactly the four characters IDNA 2003 and UTS #46
            // disagree on, regardless of what else is in the host.
            if (domain.any { it in UTS46_DEVIATION_CHARS }) fail()
            if (domain.any { it.code > 0x7f }) {
                // UTS #46 is not implemented (see the class doc): a non-ASCII host
                // goes through java.net.IDN with NO flags, so it is fail-closed on
                // code points unassigned in Unicode 3.2 (IllegalArgumentException)
                // rather than letting ALLOW_UNASSIGNED pass them through.
                val ascii = try {
                    java.net.IDN.toASCII(domain, 0).lowercase(java.util.Locale.ROOT)
                } catch (_: IllegalArgumentException) {
                    fail()
                }
                // IDN passes an ASCII "xn--" label straight through unchecked, so
                // the same Punycode-must-actually-decode validation below has to
                // run over ITS output too, not only over an input that arrived
                // already all-ASCII.
                validateXnLabels(ascii)
                return ascii
            }
            val lower = domain.lowercase(java.util.Locale.ROOT)
            validateXnLabels(lower)
            return lower
        }

        /** A label that claims to be Punycode ("xn--") must actually decode as
         *  Punycode. `java.net.IDN.toUnicode` never throws, so only a real RFC
         *  3492 decoder can reject a malformed one - and IDN also passes an
         *  already-ASCII "xn--" label straight through unchecked, so this must
         *  run over both an ASCII host's own labels and an IDN-converted one's. */
        private fun validateXnLabels(asciiDomain: String) {
            for (label in asciiDomain.split('.')) {
                if (label.startsWith("xn--")) {
                    if (decodePunycode(label.substring(4)).isNullOrEmpty()) fail()
                }
            }
        }

        // ------------------------------------------------------------------
        // Punycode (RFC 3492), decode only: this file only ever needs to
        // confirm an "xn--" label decodes at all, never to encode one.
        // ------------------------------------------------------------------

        private const val PUNYCODE_BASE = 36
        private const val PUNYCODE_TMIN = 1
        private const val PUNYCODE_TMAX = 26
        private const val PUNYCODE_SKEW = 38
        private const val PUNYCODE_DAMP = 700
        private const val PUNYCODE_INITIAL_BIAS = 72
        private const val PUNYCODE_INITIAL_N = 128

        private fun punycodeDigit(cp: Int): Int = when (cp) {
            in 'a'.code..'z'.code -> cp - 'a'.code
            in 'A'.code..'Z'.code -> cp - 'A'.code
            in '0'.code..'9'.code -> cp - '0'.code + 26
            else -> -1
        }

        private fun punycodeAdapt(delta0: Int, numPoints: Int, firstTime: Boolean): Int {
            var delta = if (firstTime) delta0 / PUNYCODE_DAMP else delta0 / 2
            delta += delta / numPoints
            var k = 0
            while (delta > ((PUNYCODE_BASE - PUNYCODE_TMIN) * PUNYCODE_TMAX) / 2) {
                delta /= (PUNYCODE_BASE - PUNYCODE_TMIN)
                k += PUNYCODE_BASE
            }
            return k + (((PUNYCODE_BASE - PUNYCODE_TMIN + 1) * delta) / (delta + PUNYCODE_SKEW))
        }

        /**
         * Decode [input] (an "xn--" label with that prefix already stripped)
         * per RFC 3492. Null on any malformed input: an out-of-alphabet
         * digit, an overflowed generalised variable-length integer, or a
         * resulting code point outside the valid Unicode range. An empty
         * [input] decodes to an empty string, which the caller treats as
         * invalid (a bare "xn--" label is not a real Punycode label).
         */
        private fun decodePunycode(input: String): String? {
            var n = PUNYCODE_INITIAL_N
            var i = 0
            var bias = PUNYCODE_INITIAL_BIAS
            val output = ArrayList<Int>()

            val lastDelimiter = input.lastIndexOf('-')
            // RFC 3492 6.2: a delimiter at index 0 ("-abc") means the basic part is
            // EMPTY, and decoding starts at index 0 - the delimiter itself is not a
            // valid digit, so decoding fails there rather than skipping past it.
            if (lastDelimiter > 0) {
                for (k in 0 until lastDelimiter) {
                    val cp = input[k].code
                    if (cp >= 0x80) return null // a basic code point must be ASCII
                    output.add(cp)
                }
            }
            var pos: Int = if (lastDelimiter > 0) lastDelimiter + 1 else 0

            while (pos < input.length) {
                val oldI = i
                var w = 1
                var k = PUNYCODE_BASE
                while (true) {
                    if (pos >= input.length) return null
                    val digit = punycodeDigit(input[pos].code)
                    pos++
                    if (digit < 0) return null
                    if (digit > (Int.MAX_VALUE - i) / w) return null // overflow
                    i += digit * w
                    val t = when {
                        k <= bias -> PUNYCODE_TMIN
                        k >= bias + PUNYCODE_TMAX -> PUNYCODE_TMAX
                        else -> k - bias
                    }
                    if (digit < t) break
                    if (w > Int.MAX_VALUE / (PUNYCODE_BASE - t)) return null // overflow
                    w *= (PUNYCODE_BASE - t)
                    k += PUNYCODE_BASE
                }
                val outLength = output.size + 1
                bias = punycodeAdapt(i - oldI, outLength, oldI == 0)
                if (i / outLength > Int.MAX_VALUE - n) return null // overflow
                n += i / outLength
                i %= outLength
                if (n > 0x10ffff || n in 0xd800..0xdfff) return null // outside the valid Unicode range
                output.add(i, n)
                i++
            }
            // UTS #46: a Punycode label that decodes to purely ASCII output (e.g.
            // "xn--abc-") is invalid - there is no reason to Punycode-encode a
            // string with nothing non-ASCII in it.
            if (output.all { it < 0x80 }) return null
            return buildString { for (cp in output) appendCodePoint(cp) }
        }

        private fun endsInANumber(host: String): Boolean {
            val parts = host.split('.').toMutableList()
            if (parts.last().isEmpty()) {
                if (parts.size == 1) return false
                parts.removeAt(parts.size - 1)
            }
            val last = parts.last()
            if (last.isNotEmpty() && last.all { it in '0'..'9' }) return true
            return parseIpv4Number(last) != null
        }

        /** Null for "not a number"; a failure never escapes from here. */
        private fun parseIpv4Number(input: String): Long? {
            if (input.isEmpty()) return null
            var s = input
            var radix = 10
            if (s.length >= 2 && (s.startsWith("0x") || s.startsWith("0X"))) {
                s = s.substring(2); radix = 16
            } else if (s.length >= 2 && s.startsWith("0")) {
                s = s.substring(1); radix = 8
            }
            if (s.isEmpty()) return 0
            if (!s.all { Character.digit(it, radix) >= 0 && it.code < 0x80 }) return null
            return java.math.BigInteger(s, radix).let { if (it.bitLength() > 62) Long.MAX_VALUE else it.toLong() }
        }

        private fun parseIpv4(input: String): Long {
            val parts = input.split('.').toMutableList()
            if (parts.last().isEmpty() && parts.size > 1) parts.removeAt(parts.size - 1)
            if (parts.size > 4) fail()
            val numbers = parts.map { parseIpv4Number(it) ?: fail() }
            for (k in 0 until numbers.size - 1) if (numbers[k] > 255) fail()
            val lastLimit = 1L shl (8 * (5 - numbers.size))
            if (numbers.last() >= lastLimit) fail()
            var ipv4 = numbers.last()
            for (k in 0 until numbers.size - 1) ipv4 += numbers[k] shl (8 * (3 - k))
            return ipv4
        }

        private fun serializeIpv4(address: Long): String =
            (3 downTo 0).joinToString(".") { ((address shr (8 * it)) and 0xff).toString() }

        private fun parseIpv6(input: String): IntArray {
            val address = IntArray(8)
            var pieceIndex = 0
            var compress = -1
            var p = 0
            val c = { at: Int -> if (at < input.length) input[at] else '\uffff' }
            if (c(p) == ':') {
                if (c(p + 1) != ':') fail()
                p += 2
                pieceIndex++
                compress = pieceIndex
            }
            while (p < input.length) {
                if (pieceIndex == 8) fail()
                if (c(p) == ':') {
                    if (compress != -1) fail()
                    p++
                    pieceIndex++
                    compress = pieceIndex
                    continue
                }
                var value = 0
                var length = 0
                while (length < 4 && Character.digit(c(p), 16) >= 0 && c(p).code < 0x80) {
                    value = value * 0x10 + Character.digit(c(p), 16)
                    p++
                    length++
                }
                if (c(p) == '.') {
                    if (length == 0) fail()
                    p -= length
                    if (pieceIndex > 6) fail()
                    var numbersSeen = 0
                    while (p < input.length) {
                        var ipv4Piece = -1
                        if (numbersSeen > 0) {
                            if (c(p) == '.' && numbersSeen < 4) p++ else fail()
                        }
                        if (c(p) !in '0'..'9') fail()
                        while (c(p) in '0'..'9') {
                            val number = c(p) - '0'
                            ipv4Piece = when (ipv4Piece) {
                                -1 -> number
                                0 -> fail()
                                else -> ipv4Piece * 10 + number
                            }
                            if (ipv4Piece > 255) fail()
                            p++
                        }
                        address[pieceIndex] = address[pieceIndex] * 0x100 + ipv4Piece
                        numbersSeen++
                        if (numbersSeen == 2 || numbersSeen == 4) pieceIndex++
                    }
                    if (numbersSeen != 4) fail()
                    break
                } else if (c(p) == ':') {
                    p++
                    if (p >= input.length) fail()
                } else if (p < input.length) {
                    fail()
                }
                address[pieceIndex] = value
                pieceIndex++
            }
            if (compress != -1) {
                var swaps = pieceIndex - compress
                pieceIndex = 7
                while (pieceIndex != 0 && swaps > 0) {
                    val tmp = address[compress + swaps - 1]
                    address[compress + swaps - 1] = address[pieceIndex]
                    address[pieceIndex] = tmp
                    pieceIndex--
                    swaps--
                }
            } else if (pieceIndex != 8) {
                fail()
            }
            return address
        }

        private fun serializeIpv6(address: IntArray): String {
            // The first longest run of two or more zero pieces is compressed.
            var bestStart = -1
            var bestLen = 1
            var k = 0
            while (k < 8) {
                if (address[k] == 0) {
                    var j = k
                    while (j < 8 && address[j] == 0) j++
                    if (j - k > bestLen) { bestStart = k; bestLen = j - k }
                    k = j
                } else {
                    k++
                }
            }
            val sb = StringBuilder()
            var ignore0 = false
            for (idx in 0 until 8) {
                if (ignore0 && address[idx] == 0) continue
                ignore0 = false
                if (bestStart == idx) {
                    sb.append(if (idx == 0) "::" else ":")
                    ignore0 = true
                    continue
                }
                sb.append(address[idx].toString(16))
                if (idx != 7) sb.append(':')
            }
            return sb.toString()
        }
    }
}
