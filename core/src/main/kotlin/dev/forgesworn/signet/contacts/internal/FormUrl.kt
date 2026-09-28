package dev.forgesworn.signet.contacts.internal

/**
 * `URLSearchParams`, which is the WHATWG application/x-www-form-urlencoded
 * format. `java.net.URLEncoder` agrees on the serialiser's byte set but writes
 * `?` for a lone surrogate, and `URLDecoder` throws on a stray `%` where the
 * WHATWG parser keeps it literally, so both directions are done here.
 */
internal object FormUrl {
    /** One name/value pair, serialised exactly as `URLSearchParams#toString`. */
    fun serialize(pairs: List<Pair<String, String>>): String =
        pairs.joinToString("&") { (k, v) -> encode(k) + "=" + encode(v) }

    private fun encode(s: String): String {
        val sb = StringBuilder()
        for (b in Js.utf8(s)) {
            val c = b.toInt() and 0xff
            when {
                c == 0x20 -> sb.append('+')
                c in 0x30..0x39 || c in 0x41..0x5a || c in 0x61..0x7a ||
                    c == 0x2a || c == 0x2d || c == 0x2e || c == 0x5f -> sb.append(c.toChar())
                else -> sb.append('%').append("0123456789ABCDEF"[c ushr 4]).append("0123456789ABCDEF"[c and 0xf])
            }
        }
        return sb.toString()
    }

    /** Parse a query string into ordered pairs (`new URLSearchParams(input)`). */
    fun parse(input: String): List<Pair<String, String>> {
        val query = if (input.startsWith("?")) input.substring(1) else input
        val out = ArrayList<Pair<String, String>>()
        for (sequence in query.split('&')) {
            if (sequence.isEmpty()) continue
            val eq = sequence.indexOf('=')
            val name = if (eq >= 0) sequence.substring(0, eq) else sequence
            val value = if (eq >= 0) sequence.substring(eq + 1) else ""
            out.add(decode(name) to decode(value))
        }
        return out
    }

    /** `URLSearchParams#get`: the first value for [name], or null. */
    fun get(pairs: List<Pair<String, String>>, name: String): String? = pairs.firstOrNull { it.first == name }?.second

    private fun decode(s: String): String {
        val bytes = Js.utf8(s.replace('+', ' '))
        val out = java.io.ByteArrayOutputStream(bytes.size)
        var i = 0
        while (i < bytes.size) {
            val b = bytes[i]
            if (b == '%'.code.toByte() && i + 2 < bytes.size) {
                val hi = hexVal(bytes[i + 1])
                val lo = hexVal(bytes[i + 2])
                if (hi >= 0 && lo >= 0) {
                    out.write((hi shl 4) or lo)
                    i += 3
                    continue
                }
            }
            out.write(b.toInt())
            i++
        }
        // "UTF-8 decode without BOM": a leading U+FEFF in a value is kept.
        return Js.utf8Decode(out.toByteArray(), stripBom = false)
    }

    private fun hexVal(b: Byte): Int = when (val c = b.toInt().toChar()) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> -1
    }
}
