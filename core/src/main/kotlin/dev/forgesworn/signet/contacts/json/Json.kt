package dev.forgesworn.signet.contacts.json

/**
 * A JSON value with JavaScript's semantics, not the JVM's.
 *
 * Every digest on this wire is SHA-256 over `JSON.stringify` output, and every
 * parser mirrors what `JSON.parse` would have handed the TypeScript reference.
 * A general-purpose JVM JSON library disagrees with both in small ways that
 * change bytes: how a number prints, which characters a string escapes, what a
 * lone surrogate becomes. So this port carries its own, small enough to read.
 *
 *  - Numbers are IEEE doubles, exactly as `JSON.parse` produces them; `2.0`
 *    and `2` are the same value, and an integer past 2^53 has already lost
 *    precision by the time anything looks at it.
 *  - Objects keep insertion order. A repeated key keeps its FIRST position and
 *    its LAST value, which is what assigning into a JavaScript object does.
 *  - [stringify] escapes exactly what `JSON.stringify` escapes and nothing
 *    more: `"`, `\`, the C0 controls, and lone surrogates. Non-ASCII text,
 *    `/`, U+2028 and U+2029 pass through literally.
 */
public sealed class JsonValue {
    public fun stringify(): String = StringBuilder().also { JsonWriter.write(this, it) }.toString()
    override fun toString(): String = stringify()
}

public object JsonNull : JsonValue()

public data class JsonBool(val value: Boolean) : JsonValue() {
    override fun toString(): String = stringify()
}

public data class JsonNumber(val value: Double) : JsonValue() {
    public constructor(value: Long) : this(value.toDouble())
    public constructor(value: Int) : this(value.toDouble())
    override fun toString(): String = stringify()
}

public data class JsonString(val value: String) : JsonValue() {
    override fun toString(): String = stringify()
}

public data class JsonArray(val items: List<JsonValue>) : JsonValue() {
    override fun toString(): String = stringify()
}

public data class JsonObject(val fields: Map<String, JsonValue>) : JsonValue() {
    public operator fun get(key: String): JsonValue? = fields[key]
    override fun toString(): String = stringify()
}

/** Thrown by [Json.parse] on anything `JSON.parse` would throw on. */
public class JsonParseException(message: String) : RuntimeException(message)

public object Json {
    /** `JSON.parse`, or a [JsonParseException] where that would throw. */
    public fun parse(text: String): JsonValue = JsonParser(text).parseDocument()

    /** `JSON.parse`, or null where that would throw. */
    public fun parseOrNull(text: String): JsonValue? = try {
        parse(text)
    } catch (_: JsonParseException) {
        null
    } catch (_: StackOverflowError) {
        null
    }
}

/** Builds a [JsonObject] in insertion order; a `null` value omits the key,
 *  the way `JSON.stringify` drops an `undefined` property. */
public fun jsonObject(vararg pairs: Pair<String, JsonValue?>): JsonObject {
    val map = LinkedHashMap<String, JsonValue>()
    for ((k, v) in pairs) if (v != null) map[k] = v
    return JsonObject(map)
}

public fun jsonArray(items: List<JsonValue>): JsonArray = JsonArray(items)
public fun jsonStrings(items: List<String>): JsonArray = JsonArray(items.map(::JsonString))
public fun String.toJson(): JsonString = JsonString(this)
public fun Long.toJson(): JsonNumber = JsonNumber(this)
public fun Int.toJson(): JsonNumber = JsonNumber(this)
public fun Boolean.toJson(): JsonBool = JsonBool(this)

// ---------------------------------------------------------------------------
// JavaScript value predicates. The TypeScript reference guards every wire
// field with one of these, so the port names them the same way.
// ---------------------------------------------------------------------------

internal const val MAX_SAFE_INTEGER: Double = 9007199254740991.0
internal const val MAX_SAFE_INTEGER_LONG: Long = 9007199254740991L

/** `typeof v === 'string'` */
internal fun JsonValue?.str(): String? = (this as? JsonString)?.value

/** `typeof v === 'number'` */
internal fun JsonValue?.num(): Double? = (this as? JsonNumber)?.value

/** `Number.isInteger(v)` */
internal fun JsonValue?.isInteger(): Boolean {
    val d = num() ?: return false
    return d.isFinite() && Math.floor(d) == d
}

/** `Number.isSafeInteger(v)` */
internal fun JsonValue?.isSafeInteger(): Boolean = isInteger() && Math.abs(num()!!) <= MAX_SAFE_INTEGER

/**
 * An integer `>= 0` that fits a [Long] exactly, or null. The TypeScript guards
 * are `Number.isInteger(v) && v >= 0`; this port also requires the value to be
 * a SAFE integer, because a JavaScript "integer" above 2^53 is already a
 * rounded value, and carrying it as a Long would claim a precision it never
 * had. See `docs/PORTING.md` in the conformance repository.
 */
internal fun JsonValue?.nonNegativeSafeLong(): Long? =
    if (isSafeInteger() && num()!! >= 0) num()!!.toLong() else null

internal fun JsonValue?.obj(): JsonObject? = this as? JsonObject

/** `typeof v === 'object' && v !== null` - arrays included, as in JavaScript. */
internal fun JsonValue?.isObjectLike(): Boolean = this is JsonObject || this is JsonArray

internal fun JsonValue?.arr(): List<JsonValue>? = (this as? JsonArray)?.items

/** Property read on a value that may be an array: arrays have no named wire fields. */
internal fun JsonValue?.field(key: String): JsonValue? = (this as? JsonObject)?.fields?.get(key)

/** `v === true` */
internal fun JsonValue?.isTrue(): Boolean = this is JsonBool && value

/** Strict equality against a number literal, as `o.v !== 2` compares. */
internal fun JsonValue?.isNumber(n: Int): Boolean = this is JsonNumber && value == n.toDouble()

private object JsonWriter {
    fun write(value: JsonValue, out: StringBuilder) {
        when (value) {
            JsonNull -> out.append("null")
            is JsonBool -> out.append(if (value.value) "true" else "false")
            is JsonNumber -> out.append(JsNumber.toString(value.value))
            is JsonString -> writeString(value.value, out)
            is JsonArray -> {
                out.append('[')
                value.items.forEachIndexed { i, item ->
                    if (i > 0) out.append(',')
                    write(item, out)
                }
                out.append(']')
            }
            is JsonObject -> {
                out.append('{')
                var first = true
                for ((k, v) in value.fields) {
                    if (!first) out.append(',')
                    first = false
                    writeString(k, out)
                    out.append(':')
                    write(v, out)
                }
                out.append('}')
            }
        }
    }

    /** ECMA-262 QuoteJSONString, including the well-formed-stringify rule for
     *  lone surrogates. */
    fun writeString(s: String, out: StringBuilder) {
        out.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' -> out.append("\\\"")
                c == '\\' -> out.append("\\\\")
                c == '\b' -> out.append("\\b")
                c == '\u000c' -> out.append("\\f")
                c == '\n' -> out.append("\\n")
                c == '\r' -> out.append("\\r")
                c == '\t' -> out.append("\\t")
                c < ' ' -> out.append("\\u").append(hex4(c))
                Character.isHighSurrogate(c) -> {
                    if (i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
                        out.append(c).append(s[i + 1])
                        i++
                    } else {
                        out.append("\\u").append(hex4(c))
                    }
                }
                Character.isLowSurrogate(c) -> out.append("\\u").append(hex4(c))
                else -> out.append(c)
            }
            i++
        }
        out.append('"')
    }

    private fun hex4(c: Char): String = c.code.toString(16).padStart(4, '0')
}

/** `Number.prototype.toString()` for the values this wire can carry. */
internal object JsNumber {
    fun toString(d: Double): String {
        if (d.isNaN() || d.isInfinite()) return "null" // JSON.stringify's rule
        if (d == 0.0) return "0" // -0 prints as 0
        // Every integer below 2^53 needs all its digits, so it prints as itself.
        if (Math.floor(d) == d && Math.abs(d) < 9007199254740992.0) return d.toLong().toString()
        val negative = d < 0
        val abs = Math.abs(d)
        // The shortest decimal that round-trips, and of those the closest
        // (ECMA-262 Number::toString). Double.toString is not a safe source:
        // it keeps a fractional digit, so it prints 4.9E-324 where the
        // shortest form is 5e-324, and older runtimes are not shortest at all.
        val exact = java.math.BigDecimal(abs)
        var bd = exact
        for (p in 1..17) {
            val candidate = exact.round(java.math.MathContext(p, java.math.RoundingMode.HALF_EVEN))
            if (candidate.toDouble() == abs) {
                bd = candidate
                break
            }
        }
        bd = bd.stripTrailingZeros()
        val digits = bd.unscaledValue().toString()
        val k = digits.length
        val n = k - bd.scale() // decimal point position, as in ECMA-262 Number::toString
        val body = when {
            n in k..21 -> digits + "0".repeat(n - k)
            n in 1..21 -> digits.substring(0, n) + "." + digits.substring(n)
            n in -5..0 -> "0." + "0".repeat(-n) + digits
            else -> {
                val e = n - 1
                val exp = if (e >= 0) "+$e" else "$e"
                if (k == 1) "${digits}e$exp" else "${digits[0]}.${digits.substring(1)}e$exp"
            }
        }
        return if (negative) "-$body" else body
    }
}

private class JsonParser(private val s: String) {
    private var i = 0
    private var depth = 0

    fun parseDocument(): JsonValue {
        skipWs()
        val v = parseValue()
        skipWs()
        if (i != s.length) fail("trailing data")
        return v
    }

    private fun fail(msg: String): Nothing = throw JsonParseException("$msg at $i")

    // JSON whitespace is exactly these four; JSON.parse accepts no others.
    private fun skipWs() {
        while (i < s.length) {
            when (s[i]) {
                ' ', '\t', '\n', '\r' -> i++
                else -> return
            }
        }
    }

    private fun parseValue(): JsonValue {
        if (i >= s.length) fail("unexpected end")
        return when (val c = s[i]) {
            '{' -> parseObject()
            '[' -> parseArray()
            '"' -> JsonString(parseString())
            't' -> literal("true", JsonBool(true))
            'f' -> literal("false", JsonBool(false))
            'n' -> literal("null", JsonNull)
            else -> if (c == '-' || c in '0'..'9') parseNumber() else fail("unexpected '$c'")
        }
    }

    private fun literal(word: String, v: JsonValue): JsonValue {
        if (!s.startsWith(word, i)) fail("bad literal")
        i += word.length
        return v
    }

    private fun enter() {
        // A hostile relay must not be able to buy a stack overflow with nesting.
        if (++depth > 512) fail("nesting too deep")
    }

    private fun parseObject(): JsonValue {
        enter()
        i++ // {
        val map = LinkedHashMap<String, JsonValue>()
        skipWs()
        if (i < s.length && s[i] == '}') {
            i++; depth--; return JsonObject(map)
        }
        while (true) {
            skipWs()
            if (i >= s.length || s[i] != '"') fail("expected key")
            val key = parseString()
            skipWs()
            if (i >= s.length || s[i] != ':') fail("expected ':'")
            i++
            skipWs()
            map[key] = parseValue()
            skipWs()
            if (i >= s.length) fail("unexpected end")
            when (s[i]) {
                ',' -> i++
                '}' -> { i++; depth--; return JsonObject(map) }
                else -> fail("expected ',' or '}'")
            }
        }
    }

    private fun parseArray(): JsonValue {
        enter()
        i++ // [
        val items = ArrayList<JsonValue>()
        skipWs()
        if (i < s.length && s[i] == ']') {
            i++; depth--; return JsonArray(items)
        }
        while (true) {
            skipWs()
            items.add(parseValue())
            skipWs()
            if (i >= s.length) fail("unexpected end")
            when (s[i]) {
                ',' -> i++
                ']' -> { i++; depth--; return JsonArray(items) }
                else -> fail("expected ',' or ']'")
            }
        }
    }

    private fun parseString(): String {
        i++ // opening quote
        val sb = StringBuilder()
        while (true) {
            if (i >= s.length) fail("unterminated string")
            val c = s[i]
            when {
                c == '"' -> { i++; return sb.toString() }
                c == '\\' -> {
                    i++
                    if (i >= s.length) fail("bad escape")
                    when (s[i]) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000c')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> {
                            var code = 0
                            for (j in 1..4) {
                                val h = s.getOrNull(i + j) ?: fail("bad unicode escape")
                                val d = Character.digit(h, 16)
                                if (d < 0 || h.code > 0x7f) fail("bad unicode escape")
                                code = code * 16 + d
                            }
                            sb.append(code.toChar())
                            i += 4
                        }
                        else -> fail("bad escape")
                    }
                    i++
                }
                c < ' ' -> fail("control character in string")
                else -> { sb.append(c); i++ }
            }
        }
    }

    private fun parseNumber(): JsonValue {
        val start = i
        if (s[i] == '-') i++
        if (i >= s.length) fail("bad number")
        if (s[i] == '0') {
            i++
        } else if (s[i] in '1'..'9') {
            while (i < s.length && s[i] in '0'..'9') i++
        } else {
            fail("bad number")
        }
        if (i < s.length && s[i] == '.') {
            i++
            if (i >= s.length || s[i] !in '0'..'9') fail("bad number")
            while (i < s.length && s[i] in '0'..'9') i++
        }
        if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
            i++
            if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
            if (i >= s.length || s[i] !in '0'..'9') fail("bad number")
            while (i < s.length && s[i] in '0'..'9') i++
        }
        // Java's decimal parser rounds correctly, as ECMA-262 requires.
        return JsonNumber(s.substring(start, i).toDouble())
    }
}
