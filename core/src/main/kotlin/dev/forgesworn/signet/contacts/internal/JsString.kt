package dev.forgesworn.signet.contacts.internal

import dev.forgesworn.signet.contacts.json.JsNumber
import dev.forgesworn.signet.contacts.json.JsonArray
import dev.forgesworn.signet.contacts.json.JsonBool
import dev.forgesworn.signet.contacts.json.JsonNull
import dev.forgesworn.signet.contacts.json.JsonNumber
import dev.forgesworn.signet.contacts.json.JsonObject
import dev.forgesworn.signet.contacts.json.JsonString
import dev.forgesworn.signet.contacts.json.JsonValue

/** JavaScript's `String(value)` for a JSON value, with a missing value as `undefined`. */
internal fun jsString(value: JsonValue?): String = when (value) {
    null -> "undefined"
    JsonNull -> "null"
    is JsonBool -> value.value.toString()
    is JsonNumber -> if (value.value.isNaN()) "NaN" else if (value.value.isInfinite()) {
        if (value.value > 0) "Infinity" else "-Infinity"
    } else JsNumber.toString(value.value)
    is JsonString -> value.value
    is JsonObject -> "[object Object]"
    // Array#toString is join(','), with null and undefined elements as ''.
    is JsonArray -> value.items.joinToString(",") { if (it == JsonNull) "" else jsString(it) }
}
