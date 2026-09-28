package dev.forgesworn.signet.contacts.nostr.internal

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** UTF-8 as `TextEncoder` writes it: a lone surrogate becomes U+FFFD. */
internal fun utf8(s: String): ByteArray {
    val sb = StringBuilder(s.length)
    var i = 0
    while (i < s.length) {
        val c = s[i]
        if (Character.isHighSurrogate(c) && i + 1 < s.length && Character.isLowSurrogate(s[i + 1])) {
            sb.append(c).append(s[i + 1])
            i += 2
            continue
        }
        sb.append(if (Character.isSurrogate(c)) '\ufffd' else c)
        i++
    }
    return sb.toString().toByteArray(Charsets.UTF_8)
}

internal fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray =
    Mac.getInstance("HmacSHA256").run {
        init(SecretKeySpec(key, "HmacSHA256"))
        for (p in parts) update(p)
        doFinal()
    }

/** RFC 8439 ChaCha20 with a 96-bit nonce, counter starting at 0: the stream NIP-44 v2 uses. */
internal object ChaCha20 {
    private fun rotl(v: Int, c: Int) = (v shl c) or (v ushr (32 - c))

    private fun le32(b: ByteArray, o: Int): Int =
        (b[o].toInt() and 0xff) or ((b[o + 1].toInt() and 0xff) shl 8) or
            ((b[o + 2].toInt() and 0xff) shl 16) or ((b[o + 3].toInt() and 0xff) shl 24)

    fun xor(key: ByteArray, nonce: ByteArray, input: ByteArray): ByteArray {
        require(key.size == 32 && nonce.size == 12)
        val state = IntArray(16)
        state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574
        for (i in 0 until 8) state[4 + i] = le32(key, i * 4)
        state[12] = 0
        for (i in 0 until 3) state[13 + i] = le32(nonce, i * 4)
        val out = ByteArray(input.size)
        val x = IntArray(16)
        val block = ByteArray(64)
        var offset = 0
        while (offset < input.size) {
            state.copyInto(x)
            repeat(10) {
                quarter(x, 0, 4, 8, 12); quarter(x, 1, 5, 9, 13); quarter(x, 2, 6, 10, 14); quarter(x, 3, 7, 11, 15)
                quarter(x, 0, 5, 10, 15); quarter(x, 1, 6, 11, 12); quarter(x, 2, 7, 8, 13); quarter(x, 3, 4, 9, 14)
            }
            for (i in 0 until 16) {
                val v = x[i] + state[i]
                block[i * 4] = v.toByte(); block[i * 4 + 1] = (v ushr 8).toByte()
                block[i * 4 + 2] = (v ushr 16).toByte(); block[i * 4 + 3] = (v ushr 24).toByte()
            }
            val n = minOf(64, input.size - offset)
            for (i in 0 until n) out[offset + i] = (input[offset + i].toInt() xor block[i].toInt()).toByte()
            offset += n
            state[12]++
        }
        x.fill(0); block.fill(0); state.fill(0)
        return out
    }

    private fun quarter(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 16)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 12)
        x[a] += x[b]; x[d] = rotl(x[d] xor x[a], 8)
        x[c] += x[d]; x[b] = rotl(x[b] xor x[c], 7)
    }
}
