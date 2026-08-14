package com.phonekey.pairing

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

object HkdfManager {

    fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        val secretKey = SecretKeySpec(key, "HmacSHA256")
        mac.init(secretKey)
        return mac.doFinal(data)
    }

    fun extract(salt: ByteArray?, ikm: ByteArray): ByteArray {
        val actualSalt = if (salt == null || salt.isEmpty()) ByteArray(32) else salt
        return hmacSha256(actualSalt, ikm)
    }

    fun expand(prk: ByteArray, info: String, outLen: Int): ByteArray {
        val result = ByteArray(outLen)
        var t = ByteArray(0)
        var counter: Byte = 1
        var offset = 0

        val infoBytes = info.toByteArray(Charsets.UTF_8)

        while (offset < outLen) {
            val msg = t + infoBytes + byteArrayOf(counter)
            t = hmacSha256(prk, msg)

            val toCopy = Math.min(t.size, outLen - offset)
            System.arraycopy(t, 0, result, offset, toCopy)
            offset += toCopy
            counter++
        }

        return result
    }

    fun deriveKey(salt: ByteArray?, ikm: ByteArray, info: String, outLen: Int): ByteArray {
        val prk = extract(salt, ikm)
        return expand(prk, info, outLen)
    }
}
