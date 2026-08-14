package com.phonekey.pairing

object SasManager {

    fun computeSasPin(kSas: ByteArray): String {
        if (kSas.isEmpty()) return "000000"

        val mac = HkdfManager.hmacSha256(kSas, "PhoneKey-SAS-PIN".toByteArray(Charsets.UTF_8))
        if (mac.size < 4) return "000000"

        val val32 = ((mac[0].toInt() and 0xFF) shl 24) or
                    ((mac[1].toInt() and 0xFF) shl 16) or
                    ((mac[2].toInt() and 0xFF) shl 8)  or
                     (mac[3].toInt() and 0xFF)

        // Ensure non-negative unsigned value
        val unsignedVal = val32.toLong() and 0xFFFFFFFFL
        val pin = (unsignedVal % 900000) + 100000

        return String.format("%06d", pin)
    }
}
