package com.phonekey.crypto

object ProtocolValidator {

    enum class ErrorCode {
        SUCCESS,
        INVALID_REQUEST,
        INVALID_PROTOCOL_VERSION,
        INVALID_ALGORITHM,
        EXPIRED
    }

    fun validate(payload: ProtocolEncoder.AuthPayload, currentTimeMs: Long): ErrorCode {
        // Verify domain prefix
        val expectedDomain = "PhoneKey-Auth-v1".toByteArray(Charsets.US_ASCII)
        for (i in expectedDomain.indices) {
            if (payload.domain[i] != expectedDomain[i]) {
                return ErrorCode.INVALID_REQUEST
            }
        }

        // Verify version
        if (payload.protocolVersion != ProtocolEncoder.CURRENT_PROTOCOL_VERSION) {
            return ErrorCode.INVALID_PROTOCOL_VERSION
        }

        // Verify algorithm
        if (payload.algorithmId != ProtocolEncoder.ALGORITHM_ECDSA_P256_SHA256) {
            return ErrorCode.INVALID_ALGORITHM
        }

        // Verify expiration
        if (currentTimeMs > payload.expirationTimestampMs) {
            return ErrorCode.EXPIRED
        }

        return ErrorCode.SUCCESS
    }
}
