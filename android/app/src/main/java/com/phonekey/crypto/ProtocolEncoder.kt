package com.phonekey.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.Arrays

object ProtocolEncoder {

    val DOMAIN_BYTES = "PhoneKey-Auth-v1".toByteArray(Charsets.US_ASCII)
    const val DOMAIN_FIELD_SIZE = 16
    const val CANONICAL_PAYLOAD_SIZE = 108
    const val CURRENT_PROTOCOL_VERSION: Short = 0x0100
    const val ALGORITHM_ECDSA_P256_SHA256: Short = 0x0001

    data class AuthPayload(
        val domain: ByteArray = ByteArray(DOMAIN_FIELD_SIZE).apply {
            System.arraycopy(DOMAIN_BYTES, 0, this, 0, DOMAIN_BYTES.size)
        },
        val protocolVersion: Short = CURRENT_PROTOCOL_VERSION,
        val algorithmId: Short = ALGORITHM_ECDSA_P256_SHA256,
        val deviceId: ByteArray,
        val sessionId: ByteArray,
        val pcId: ByteArray,
        val challenge: ByteArray,
        val expirationTimestampMs: Long
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AuthPayload) return false
            return domain.contentEquals(other.domain) &&
                   protocolVersion == other.protocolVersion &&
                   algorithmId == other.algorithmId &&
                   deviceId.contentEquals(other.deviceId) &&
                   sessionId.contentEquals(other.sessionId) &&
                   pcId.contentEquals(other.pcId) &&
                   challenge.contentEquals(other.challenge) &&
                   expirationTimestampMs == other.expirationTimestampMs
        }

        override fun hashCode(): Int {
            var result = domain.contentHashCode()
            result = 31 * result + protocolVersion
            result = 31 * result + algorithmId
            result = 31 * result + deviceId.contentHashCode()
            result = 31 * result + sessionId.contentHashCode()
            result = 31 * result + pcId.contentHashCode()
            result = 31 * result + challenge.contentHashCode()
            result = 31 * result + expirationTimestampMs.hashCode()
            return result
        }
    }

    fun encode(payload: AuthPayload): ByteArray {
        require(payload.deviceId.size == 16) { "DeviceId must be 16 bytes" }
        require(payload.sessionId.size == 16) { "SessionId must be 16 bytes" }
        require(payload.pcId.size == 16) { "PcId must be 16 bytes" }
        require(payload.challenge.size == 32) { "Challenge must be 32 bytes" }

        val buffer = ByteBuffer.allocate(CANONICAL_PAYLOAD_SIZE).order(ByteOrder.BIG_ENDIAN)

        // 1. Domain (16 Bytes)
        val domainFixed = ByteArray(16)
        System.arraycopy(payload.domain, 0, domainFixed, 0, Math.min(payload.domain.size, 16))
        buffer.put(domainFixed)

        // 2. ProtocolVersion (2 Bytes)
        buffer.putShort(payload.protocolVersion)

        // 3. AlgorithmID (2 Bytes)
        buffer.putShort(payload.algorithmId)

        // 4. DeviceID (16 Bytes)
        buffer.put(payload.deviceId)

        // 5. SessionID (16 Bytes)
        buffer.put(payload.sessionId)

        // 6. IntendedPCID (16 Bytes)
        buffer.put(payload.pcId)

        // 7. Challenge (32 Bytes)
        buffer.put(payload.challenge)

        // 8. ExpirationTimestamp (8 Bytes)
        buffer.putLong(payload.expirationTimestampMs)

        return buffer.array()
    }

    fun decode(bytes: ByteArray): AuthPayload {
        require(bytes.size == CANONICAL_PAYLOAD_SIZE) { "Payload size must be exactly 108 bytes" }

        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)

        val domain = ByteArray(16)
        buffer.get(domain)

        val version = buffer.short
        val algorithm = buffer.short

        val deviceId = ByteArray(16)
        buffer.get(deviceId)

        val sessionId = ByteArray(16)
        buffer.get(sessionId)

        val pcId = ByteArray(16)
        buffer.get(pcId)

        val challenge = ByteArray(32)
        buffer.get(challenge)

        val expiration = buffer.long

        return AuthPayload(
            domain = domain,
            protocolVersion = version,
            algorithmId = algorithm,
            deviceId = deviceId,
            sessionId = sessionId,
            pcId = pcId,
            challenge = challenge,
            expirationTimestampMs = expiration
        )
    }
}
