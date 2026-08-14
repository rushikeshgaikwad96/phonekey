#include "Protocol.h"
#include <cstring>
#include <algorithm>

namespace PhoneKey {

std::string ErrorCodeToString(ErrorCode code) {
    switch (code) {
        case ErrorCode::SUCCESS: return "SUCCESS";
        case ErrorCode::INVALID_REQUEST: return "INVALID_REQUEST";
        case ErrorCode::INVALID_PROTOCOL_VERSION: return "INVALID_PROTOCOL_VERSION";
        case ErrorCode::INVALID_ALGORITHM: return "INVALID_ALGORITHM";
        case ErrorCode::UNKNOWN_DEVICE: return "UNKNOWN_DEVICE";
        case ErrorCode::INVALID_SIGNATURE: return "INVALID_SIGNATURE";
        case ErrorCode::CHALLENGE_NOT_FOUND: return "CHALLENGE_NOT_FOUND";
        case ErrorCode::CHALLENGE_EXPIRED: return "CHALLENGE_EXPIRED";
        case ErrorCode::CHALLENGE_ALREADY_CONSUMED: return "CHALLENGE_ALREADY_CONSUMED";
        case ErrorCode::SESSION_MISMATCH: return "SESSION_MISMATCH";
        case ErrorCode::DEVICE_MISMATCH: return "DEVICE_MISMATCH";
        case ErrorCode::PC_MISMATCH: return "PC_MISMATCH";
        case ErrorCode::MALFORMED_SIGNATURE: return "MALFORMED_SIGNATURE";
        case ErrorCode::CRYPTO_ERROR: return "CRYPTO_ERROR";
        case ErrorCode::BIOMETRIC_REQUIRED: return "BIOMETRIC_REQUIRED";
        case ErrorCode::BIOMETRIC_FAILED: return "BIOMETRIC_FAILED";
        case ErrorCode::KEY_INVALIDATED: return "KEY_INVALIDATED";
        default: return "UNKNOWN_ERROR";
    }
}

AuthPayload::AuthPayload() {
    std::memcpy(domain.data(), DOMAIN_PREFIX, DOMAIN_SIZE);
    protocolVersion = CURRENT_PROTOCOL_VERSION;
    algorithmId = ALGORITHM_ECDSA_P256_SHA256;
    deviceId.fill(0);
    sessionId.fill(0);
    pcId.fill(0);
    challenge.fill(0);
    expirationTimestampMs = 0;
}

std::vector<uint8_t> AuthPayload::Serialize() const {
    std::vector<uint8_t> buffer(CANONICAL_PAYLOAD_SIZE, 0);
    size_t offset = 0;

    // 1. Domain (16 Bytes)
    std::memcpy(&buffer[offset], domain.data(), DOMAIN_SIZE);
    offset += DOMAIN_SIZE;

    // 2. ProtocolVersion (2 Bytes, Big-Endian)
    buffer[offset]     = static_cast<uint8_t>((protocolVersion >> 8) & 0xFF);
    buffer[offset + 1] = static_cast<uint8_t>(protocolVersion & 0xFF);
    offset += 2;

    // 3. AlgorithmID (2 Bytes, Big-Endian)
    buffer[offset]     = static_cast<uint8_t>((algorithmId >> 8) & 0xFF);
    buffer[offset + 1] = static_cast<uint8_t>(algorithmId & 0xFF);
    offset += 2;

    // 4. DeviceID (16 Bytes)
    std::memcpy(&buffer[offset], deviceId.data(), UUID_SIZE);
    offset += UUID_SIZE;

    // 5. SessionID (16 Bytes)
    std::memcpy(&buffer[offset], sessionId.data(), UUID_SIZE);
    offset += UUID_SIZE;

    // 6. IntendedPCID (16 Bytes)
    std::memcpy(&buffer[offset], pcId.data(), UUID_SIZE);
    offset += UUID_SIZE;

    // 7. Challenge (32 Bytes)
    std::memcpy(&buffer[offset], challenge.data(), CHALLENGE_SIZE);
    offset += CHALLENGE_SIZE;

    // 8. ExpirationTimestamp (8 Bytes, Big-Endian)
    for (int i = 7; i >= 0; --i) {
        buffer[offset + (7 - i)] = static_cast<uint8_t>((expirationTimestampMs >> (i * 8)) & 0xFF);
    }
    offset += 8;

    return buffer;
}

bool AuthPayload::Deserialize(const uint8_t* data, size_t size, AuthPayload& outPayload, ErrorCode& outError) {
    if (!data || size != CANONICAL_PAYLOAD_SIZE) {
        outError = ErrorCode::INVALID_REQUEST;
        return false;
    }

    size_t offset = 0;

    // 1. Domain
    std::memcpy(outPayload.domain.data(), &data[offset], DOMAIN_SIZE);
    if (std::memcmp(outPayload.domain.data(), DOMAIN_PREFIX, DOMAIN_SIZE) != 0) {
        outError = ErrorCode::INVALID_REQUEST;
        return false;
    }
    offset += DOMAIN_SIZE;

    // 2. ProtocolVersion
    outPayload.protocolVersion = (static_cast<uint16_t>(data[offset]) << 8) | static_cast<uint16_t>(data[offset + 1]);
    if (outPayload.protocolVersion != CURRENT_PROTOCOL_VERSION) {
        outError = ErrorCode::INVALID_PROTOCOL_VERSION;
        return false;
    }
    offset += 2;

    // 3. AlgorithmID
    outPayload.algorithmId = (static_cast<uint16_t>(data[offset]) << 8) | static_cast<uint16_t>(data[offset + 1]);
    if (outPayload.algorithmId != ALGORITHM_ECDSA_P256_SHA256) {
        outError = ErrorCode::INVALID_ALGORITHM;
        return false;
    }
    offset += 2;

    // 4. DeviceID
    std::memcpy(outPayload.deviceId.data(), &data[offset], UUID_SIZE);
    offset += UUID_SIZE;

    // 5. SessionID
    std::memcpy(outPayload.sessionId.data(), &data[offset], UUID_SIZE);
    offset += UUID_SIZE;

    // 6. IntendedPCID
    std::memcpy(outPayload.pcId.data(), &data[offset], UUID_SIZE);
    offset += UUID_SIZE;

    // 7. Challenge
    std::memcpy(outPayload.challenge.data(), &data[offset], CHALLENGE_SIZE);
    offset += CHALLENGE_SIZE;

    // 8. ExpirationTimestamp
    outPayload.expirationTimestampMs = 0;
    for (int i = 0; i < 8; ++i) {
        outPayload.expirationTimestampMs = (outPayload.expirationTimestampMs << 8) | static_cast<uint64_t>(data[offset + i]);
    }
    offset += 8;

    outError = ErrorCode::SUCCESS;
    return true;
}

} // namespace PhoneKey
