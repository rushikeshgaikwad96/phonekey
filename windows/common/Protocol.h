#ifndef PHONEKEY_PROTOCOL_H
#define PHONEKEY_PROTOCOL_H

#include <cstdint>
#include <cstddef>
#include <array>
#include <vector>
#include <string>
#include <system_error>

namespace PhoneKey {

// Protocol Constants
constexpr size_t DOMAIN_SIZE = 16;
constexpr size_t UUID_SIZE = 16;
constexpr size_t CHALLENGE_SIZE = 32;
constexpr size_t CANONICAL_PAYLOAD_SIZE = 108;

constexpr const char DOMAIN_PREFIX[16] = {'P', 'h', 'o', 'n', 'e', 'K', 'e', 'y', '-', 'A', 'u', 't', 'h', '-', 'v', '1'};

constexpr uint16_t CURRENT_PROTOCOL_VERSION = 0x0100; // v1.0
constexpr uint16_t ALGORITHM_ECDSA_P256_SHA256 = 0x0001;
constexpr uint64_t DEFAULT_CHALLENGE_TTL_MS = 30000; // 30 Seconds

// Error Codes
enum class ErrorCode : uint16_t {
    SUCCESS                     = 0x0000,
    INVALID_REQUEST             = 0x0001,
    INVALID_PROTOCOL_VERSION    = 0x0002,
    INVALID_ALGORITHM           = 0x0003,
    UNKNOWN_DEVICE              = 0x0004,
    INVALID_SIGNATURE           = 0x0005,
    CHALLENGE_NOT_FOUND         = 0x0006,
    CHALLENGE_EXPIRED           = 0x0007,
    CHALLENGE_ALREADY_CONSUMED  = 0x0008,
    SESSION_MISMATCH            = 0x0009,
    DEVICE_MISMATCH             = 0x000A,
    PC_MISMATCH                 = 0x000B,
    MALFORMED_SIGNATURE         = 0x000C,
    CRYPTO_ERROR                = 0x000D,
    BIOMETRIC_REQUIRED          = 0x000E,
    BIOMETRIC_FAILED            = 0x000F,
    KEY_INVALIDATED             = 0x0010
};

std::string ErrorCodeToString(ErrorCode code);

// Canonical Binary Payload Structure (108 Bytes)
struct AuthPayload {
    std::array<uint8_t, DOMAIN_SIZE> domain;
    uint16_t protocolVersion;
    uint16_t algorithmId;
    std::array<uint8_t, UUID_SIZE> deviceId;
    std::array<uint8_t, UUID_SIZE> sessionId;
    std::array<uint8_t, UUID_SIZE> pcId;
    std::array<uint8_t, CHALLENGE_SIZE> challenge;
    uint64_t expirationTimestampMs;

    AuthPayload();
    
    // Serializes AuthPayload to 108-byte Big-Endian buffer
    std::vector<uint8_t> Serialize() const;

    // Deserializes 108-byte buffer into AuthPayload structure
    static bool Deserialize(const uint8_t* data, size_t size, AuthPayload& outPayload, ErrorCode& outError);
};

} // namespace PhoneKey

#endif // PHONEKEY_PROTOCOL_H
