#ifndef PHONEKEY_CHALLENGE_GENERATOR_H
#define PHONEKEY_CHALLENGE_GENERATOR_H

#include "../common/CryptoEngine.h"
#include "../common/Protocol.h"
#include <array>
#include <chrono>

namespace PhoneKey {

struct ChallengeRecord {
    std::array<uint8_t, UUID_SIZE> sessionId;
    std::array<uint8_t, UUID_SIZE> deviceId;
    std::array<uint8_t, UUID_SIZE> pcId;
    std::array<uint8_t, CHALLENGE_SIZE> challenge;
    uint64_t creationTimestampMs;
    uint64_t expirationTimestampMs;
    enum class State { OUTSTANDING, CONSUMED, EXPIRED } state;
};

class ChallengeGenerator {
public:
    explicit ChallengeGenerator(CryptoEngine& cryptoEngine);

    // Creates a new 256-bit CSPRNG challenge record with 30s TTL
    ChallengeRecord GenerateChallenge(const std::array<uint8_t, UUID_SIZE>& deviceId, const std::array<uint8_t, UUID_SIZE>& pcId);

private:
    CryptoEngine& m_cryptoEngine;
};

} // namespace PhoneKey

#endif // PHONEKEY_CHALLENGE_GENERATOR_H
