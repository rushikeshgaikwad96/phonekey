#include "ChallengeGenerator.h"
#include <chrono>

namespace PhoneKey {

ChallengeGenerator::ChallengeGenerator(CryptoEngine& cryptoEngine)
    : m_cryptoEngine(cryptoEngine) {}

ChallengeRecord ChallengeGenerator::GenerateChallenge(const std::array<uint8_t, UUID_SIZE>& deviceId, const std::array<uint8_t, UUID_SIZE>& pcId) {
    ChallengeRecord record;
    record.deviceId = deviceId;
    record.pcId = pcId;

    // Generate 16 random bytes for session ID
    m_cryptoEngine.GenerateRandomBytes(record.sessionId.data(), UUID_SIZE);

    // Generate 32 random bytes for challenge nonce
    m_cryptoEngine.GenerateRandomBytes(record.challenge.data(), CHALLENGE_SIZE);

    uint64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    record.creationTimestampMs = nowMs;
    record.expirationTimestampMs = nowMs + DEFAULT_CHALLENGE_TTL_MS; // 30s TTL
    record.state = ChallengeRecord::State::OUTSTANDING;

    return record;
}

} // namespace PhoneKey
