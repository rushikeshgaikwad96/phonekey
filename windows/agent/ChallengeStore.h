#ifndef PHONEKEY_CHALLENGE_STORE_H
#define PHONEKEY_CHALLENGE_STORE_H

#include "ChallengeGenerator.h"
#include "../common/Protocol.h"
#include <unordered_map>
#include <mutex>
#include <vector>
#include <array>

namespace PhoneKey {

class ChallengeStore {
public:
    ChallengeStore();

    // Stores a newly generated challenge record
    void AddChallenge(const ChallengeRecord& record);

    // Validates a challenge record without consuming it
    ErrorCode ValidateChallenge(const std::array<uint8_t, UUID_SIZE>& sessionId,
                                const std::array<uint8_t, UUID_SIZE>& deviceId,
                                const std::array<uint8_t, UUID_SIZE>& pcId,
                                const std::array<uint8_t, CHALLENGE_SIZE>& challenge,
                                uint64_t currentTimeMs,
                                ChallengeRecord& outRecord);

    // Atomically consumes an outstanding challenge, marking it CONSUMED
    ErrorCode ConsumeChallenge(const std::array<uint8_t, UUID_SIZE>& sessionId,
                               const std::array<uint8_t, UUID_SIZE>& deviceId,
                               const std::array<uint8_t, UUID_SIZE>& pcId,
                               const std::array<uint8_t, CHALLENGE_SIZE>& challenge,
                               uint64_t currentTimeMs);

    // Atomically validates AND consumes challenge in a single thread-safe operation
    ErrorCode ValidateAndConsumeChallenge(const std::array<uint8_t, UUID_SIZE>& sessionId,
                                          const std::array<uint8_t, UUID_SIZE>& deviceId,
                                          const std::array<uint8_t, UUID_SIZE>& pcId,
                                          const std::array<uint8_t, CHALLENGE_SIZE>& challenge,
                                          uint64_t currentTimeMs);

    // Purges expired challenges from store
    size_t ExpireChallenges(uint64_t currentTimeMs);

    // Helper: Gets count of active challenges in store
    size_t GetActiveCount();

private:
    std::mutex m_mutex;
    // Map key is session ID
    std::unordered_map<std::string, ChallengeRecord> m_store;

    static std::string BytesToKey(const uint8_t* data, size_t len);
};

} // namespace PhoneKey

#endif // PHONEKEY_CHALLENGE_STORE_H
