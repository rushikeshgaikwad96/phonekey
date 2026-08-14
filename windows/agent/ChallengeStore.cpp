#include "ChallengeStore.h"
#include <sstream>
#include <iomanip>
#include <cstring>

namespace PhoneKey {

ChallengeStore::ChallengeStore() {}

std::string ChallengeStore::BytesToKey(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

void ChallengeStore::AddChallenge(const ChallengeRecord& record) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string key = BytesToKey(record.sessionId.data(), UUID_SIZE);
    m_store[key] = record;
}

ErrorCode ChallengeStore::ValidateChallenge(const std::array<uint8_t, UUID_SIZE>& sessionId,
                                            const std::array<uint8_t, UUID_SIZE>& deviceId,
                                            const std::array<uint8_t, UUID_SIZE>& pcId,
                                            const std::array<uint8_t, CHALLENGE_SIZE>& challenge,
                                            uint64_t currentTimeMs,
                                            ChallengeRecord& outRecord) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string key = BytesToKey(sessionId.data(), UUID_SIZE);

    auto it = m_store.find(key);
    if (it == m_store.end()) {
        return ErrorCode::CHALLENGE_NOT_FOUND;
    }

    const ChallengeRecord& rec = it->second;

    if (rec.state == ChallengeRecord::State::CONSUMED) {
        return ErrorCode::CHALLENGE_ALREADY_CONSUMED;
    }

    if (rec.state == ChallengeRecord::State::EXPIRED || currentTimeMs > rec.expirationTimestampMs) {
        return ErrorCode::CHALLENGE_EXPIRED;
    }

    if (std::memcmp(rec.deviceId.data(), deviceId.data(), UUID_SIZE) != 0) {
        return ErrorCode::DEVICE_MISMATCH;
    }

    if (std::memcmp(rec.pcId.data(), pcId.data(), UUID_SIZE) != 0) {
        return ErrorCode::PC_MISMATCH;
    }

    if (std::memcmp(rec.challenge.data(), challenge.data(), CHALLENGE_SIZE) != 0) {
        return ErrorCode::CHALLENGE_NOT_FOUND;
    }

    outRecord = rec;
    return ErrorCode::SUCCESS;
}

ErrorCode ChallengeStore::ConsumeChallenge(const std::array<uint8_t, UUID_SIZE>& sessionId,
                                           const std::array<uint8_t, UUID_SIZE>& deviceId,
                                           const std::array<uint8_t, UUID_SIZE>& pcId,
                                           const std::array<uint8_t, CHALLENGE_SIZE>& challenge,
                                           uint64_t currentTimeMs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string key = BytesToKey(sessionId.data(), UUID_SIZE);

    auto it = m_store.find(key);
    if (it == m_store.end()) {
        return ErrorCode::CHALLENGE_NOT_FOUND;
    }

    ChallengeRecord& rec = it->second;

    if (rec.state == ChallengeRecord::State::CONSUMED) {
        return ErrorCode::CHALLENGE_ALREADY_CONSUMED;
    }

    if (rec.state == ChallengeRecord::State::EXPIRED || currentTimeMs > rec.expirationTimestampMs) {
        rec.state = ChallengeRecord::State::EXPIRED;
        return ErrorCode::CHALLENGE_EXPIRED;
    }

    if (std::memcmp(rec.deviceId.data(), deviceId.data(), UUID_SIZE) != 0) {
        return ErrorCode::DEVICE_MISMATCH;
    }

    if (std::memcmp(rec.pcId.data(), pcId.data(), UUID_SIZE) != 0) {
        return ErrorCode::PC_MISMATCH;
    }

    if (std::memcmp(rec.challenge.data(), challenge.data(), CHALLENGE_SIZE) != 0) {
        return ErrorCode::CHALLENGE_NOT_FOUND;
    }

    // Atomically mark challenge CONSUMED
    rec.state = ChallengeRecord::State::CONSUMED;
    return ErrorCode::SUCCESS;
}

ErrorCode ChallengeStore::ValidateAndConsumeChallenge(const std::array<uint8_t, UUID_SIZE>& sessionId,
                                                      const std::array<uint8_t, UUID_SIZE>& deviceId,
                                                      const std::array<uint8_t, UUID_SIZE>& pcId,
                                                      const std::array<uint8_t, CHALLENGE_SIZE>& challenge,
                                                      uint64_t currentTimeMs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string key = BytesToKey(sessionId.data(), UUID_SIZE);

    auto it = m_store.find(key);
    if (it == m_store.end()) {
        return ErrorCode::CHALLENGE_NOT_FOUND;
    }

    ChallengeRecord& rec = it->second;

    if (rec.state == ChallengeRecord::State::CONSUMED) {
        return ErrorCode::CHALLENGE_ALREADY_CONSUMED;
    }

    if (rec.state == ChallengeRecord::State::EXPIRED || currentTimeMs > rec.expirationTimestampMs) {
        rec.state = ChallengeRecord::State::EXPIRED;
        return ErrorCode::CHALLENGE_EXPIRED;
    }

    if (std::memcmp(rec.deviceId.data(), deviceId.data(), UUID_SIZE) != 0) {
        return ErrorCode::DEVICE_MISMATCH;
    }

    if (std::memcmp(rec.pcId.data(), pcId.data(), UUID_SIZE) != 0) {
        return ErrorCode::PC_MISMATCH;
    }

    if (std::memcmp(rec.challenge.data(), challenge.data(), CHALLENGE_SIZE) != 0) {
        return ErrorCode::CHALLENGE_NOT_FOUND;
    }

    // Atomically mark CONSUMED in single lock acquisition
    rec.state = ChallengeRecord::State::CONSUMED;
    return ErrorCode::SUCCESS;
}

size_t ChallengeStore::ExpireChallenges(uint64_t currentTimeMs) {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count = 0;
    for (auto& pair : m_store) {
        if (pair.second.state == ChallengeRecord::State::OUTSTANDING && currentTimeMs > pair.second.expirationTimestampMs) {
            pair.second.state = ChallengeRecord::State::EXPIRED;
            count++;
        }
    }
    return count;
}

size_t ChallengeStore::GetActiveCount() {
    std::lock_guard<std::mutex> lock(m_mutex);
    size_t count = 0;
    for (const auto& pair : m_store) {
        if (pair.second.state == ChallengeRecord::State::OUTSTANDING) {
            count++;
        }
    }
    return count;
}

} // namespace PhoneKey
