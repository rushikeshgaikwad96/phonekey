#include <iostream>
#include <vector>
#include <string>
#include <cassert>
#include <thread>
#include <atomic>
#include <fstream>
#include <sstream>
#include <cstring>
#include "../windows/common/Protocol.h"
#include "../windows/common/CryptoEngine.h"
#include "../windows/agent/ChallengeGenerator.h"
#include "../windows/agent/ChallengeStore.h"
#include "../windows/agent/DeviceRegistry.h"

using namespace PhoneKey;

// Helper: Convert hex string to byte vector
std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Minimal JSON value extractor helper for test vectors
std::string ExtractJsonField(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    size_t colon = json.find(":", pos);
    if (colon == std::string::npos) return "";
    size_t start = json.find("\"", colon);
    if (start == std::string::npos) return "";
    size_t end = json.find("\"", start + 1);
    if (end == std::string::npos) return "";
    return json.substr(start + 1, end - start - 1);
}

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << " [FAIL] " << msg << " (Line " << __LINE__ << ")" << std::endl; \
        return false; \
    } else { \
        std::cout << " [PASS] " << msg << std::endl; \
    }

bool TestProtocolEncoding() {
    std::cout << "--- Running Protocol Encoding Tests ---" << std::endl;

    AuthPayload p1;
    p1.protocolVersion = 0x0100;
    p1.algorithmId = 0x0001;
    p1.deviceId.fill(0x11);
    p1.sessionId.fill(0xAA);
    p1.pcId.fill(0x99);
    p1.challenge.fill(0x77);
    p1.expirationTimestampMs = 1776182400000;

    std::vector<uint8_t> bytes = p1.Serialize();
    TEST_ASSERT(bytes.size() == 108, "Serialized payload size is exactly 108 bytes");
    TEST_ASSERT(std::memcmp(bytes.data(), DOMAIN_PREFIX, 16) == 0, "Domain prefix matches PhoneKey-Auth-v1");

    AuthPayload p2;
    ErrorCode err;
    bool desRes = AuthPayload::Deserialize(bytes.data(), bytes.size(), p2, err);
    TEST_ASSERT(desRes && err == ErrorCode::SUCCESS, "Deserialization succeeded");
    TEST_ASSERT(p2.protocolVersion == 0x0100, "Protocol version match");
    TEST_ASSERT(p2.algorithmId == 0x0001, "Algorithm ID match");
    TEST_ASSERT(p2.expirationTimestampMs == 1776182400000, "Expiration timestamp match");

    // Invalid length check
    bool invalidLen = AuthPayload::Deserialize(bytes.data(), 50, p2, err);
    TEST_ASSERT(!invalidLen && err == ErrorCode::INVALID_REQUEST, "Rejects invalid payload length");

    // Invalid version check
    bytes[16] = 0x02; // Change version to 0x0200
    bool invalidVer = AuthPayload::Deserialize(bytes.data(), bytes.size(), p2, err);
    TEST_ASSERT(!invalidVer && err == ErrorCode::INVALID_PROTOCOL_VERSION, "Rejects invalid protocol version");

    return true;
}

bool TestCrossPlatformTestVectors() {
    std::cout << "--- Running Cross-Platform Test Vector Verification ---" << std::endl;

    CryptoEngine crypto;
    TEST_ASSERT(crypto.Initialize(), "CryptoEngine CNG initialization");

    // Read valid test vector
    std::ifstream fValid("protocol/test-vectors/vector_valid.json");
    TEST_ASSERT(fValid.is_open(), "vector_valid.json file opened");
    std::stringstream bufValid; bufValid << fValid.rdbuf();
    std::string jsonValid = bufValid.str();

    std::string payloadHex = ExtractJsonField(jsonValid, "canonical_payload_hex");
    std::string pubRawHex  = ExtractJsonField(jsonValid, "public_key_raw_xy_hex");
    std::string sigDerHex  = ExtractJsonField(jsonValid, "signature_der_hex");

    TEST_ASSERT(!payloadHex.empty(), "Extracted canonical_payload_hex from test vector");
    TEST_ASSERT(!pubRawHex.empty(), "Extracted public_key_raw_xy_hex from test vector");
    TEST_ASSERT(!sigDerHex.empty(), "Extracted signature_der_hex from test vector");

    std::vector<uint8_t> payloadBytes = HexToBytes(payloadHex);
    std::vector<uint8_t> pubRawBytes  = HexToBytes(pubRawHex);
    std::vector<uint8_t> sigDerBytes  = HexToBytes(sigDerHex);

    TEST_ASSERT(payloadBytes.size() == 108, "Canonical payload length is 108 bytes");

    BCRYPT_KEY_HANDLE hKey = crypto.ImportRawPublicKey(pubRawBytes.data(), pubRawBytes.size());
    TEST_ASSERT(hKey != NULL, "Imported ECDSA P-256 public key into Windows CNG");

    bool verifySuccess = crypto.VerifySignature(hKey, payloadBytes.data(), payloadBytes.size(), sigDerBytes.data(), sigDerBytes.size());
    TEST_ASSERT(verifySuccess == true, "Valid cross-platform test vector signature verified successfully!");

    // Read tampered test vector
    std::ifstream fTampered("protocol/test-vectors/vector_tampered.json");
    TEST_ASSERT(fTampered.is_open(), "vector_tampered.json file opened");
    std::stringstream bufTampered; bufTampered << fTampered.rdbuf();
    std::string jsonTampered = bufTampered.str();

    std::string tamperedPayloadHex = ExtractJsonField(jsonTampered, "canonical_payload_hex");
    std::vector<uint8_t> tamperedPayloadBytes = HexToBytes(tamperedPayloadHex);

    bool tamperedResult = crypto.VerifySignature(hKey, tamperedPayloadBytes.data(), tamperedPayloadBytes.size(), sigDerBytes.data(), sigDerBytes.size());
    TEST_ASSERT(tamperedResult == false, "Tampered payload rejected by Windows CNG verifier!");

    BCryptDestroyKey(hKey);
    return true;
}

bool TestChallengeStoreAndReplayDefense() {
    std::cout << "--- Running Challenge Store & Replay Defense Tests ---" << std::endl;

    CryptoEngine crypto;
    crypto.Initialize();
    ChallengeGenerator gen(crypto);
    ChallengeStore store;

    std::array<uint8_t, 16> devId; devId.fill(0x22);
    std::array<uint8_t, 16> pcId; pcId.fill(0x88);

    ChallengeRecord rec = gen.GenerateChallenge(devId, pcId);
    store.AddChallenge(rec);

    uint64_t nowMs = rec.creationTimestampMs + 1000; // 1 second later

    // 1. Valid consumption
    ErrorCode err1 = store.ConsumeChallenge(rec.sessionId, devId, pcId, rec.challenge, nowMs);
    TEST_ASSERT(err1 == ErrorCode::SUCCESS, "First challenge consumption succeeds");

    // 2. Immediate Replay Attempt (Same Challenge)
    ErrorCode err2 = store.ConsumeChallenge(rec.sessionId, devId, pcId, rec.challenge, nowMs);
    TEST_ASSERT(err2 == ErrorCode::CHALLENGE_ALREADY_CONSUMED, "Replay attempt rejected with CHALLENGE_ALREADY_CONSUMED");

    // 3. Expired Challenge Test (30s TTL)
    ChallengeRecord recExpired = gen.GenerateChallenge(devId, pcId);
    store.AddChallenge(recExpired);
    uint64_t expiredTimeMs = recExpired.expirationTimestampMs + 5000; // 5 seconds after expiry
    ErrorCode errExpired = store.ConsumeChallenge(recExpired.sessionId, devId, pcId, recExpired.challenge, expiredTimeMs);
    TEST_ASSERT(errExpired == ErrorCode::CHALLENGE_EXPIRED, "Expired challenge rejected with CHALLENGE_EXPIRED");

    // 4. Unknown Challenge Test
    std::array<uint8_t, 16> fakeSession; fakeSession.fill(0xFF);
    ErrorCode errUnknown = store.ConsumeChallenge(fakeSession, devId, pcId, rec.challenge, nowMs);
    TEST_ASSERT(errUnknown == ErrorCode::CHALLENGE_NOT_FOUND, "Unknown challenge rejected with CHALLENGE_NOT_FOUND");

    return true;
}

bool TestConcurrentReplayRaceCondition() {
    std::cout << "--- Running Concurrent Multithreaded Replay Test ---" << std::endl;

    CryptoEngine crypto;
    crypto.Initialize();
    ChallengeGenerator gen(crypto);
    ChallengeStore store;

    std::array<uint8_t, 16> devId; devId.fill(0x33);
    std::array<uint8_t, 16> pcId; pcId.fill(0x77);

    ChallengeRecord rec = gen.GenerateChallenge(devId, pcId);
    store.AddChallenge(rec);

    const int NUM_THREADS = 20;
    std::atomic<int> successCount{0};
    std::atomic<int> replayCount{0};
    std::vector<std::thread> threads;

    uint64_t nowMs = rec.creationTimestampMs + 500;

    for (int i = 0; i < NUM_THREADS; ++i) {
        threads.emplace_back([&]() {
            ErrorCode err = store.ConsumeChallenge(rec.sessionId, devId, pcId, rec.challenge, nowMs);
            if (err == ErrorCode::SUCCESS) {
                successCount++;
            } else if (err == ErrorCode::CHALLENGE_ALREADY_CONSUMED) {
                replayCount++;
            }
        });
    }

    for (auto& t : threads) {
        t.join();
    }

    TEST_ASSERT(successCount.load() == 1, "Exactly ONE thread succeeded in concurrent race");
    TEST_ASSERT(replayCount.load() == NUM_THREADS - 1, "All other concurrent threads were rejected as replays");

    return true;
}

bool TestParserFuzzing() {
    std::cout << "--- Running Parser & Fuzzing Safety Tests ---" << std::endl;

    AuthPayload outP;
    ErrorCode err;

    // Test 1: Empty input
    bool res1 = AuthPayload::Deserialize(nullptr, 0, outP, err);
    TEST_ASSERT(!res1 && err == ErrorCode::INVALID_REQUEST, "Handles null/empty input without crash");

    // Test 2: Random binary fuzzing (1000 random iterations)
    CryptoEngine crypto;
    crypto.Initialize();
    int crashCount = 0;

    for (int i = 0; i < 1000; ++i) {
        std::vector<uint8_t> fuzzBuf(108);
        crypto.GenerateRandomBytes(fuzzBuf.data(), fuzzBuf.size());
        AuthPayload::Deserialize(fuzzBuf.data(), fuzzBuf.size(), outP, err);
    }

    TEST_ASSERT(crashCount == 0, "1000 random binary fuzz iterations completed without crash");

    return true;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "      PHONEKEY MILESTONE 2 AUTOMATED TEST SUITE    " << std::endl;
    std::cout << "====================================================" << std::endl;

    bool allPassed = true;
    allPassed &= TestProtocolEncoding();
    allPassed &= TestCrossPlatformTestVectors();
    allPassed &= TestChallengeStoreAndReplayDefense();
    allPassed &= TestConcurrentReplayRaceCondition();
    allPassed &= TestParserFuzzing();

    std::cout << "====================================================" << std::endl;
    if (allPassed) {
        std::cout << "    ALL MILESTONE 2 TESTS PASSED SUCCESSFULLY!    " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 0;
    } else {
        std::cerr << "    SOME TESTS FAILED!                            " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 1;
    }
}
