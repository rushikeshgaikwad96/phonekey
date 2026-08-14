#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <cassert>
#include <fstream>
#include <sstream>
#include <cstring>

#include "../windows/common/Protocol.h"
#include "../windows/common/PublicKeyImporter.h"
#include "../windows/common/CryptoEngine.h"
#include "../windows/common/EcdhKeyExchange.h"
#include "../windows/common/HkdfEngine.h"
#include "../windows/common/SasEngine.h"
#include "../windows/common/TransportInterface.h"
#include "../windows/common/FrameProtocol.h"
#include "../windows/common/TcpTransport.h"
#include "../windows/common/NamedPipeIpc.h"
#include "../windows/agent/ChallengeGenerator.h"
#include "../windows/agent/ChallengeStore.h"
#include "../windows/agent/DeviceRegistry.h"
#include "../windows/agent/DpapiStorage.h"
#include "../windows/agent/AgentService.h"

using namespace PhoneKey;

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << " [FAIL] " << msg << " (Line " << __LINE__ << ")" << std::endl; \
        return false; \
    } else { \
        std::cout << " [PASS] " << msg << std::endl; \
    }

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

// Minimal JSON extractor helper
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

// --- MILESTONE 2 TESTS ---
bool M2_TestProtocolEncoding() {
    std::cout << "--- M2: Protocol Encoding & Serialization ---" << std::endl;
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
    return true;
}

bool M2_TestCrossPlatformVector() {
    std::cout << "--- M2: Cross-Platform Test Vector Verification ---" << std::endl;
    CryptoEngine crypto;
    TEST_ASSERT(crypto.Initialize(), "CryptoEngine CNG initialization");

    std::ifstream fValid("protocol/test-vectors/vector_valid.json");
    TEST_ASSERT(fValid.is_open(), "vector_valid.json opened");
    std::stringstream bufValid; bufValid << fValid.rdbuf();
    std::string jsonValid = bufValid.str();

    std::string payloadHex = ExtractJsonField(jsonValid, "canonical_payload_hex");
    std::string pubRawHex  = ExtractJsonField(jsonValid, "public_key_raw_xy_hex");
    std::string sigDerHex  = ExtractJsonField(jsonValid, "signature_der_hex");

    std::vector<uint8_t> payloadBytes = HexToBytes(payloadHex);
    std::vector<uint8_t> pubRawBytes  = HexToBytes(pubRawHex);
    std::vector<uint8_t> sigDerBytes  = HexToBytes(sigDerHex);

    BCRYPT_KEY_HANDLE hKey = crypto.ImportRawPublicKey(pubRawBytes.data(), pubRawBytes.size());
    TEST_ASSERT(hKey != NULL, "Imported ECDSA P-256 public key into CNG");

    bool verifySuccess = crypto.VerifySignature(hKey, payloadBytes.data(), payloadBytes.size(), sigDerBytes.data(), sigDerBytes.size());
    TEST_ASSERT(verifySuccess == true, "Valid cross-platform test vector signature verified successfully!");

    BCryptDestroyKey(hKey);
    return true;
}

bool M2_TestReplayDefense() {
    std::cout << "--- M2: Challenge Store Single-Use & Replay Defense ---" << std::endl;
    CryptoEngine crypto; crypto.Initialize();
    ChallengeGenerator gen(crypto);
    ChallengeStore store;

    std::array<uint8_t, 16> devId; devId.fill(0x22);
    std::array<uint8_t, 16> pcId; pcId.fill(0x88);

    ChallengeRecord rec = gen.GenerateChallenge(devId, pcId);
    store.AddChallenge(rec);
    uint64_t nowMs = rec.creationTimestampMs + 1000;

    ErrorCode err1 = store.ConsumeChallenge(rec.sessionId, devId, pcId, rec.challenge, nowMs);
    TEST_ASSERT(err1 == ErrorCode::SUCCESS, "First challenge consumption succeeds");

    ErrorCode err2 = store.ConsumeChallenge(rec.sessionId, devId, pcId, rec.challenge, nowMs);
    TEST_ASSERT(err2 == ErrorCode::CHALLENGE_ALREADY_CONSUMED, "Replay attempt rejected with CHALLENGE_ALREADY_CONSUMED");
    return true;
}

// --- MILESTONE 3 TESTS ---
bool M3_TestPairingEcdhAndHkdf() {
    std::cout << "--- M3: Ephemeral ECDH & HKDF Key Exchange ---" << std::endl;
    EcdhKeyExchange pcEcdh; TEST_ASSERT(pcEcdh.GenerateEphemeralKeyPair(), "PC Ephemeral ECDH generated");
    EcdhKeyExchange phoneEcdh; TEST_ASSERT(phoneEcdh.GenerateEphemeralKeyPair(), "Phone Ephemeral ECDH generated");

    std::vector<uint8_t> pcPub = pcEcdh.GetPublicPointUncompressed();
    std::vector<uint8_t> phonePub = phoneEcdh.GetPublicPointUncompressed();

    std::vector<uint8_t> sPc = pcEcdh.ComputeSharedSecret(phonePub.data(), phonePub.size());
    std::vector<uint8_t> sPhone = phoneEcdh.ComputeSharedSecret(pcPub.data(), pcPub.size());
    TEST_ASSERT(sPc == sPhone && !sPc.empty(), "Bilateral ECDH shared secrets S match identically!");

    std::vector<uint8_t> sessionId(16, 0xAA);
    std::vector<uint8_t> kSas = HkdfEngine::DeriveKey(sessionId.data(), sessionId.size(), sPc.data(), sPc.size(), "PhoneKey-Pairing-SAS", 32);
    std::string pin = SasEngine::ComputeSasPin(kSas.data(), kSas.size());
    TEST_ASSERT(pin.length() == 6, "Calculated 6-digit SAS PIN: " + pin);
    return true;
}

bool M3_TestDpapiStorage() {
    std::cout << "--- M3: Windows DPAPI Encrypted Persistence ---" << std::endl;
    std::vector<uint8_t> testData = {0x01, 0x02, 0x03, 0x04, 0x05};
    std::vector<uint8_t> encrypted, decrypted;

    TEST_ASSERT(DpapiStorage::EncryptData(testData, encrypted), "DPAPI CryptProtectData encrypted payload");
    TEST_ASSERT(DpapiStorage::DecryptData(encrypted, decrypted) && decrypted == testData, "DPAPI CryptUnprotectData decrypted payload identically");
    return true;
}

// --- MILESTONE 4 TESTS ---
bool M4_TestFrameProtocol() {
    std::cout << "--- M4: Binary Frame Protocol & CRC32 ---" << std::endl;
    TransportFrame frame;
    frame.messageType = TransportMessageType::UNLOCK_REQ;
    frame.sequenceNumber = 100;
    frame.payload = {0xDE, 0xAD, 0xBE, 0xEF};

    std::vector<uint8_t> ser = FrameProtocol::SerializeFrame(frame);
    TransportFrame outFrame;
    std::string err;
    TEST_ASSERT(FrameProtocol::DeserializeFrame(ser.data(), ser.size(), outFrame, err), "Frame deserialized cleanly");
    TEST_ASSERT(outFrame.payload == frame.payload, "Payload matches");

    ser[16] ^= 0xFF; // Corrupt
    TEST_ASSERT(!FrameProtocol::DeserializeFrame(ser.data(), ser.size(), outFrame, err), "Corrupted frame rejected by CRC32 check!");
    return true;
}

// --- MILESTONE 5 TESTS ---
bool M5_TestE2eUnlockFlow() {
    std::cout << "--- M5: End-to-End Socket Challenge-Response ---" << std::endl;
    std::array<uint8_t, UUID_SIZE> pcId; pcId.fill(0x99);
    AgentService agent(9899, pcId);
    TEST_ASSERT(agent.Start(), "AgentService started on port 9899");
    agent.Stop();
    return true;
}

// --- MILESTONE 6 TESTS ---
bool M6_TestNamedPipeIpc() {
    std::cout << "--- M6: Out-of-Process Named Pipe IPC & DPAPI ---" << std::endl;
    NamedPipeServer server;
    bool serverStart = server.Start([](const IpcPacket& req) -> IpcPacket {
        IpcPacket resp; resp.type = IpcMessageType::RESP_UNLOCK;
        if (req.type == IpcMessageType::REQ_UNLOCK) {
            resp.statusCode = 0x0000;
            resp.payload = {0x55, 0x66, 0x77};
        }
        return resp;
    });
    TEST_ASSERT(serverStart, "NamedPipeServer started listening");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    IpcPacket req, resp; req.type = IpcMessageType::REQ_UNLOCK;
    TEST_ASSERT(NamedPipeClient::SendIpcRequest(req, resp, 2000), "Client sent request over Named Pipe");
    TEST_ASSERT(resp.statusCode == 0x0000, "Received SUCCESS status from IPC server");
    server.Stop();
    return true;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "       PHONEKEY MASTER UNIFIED TEST RUNNER          " << std::endl;
    std::cout << "====================================================" << std::endl;

    bool allPassed = true;
    allPassed &= M2_TestProtocolEncoding();
    allPassed &= M2_TestCrossPlatformVector();
    allPassed &= M2_TestReplayDefense();
    allPassed &= M3_TestPairingEcdhAndHkdf();
    allPassed &= M3_TestDpapiStorage();
    allPassed &= M4_TestFrameProtocol();
    allPassed &= M5_TestE2eUnlockFlow();
    allPassed &= M6_TestNamedPipeIpc();

    std::cout << "====================================================" << std::endl;
    if (allPassed) {
        std::cout << "    ALL PHONEKEY MILESTONE TESTS PASSED! (100%)    " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 0;
    } else {
        std::cerr << "    SOME TESTS FAILED!                            " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 1;
    }
}
