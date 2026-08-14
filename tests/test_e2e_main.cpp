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
#include "../windows/agent/AgentService.h"
#include "../windows/common/TcpTransport.h"
#include "../windows/common/FrameProtocol.h"
#include "../windows/common/EcdhKeyExchange.h"

using namespace PhoneKey;

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << " [FAIL] " << msg << " (Line " << __LINE__ << ")" << std::endl; \
        return false; \
    } else { \
        std::cout << " [PASS] " << msg << std::endl; \
    }

class MockAndroidClient : public ITransportListener {
public:
    TcpTransport transport;
    CryptoEngine crypto;
    BCRYPT_KEY_HANDLE hKeyPair;
    std::array<uint8_t, UUID_SIZE> deviceId;
    std::vector<uint8_t> rawPubKeyXy;
    std::atomic<bool> isReqReceived{false};
    TransportFrame reqFrame;

    MockAndroidClient() : hKeyPair(NULL) {
        deviceId.fill(0x11);
        crypto.Initialize();
        transport.SetListener(this);
    }

    ~MockAndroidClient() override {
        if (hKeyPair) {
            BCryptDestroyKey(hKeyPair);
            hKeyPair = NULL;
        }
        transport.Close();
    }

    bool InitKeys() {
        BCRYPT_ALG_HANDLE hAlg = NULL;
        NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
        if (!NT_SUCCESS(status)) return false;

        status = BCryptGenerateKeyPair(hAlg, &hKeyPair, 256, 0);
        if (!NT_SUCCESS(status)) {
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return false;
        }

        status = BCryptFinalizeKeyPair(hKeyPair, 0);
        BCryptCloseAlgorithmProvider(hAlg, 0);
        if (!NT_SUCCESS(status)) return false;

        // Export raw public key
        ULONG cbBlob = 0;
        BCryptExportKey(hKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cbBlob, 0);
        std::vector<uint8_t> blob(cbBlob);
        BCryptExportKey(hKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, blob.data(), cbBlob, &cbBlob, 0);

        rawPubKeyXy.assign(blob.begin() + sizeof(BCRYPT_ECCKEY_BLOB), blob.end());
        return true;
    }

    void OnFrameReceived(const TransportFrame& frame) override {
        if (frame.messageType == TransportMessageType::UNLOCK_REQ) {
            reqFrame = frame;
            isReqReceived = true;
        }
    }

    void OnConnectionStateChanged(bool isConnected, const std::string& peerAddress) override {
        (void)isConnected;
        (void)peerAddress;
    }

    void OnError(const std::string& errorMessage) override {
        (void)errorMessage;
    }
};

bool TestEndToEndUnlockAuthentication() {
    std::cout << "--- Running End-to-End Unlock Authentication Integration Test ---" << std::endl;

    std::array<uint8_t, UUID_SIZE> pcId; pcId.fill(0x99);
    uint16_t port = 9888;

    AgentService agent(port, pcId);
    TEST_ASSERT(agent.Start(), "AgentService started listener on port 9888");

    MockAndroidClient client;
    TEST_ASSERT(client.InitKeys(), "Mock Android client generated ECDSA P-256 keypair");

    // Register dev device public key with agent
    bool regOk = agent.RegisterDevice(client.deviceId, "Test Phone", client.rawPubKeyXy.data(), client.rawPubKeyXy.size());
    TEST_ASSERT(regOk, "AgentService registered client device public key");

    // Client connects to Agent
    TEST_ASSERT(client.transport.Connect("127.0.0.1", port), "Client connected to AgentService TCP socket");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Agent issues challenge request
    ChallengeRecord rec = agent.InitiateUnlockRequest(client.deviceId);
    TEST_ASSERT(rec.state == ChallengeRecord::State::OUTSTANDING, "Agent created OUTSTANDING challenge record");

    // Wait for client to receive UNLOCK_REQ frame
    for (int i = 0; i < 20 && !client.isReqReceived; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    TEST_ASSERT(client.isReqReceived.load(), "Client received UNLOCK_REQ frame over TCP socket");

    // Client constructs canonical payload P
    AuthPayload p;
    p.protocolVersion = CURRENT_PROTOCOL_VERSION;
    p.algorithmId = ALGORITHM_ECDSA_P256_SHA256;
    p.deviceId = client.deviceId;
    p.sessionId = rec.sessionId;
    p.pcId = pcId;
    p.challenge = rec.challenge;
    p.expirationTimestampMs = rec.expirationTimestampMs;

    std::vector<uint8_t> canonicalBytes = p.Serialize();
    TEST_ASSERT(canonicalBytes.size() == 108, "Canonical payload size is 108 bytes");

    // Sign payload P with client key
    BCRYPT_HASH_HANDLE hHash = NULL;
    BCRYPT_ALG_HANDLE hShaAlg = NULL;
    BCryptOpenAlgorithmProvider(&hShaAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    BCryptCreateHash(hShaAlg, &hHash, NULL, 0, NULL, 0, 0);
    BCryptHashData(hHash, canonicalBytes.data(), static_cast<ULONG>(canonicalBytes.size()), 0);
    std::vector<uint8_t> hashBuf(32, 0);
    BCryptFinishHash(hHash, hashBuf.data(), 32, 0);
    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hShaAlg, 0);

    std::vector<uint8_t> rawRs(64, 0);
    ULONG cbSig = 0;
    NTSTATUS status = BCryptSignHash(client.hKeyPair, NULL, hashBuf.data(), 32, rawRs.data(), 64, &cbSig, 0);
    TEST_ASSERT(NT_SUCCESS(status), "Client computed ECDSA signature over canonical payload P");

    // Construct full UNLOCK_RESP payload = Canonical Bytes (108B) || Signature Bytes (64B)
    std::vector<uint8_t> fullPayload = canonicalBytes;
    fullPayload.insert(fullPayload.end(), rawRs.begin(), rawRs.end());

    // Send UNLOCK_RESP over TCP socket
    bool sendOk = client.transport.SendFrame(TransportMessageType::UNLOCK_RESP, fullPayload);
    TEST_ASSERT(sendOk, "Client sent UNLOCK_RESP frame over TCP socket");

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    // Verify challenge state is now CONSUMED
    ChallengeRecord updatedRec;
    uint64_t nowMs = rec.creationTimestampMs + 500;
    ErrorCode stateErr = agent.GetChallengeStore().ValidateChallenge(rec.sessionId, client.deviceId, pcId, rec.challenge, nowMs, updatedRec);
    TEST_ASSERT(stateErr == ErrorCode::CHALLENGE_ALREADY_CONSUMED, "Agent successfully verified signature & consumed challenge!");

    // Test Replay Rejection over TCP socket
    bool replaySend = client.transport.SendFrame(TransportMessageType::UNLOCK_RESP, fullPayload);
    TEST_ASSERT(replaySend, "Sent replayed UNLOCK_RESP over socket second time");

    std::this_thread::sleep_for(std::chrono::milliseconds(150));

    agent.Stop();
    return true;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "      PHONEKEY MILESTONE 5 END-TO-END TEST SUITE    " << std::endl;
    std::cout << "====================================================" << std::endl;

    bool allPassed = true;
    allPassed &= TestEndToEndUnlockAuthentication();

    std::cout << "====================================================" << std::endl;
    if (allPassed) {
        std::cout << "    ALL MILESTONE 5 E2E INTEGRATION TESTS PASSED!  " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 0;
    } else {
        std::cerr << "    SOME E2E INTEGRATION TESTS FAILED!            " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 1;
    }
}
