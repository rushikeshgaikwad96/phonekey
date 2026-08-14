#include "AgentService.h"
#include "../common/TcpTransport.h"
#include <iostream>
#include <chrono>

namespace PhoneKey {

AgentService::AgentService(uint16_t listenPort, const std::array<uint8_t, UUID_SIZE>& pcId)
    : m_port(listenPort), m_pcId(pcId),
      m_cryptoEngine(), m_challengeGen(m_cryptoEngine),
      m_challengeStore(), m_deviceRegistry(m_cryptoEngine) {
    m_transport = std::make_unique<TcpTransport>();
    m_transport->SetListener(this);
}

AgentService::~AgentService() {
    Stop();
}

bool AgentService::Start() {
    if (!m_cryptoEngine.Initialize()) {
        std::cerr << "[AgentService] CryptoEngine failed to initialize." << std::endl;
        return false;
    }
    return m_transport->StartListener(m_port);
}

void AgentService::Stop() {
    if (m_transport) {
        m_transport->Close();
    }
}

bool AgentService::RegisterDevice(const std::array<uint8_t, UUID_SIZE>& deviceId, const std::string& name, const uint8_t* rawPublicKeyXy, size_t keyLen) {
    return m_deviceRegistry.RegisterDevice(deviceId, name, rawPublicKeyXy, keyLen);
}

ChallengeRecord AgentService::InitiateUnlockRequest(const std::array<uint8_t, UUID_SIZE>& deviceId) {
    ChallengeRecord record = m_challengeGen.GenerateChallenge(deviceId, m_pcId);
    m_challengeStore.AddChallenge(record);

    // Build UNLOCK_REQ binary payload (80 Bytes: SessionID (16B) || PCID (16B) || Challenge (32B) || CreatedTime (8B) || ExpireTime (8B))
    std::vector<uint8_t> payload(80, 0);
    std::memcpy(&payload[0], record.sessionId.data(), UUID_SIZE);
    std::memcpy(&payload[16], record.pcId.data(), UUID_SIZE);
    std::memcpy(&payload[32], record.challenge.data(), CHALLENGE_SIZE);

    for (int i = 7; i >= 0; --i) {
        payload[64 + (7 - i)] = static_cast<uint8_t>((record.creationTimestampMs >> (i * 8)) & 0xFF);
        payload[72 + (7 - i)] = static_cast<uint8_t>((record.expirationTimestampMs >> (i * 8)) & 0xFF);
    }

    if (m_transport->IsConnected()) {
        m_transport->SendFrame(TransportMessageType::UNLOCK_REQ, payload);
    }

    return record;
}

void AgentService::OnFrameReceived(const TransportFrame& frame) {
    if (frame.messageType == TransportMessageType::UNLOCK_RESP) {
        ErrorCode err = ProcessUnlockResponse(frame);
        std::vector<uint8_t> respPayload = {
            static_cast<uint8_t>((static_cast<uint16_t>(err) >> 8) & 0xFF),
            static_cast<uint8_t>(static_cast<uint16_t>(err) & 0xFF)
        };
        m_transport->SendFrame(err == ErrorCode::SUCCESS ? TransportMessageType::UNLOCK_RESP : TransportMessageType::ERROR_MSG, respPayload);
    }
}

ErrorCode AgentService::ProcessUnlockResponse(const TransportFrame& frame) {
    // Expect payload size >= 108 bytes (Canonical payload P) + Signature bytes
    if (frame.payload.size() < 108 + 8) {
        return ErrorCode::INVALID_REQUEST;
    }

    // 1. Deserialize canonical payload P
    AuthPayload payloadP;
    ErrorCode parseErr;
    if (!AuthPayload::Deserialize(frame.payload.data(), 108, payloadP, parseErr)) {
        return parseErr;
    }

    // Extract signature bytes following the 108-byte canonical payload
    const uint8_t* sigBytes = frame.payload.data() + 108;
    size_t sigLen = frame.payload.size() - 108;

    uint64_t nowMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()
    ).count();

    // 2. Validate Challenge Store state & 30s TTL
    ChallengeRecord rec;
    ErrorCode valErr = m_challengeStore.ValidateChallenge(payloadP.sessionId, payloadP.deviceId, m_pcId, payloadP.challenge, nowMs, rec);
    if (valErr != ErrorCode::SUCCESS) {
        return valErr;
    }

    // 3. Lookup device public key in registry
    BCRYPT_KEY_HANDLE hPubKey = m_deviceRegistry.GetDevicePublicKey(payloadP.deviceId);
    if (!hPubKey) {
        return ErrorCode::UNKNOWN_DEVICE;
    }

    // 4. Verify signature via CNG BCryptVerifySignature
    bool sigValid = m_cryptoEngine.VerifySignature(hPubKey, frame.payload.data(), 108, sigBytes, sigLen);
    if (!sigValid) {
        return ErrorCode::INVALID_SIGNATURE;
    }

    // 5. Atomically consume challenge
    ErrorCode consumeErr = m_challengeStore.ConsumeChallenge(payloadP.sessionId, payloadP.deviceId, m_pcId, payloadP.challenge, nowMs);
    return consumeErr;
}

void AgentService::OnConnectionStateChanged(bool isConnected, const std::string& peerAddress) {
    std::cout << "[AgentService] Connection state: " << (isConnected ? "CONNECTED to " : "DISCONNECTED from ") << peerAddress << std::endl;
}

void AgentService::OnError(const std::string& errorMessage) {
    std::cerr << "[AgentService] Error: " << errorMessage << std::endl;
}

} // namespace PhoneKey
