#ifndef PHONEKEY_AGENT_SERVICE_H
#define PHONEKEY_AGENT_SERVICE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "../common/TransportInterface.h"
#include "../common/CryptoEngine.h"
#include "../common/Protocol.h"
#include "ChallengeGenerator.h"
#include "ChallengeStore.h"
#include "DeviceRegistry.h"
#include <memory>
#include <array>
#include <string>

namespace PhoneKey {

class AgentService : public ITransportListener {
public:
    AgentService(uint16_t listenPort, const std::array<uint8_t, UUID_SIZE>& pcId);
    ~AgentService() override;

    // Initializes CryptoEngine, DeviceRegistry, and starts TCP Transport Listener
    bool Start();

    // Stops agent listener and disconnects clients
    void Stop();

    // Registers a development phone device with raw 64-byte EC public key
    bool RegisterDevice(const std::array<uint8_t, UUID_SIZE>& deviceId, const std::string& name, const uint8_t* rawPublicKeyXy, size_t keyLen);

    // Initiates an unlock challenge request to the connected client
    ChallengeRecord InitiateUnlockRequest(const std::array<uint8_t, UUID_SIZE>& deviceId);

    // ITransportListener Callbacks
    void OnFrameReceived(const TransportFrame& frame) override;
    void OnConnectionStateChanged(bool isConnected, const std::string& peerAddress) override;
    void OnError(const std::string& errorMessage) override;

    // Accessors
    CryptoEngine& GetCryptoEngine() { return m_cryptoEngine; }
    ChallengeStore& GetChallengeStore() { return m_challengeStore; }
    DeviceRegistry& GetDeviceRegistry() { return m_deviceRegistry; }

private:
    uint16_t m_port;
    std::array<uint8_t, UUID_SIZE> m_pcId;
    CryptoEngine m_cryptoEngine;
    ChallengeGenerator m_challengeGen;
    ChallengeStore m_challengeStore;
    DeviceRegistry m_deviceRegistry;
    std::unique_ptr<ITransport> m_transport;

    ErrorCode ProcessUnlockResponse(const TransportFrame& frame);
};

} // namespace PhoneKey

#endif // PHONEKEY_AGENT_SERVICE_H
