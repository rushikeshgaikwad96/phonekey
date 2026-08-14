#ifndef PHONEKEY_BLUETOOTH_TRANSPORT_H
#define PHONEKEY_BLUETOOTH_TRANSPORT_H

#include "TransportInterface.h"
#include <thread>
#include <atomic>
#include <mutex>

namespace PhoneKey {

class BluetoothTransport : public ITransport {
public:
    BluetoothTransport();
    ~BluetoothTransport() override;

    bool StartListener(uint16_t portOrServiceChannel) override;
    bool Connect(const std::string& addressOrUuid, uint16_t portOrChannel) override;
    bool SendFrame(TransportMessageType messageType, const std::vector<uint8_t>& payload) override;
    void SetListener(ITransportListener* listener) override;
    bool IsConnected() const override;
    void Close() override;

private:
    ITransportListener* m_listener;
    std::atomic<bool> m_isConnected;
    std::atomic<bool> m_isRunning;
    std::atomic<uint32_t> m_sequenceCounter;
    std::mutex m_sendMutex;
};

} // namespace PhoneKey

#endif // PHONEKEY_BLUETOOTH_TRANSPORT_H
