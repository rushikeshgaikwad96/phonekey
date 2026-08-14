#ifndef PHONEKEY_TCP_TRANSPORT_H
#define PHONEKEY_TCP_TRANSPORT_H

#include "TransportInterface.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <thread>
#include <atomic>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

namespace PhoneKey {

class TcpTransport : public ITransport {
public:
    TcpTransport();
    ~TcpTransport() override;

    bool StartListener(uint16_t port) override;
    bool Connect(const std::string& address, uint16_t port) override;
    bool SendFrame(TransportMessageType messageType, const std::vector<uint8_t>& payload) override;
    void SetListener(ITransportListener* listener) override;
    bool IsConnected() const override;
    void Close() override;

private:
    SOCKET m_listenSocket;
    SOCKET m_clientSocket;
    ITransportListener* m_listener;
    std::atomic<bool> m_isConnected;
    std::atomic<bool> m_isRunning;
    std::atomic<uint32_t> m_sequenceCounter;
    std::thread m_workerThread;
    std::mutex m_sendMutex;

    void ListenerWorker();
    void ReceiverWorker();
};

} // namespace PhoneKey

#endif // PHONEKEY_TCP_TRANSPORT_H
