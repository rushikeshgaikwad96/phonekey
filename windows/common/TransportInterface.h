#ifndef PHONEKEY_TRANSPORT_INTERFACE_H
#define PHONEKEY_TRANSPORT_INTERFACE_H

#include <vector>
#include <cstdint>
#include <string>
#include <functional>
#include <memory>

namespace PhoneKey {

constexpr uint32_t FRAME_MAGIC = 0x504B4652; // "PKFR"
constexpr size_t MAX_PAYLOAD_SIZE = 65536;    // 64 KB limit

enum class TransportMessageType : uint8_t {
    PAIR_REQ     = 0x01,
    PAIR_RESP    = 0x02,
    UNLOCK_REQ   = 0x10,
    UNLOCK_RESP  = 0x11,
    ERROR_MSG    = 0xFF
};

struct TransportFrame {
    uint32_t magic;
    uint32_t payloadLength;
    TransportMessageType messageType;
    uint8_t flags;
    uint32_t sequenceNumber;
    std::vector<uint8_t> payload;
    uint32_t checksum;

    TransportFrame()
        : magic(FRAME_MAGIC), payloadLength(0), messageType(TransportMessageType::UNLOCK_REQ),
          flags(0), sequenceNumber(0), checksum(0) {}
};

class ITransportListener {
public:
    virtual ~ITransportListener() = default;
    virtual void OnFrameReceived(const TransportFrame& frame) = 0;
    virtual void OnConnectionStateChanged(bool isConnected, const std::string& peerAddress) = 0;
    virtual void OnError(const std::string& errorMessage) = 0;
};

class ITransport {
public:
    virtual ~ITransport() = default;
    virtual bool StartListener(uint16_t port) = 0;
    virtual bool Connect(const std::string& address, uint16_t port) = 0;
    virtual bool SendFrame(TransportMessageType messageType, const std::vector<uint8_t>& payload) = 0;
    virtual void SetListener(ITransportListener* listener) = 0;
    virtual bool IsConnected() const = 0;
    virtual void Close() = 0;
};

} // namespace PhoneKey

#endif // PHONEKEY_TRANSPORT_INTERFACE_H
