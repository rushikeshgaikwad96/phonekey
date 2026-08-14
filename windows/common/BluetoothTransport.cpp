#include "BluetoothTransport.h"
#include "FrameProtocol.h"

namespace PhoneKey {

BluetoothTransport::BluetoothTransport()
    : m_listener(nullptr), m_isConnected(false), m_isRunning(false), m_sequenceCounter(1) {}

BluetoothTransport::~BluetoothTransport() {
    Close();
}

void BluetoothTransport::SetListener(ITransportListener* listener) {
    m_listener = listener;
}

bool BluetoothTransport::IsConnected() const {
    return m_isConnected.load();
}

bool BluetoothTransport::StartListener(uint16_t portOrServiceChannel) {
    (void)portOrServiceChannel;
    m_isRunning = true;
    m_isConnected = true;
    if (m_listener) {
        m_listener->OnConnectionStateChanged(true, "BLE:Listening");
    }
    return true;
}

bool BluetoothTransport::Connect(const std::string& addressOrUuid, uint16_t portOrChannel) {
    (void)addressOrUuid;
    (void)portOrChannel;
    m_isRunning = true;
    m_isConnected = true;
    if (m_listener) {
        m_listener->OnConnectionStateChanged(true, addressOrUuid);
    }
    return true;
}

bool BluetoothTransport::SendFrame(TransportMessageType messageType, const std::vector<uint8_t>& payload) {
    if (!m_isConnected) return false;

    std::lock_guard<std::mutex> lock(m_sendMutex);

    TransportFrame frame;
    frame.messageType = messageType;
    frame.sequenceNumber = m_sequenceCounter++;
    frame.payload = payload;

    std::vector<uint8_t> serialized = FrameProtocol::SerializeFrame(frame);
    (void)serialized;

    return true;
}

void BluetoothTransport::Close() {
    m_isRunning = false;
    m_isConnected = false;
    if (m_listener) {
        m_listener->OnConnectionStateChanged(false, "BLE:Disconnected");
    }
}

} // namespace PhoneKey
