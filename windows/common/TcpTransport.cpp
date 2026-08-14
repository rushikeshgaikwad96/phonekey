#include "TcpTransport.h"
#include "FrameProtocol.h"
#include <iostream>

namespace PhoneKey {

TcpTransport::TcpTransport()
    : m_listenSocket(INVALID_SOCKET), m_clientSocket(INVALID_SOCKET),
      m_listener(nullptr), m_isConnected(false), m_isRunning(false),
      m_sequenceCounter(1) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
}

TcpTransport::~TcpTransport() {
    Close();
    WSACleanup();
}

void TcpTransport::SetListener(ITransportListener* listener) {
    m_listener = listener;
}

bool TcpTransport::IsConnected() const {
    return m_isConnected.load();
}

bool TcpTransport::StartListener(uint16_t port) {
    Close();

    m_listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET) {
        if (m_listener) m_listener->OnError("Failed to create listen socket");
        return false;
    }

    int reuse = 1;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<const char*>(&reuse), sizeof(reuse));

    sockaddr_in service;
    service.sin_family = AF_INET;
    service.sin_addr.s_addr = INADDR_ANY; // Binds to 0.0.0.0 (all network interfaces)
    service.sin_port = htons(port);

    if (bind(m_listenSocket, reinterpret_cast<SOCKADDR*>(&service), sizeof(service)) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        if (m_listener) m_listener->OnError("Failed to bind listen socket");
        return false;
    }

    if (listen(m_listenSocket, SOMAXCONN) == SOCKET_ERROR) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
        if (m_listener) m_listener->OnError("Failed to listen on socket");
        return false;
    }

    m_isRunning = true;
    m_workerThread = std::thread(&TcpTransport::ListenerWorker, this);
    return true;
}

void TcpTransport::ListenerWorker() {
    sockaddr_in clientAddr;
    int addrLen = sizeof(clientAddr);

    SOCKET acceptedSocket = accept(m_listenSocket, reinterpret_cast<SOCKADDR*>(&clientAddr), &addrLen);
    if (acceptedSocket == INVALID_SOCKET || !m_isRunning) {
        return;
    }

    m_clientSocket = acceptedSocket;
    m_isConnected = true;

    char clientIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddr.sin_addr), clientIp, INET_ADDRSTRLEN);
    std::string peerAddr = std::string(clientIp) + ":" + std::to_string(ntohs(clientAddr.sin_port));

    if (m_listener) {
        m_listener->OnConnectionStateChanged(true, peerAddr);
    }

    ReceiverWorker();
}

bool TcpTransport::Connect(const std::string& address, uint16_t port) {
    Close();

    m_clientSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_clientSocket == INVALID_SOCKET) {
        if (m_listener) m_listener->OnError("Failed to create client socket");
        return false;
    }

    sockaddr_in clientService;
    clientService.sin_family = AF_INET;
    inet_pton(AF_INET, address.c_str(), &clientService.sin_addr);
    clientService.sin_port = htons(port);

    if (connect(m_clientSocket, reinterpret_cast<SOCKADDR*>(&clientService), sizeof(clientService)) == SOCKET_ERROR) {
        closesocket(m_clientSocket);
        m_clientSocket = INVALID_SOCKET;
        if (m_listener) m_listener->OnError("Failed to connect to target host");
        return false;
    }

    m_isConnected = true;
    m_isRunning = true;

    if (m_listener) {
        m_listener->OnConnectionStateChanged(true, address + ":" + std::to_string(port));
    }

    m_workerThread = std::thread(&TcpTransport::ReceiverWorker, this);
    return true;
}

void TcpTransport::ReceiverWorker() {
    std::vector<uint8_t> rxBuffer;
    char tempBuf[4096];

    while (m_isRunning && m_isConnected) {
        int bytesRead = recv(m_clientSocket, tempBuf, sizeof(tempBuf), 0);
        if (bytesRead <= 0) {
            m_isConnected = false;
            if (m_listener) {
                m_listener->OnConnectionStateChanged(false, "Disconnected");
            }
            break;
        }

        rxBuffer.insert(rxBuffer.end(), tempBuf, tempBuf + bytesRead);

        // Process frames in rxBuffer safely with payload cap & discard on corruption
        while (rxBuffer.size() >= 18) {
            // Check magic bytes before attempting payload parse
            uint32_t magic = (static_cast<uint32_t>(rxBuffer[0]) << 24) |
                             (static_cast<uint32_t>(rxBuffer[1]) << 16) |
                             (static_cast<uint32_t>(rxBuffer[2]) << 8)  |
                              static_cast<uint32_t>(rxBuffer[3]);

            if (magic != FRAME_MAGIC) {
                if (m_listener) {
                    m_listener->OnError("Stream corruption: invalid magic bytes. Discarding invalid stream byte.");
                }
                rxBuffer.erase(rxBuffer.begin()); // Drop invalid byte to resynchronize stream
                continue;
            }

            uint32_t payloadLen = (static_cast<uint32_t>(rxBuffer[4]) << 24) |
                                  (static_cast<uint32_t>(rxBuffer[5]) << 16) |
                                  (static_cast<uint32_t>(rxBuffer[6]) << 8)  |
                                   static_cast<uint32_t>(rxBuffer[7]);

            if (payloadLen > MAX_PAYLOAD_SIZE) {
                if (m_listener) {
                    m_listener->OnError("Stream security alert: frame payload size exceeds 64KB ceiling. Dropping connection.");
                }
                m_isConnected = false;
                break;
            }

            size_t totalFrameLen = 14 + static_cast<size_t>(payloadLen) + 4;
            if (rxBuffer.size() < totalFrameLen) {
                break; // Wait for rest of frame bytes to arrive
            }

            TransportFrame frame;
            std::string err;
            if (FrameProtocol::DeserializeFrame(rxBuffer.data(), totalFrameLen, frame, err)) {
                if (m_listener) {
                    m_listener->OnFrameReceived(frame);
                }
            } else {
                if (m_listener) {
                    m_listener->OnError("Frame deserialization error: " + err);
                }
            }

            rxBuffer.erase(rxBuffer.begin(), rxBuffer.begin() + totalFrameLen);
        }
    }
}

bool TcpTransport::SendFrame(TransportMessageType messageType, const std::vector<uint8_t>& payload) {
    if (!m_isConnected || m_clientSocket == INVALID_SOCKET) return false;

    std::lock_guard<std::mutex> lock(m_sendMutex);

    TransportFrame frame;
    frame.messageType = messageType;
    frame.sequenceNumber = m_sequenceCounter++;
    frame.payload = payload;

    std::vector<uint8_t> serialized = FrameProtocol::SerializeFrame(frame);
    if (serialized.empty()) return false;

    int totalSent = 0;
    int toSend = static_cast<int>(serialized.size());

    while (totalSent < toSend) {
        int sent = send(m_clientSocket, reinterpret_cast<const char*>(serialized.data() + totalSent), toSend - totalSent, 0);
        if (sent <= 0) {
            m_isConnected = false;
            return false;
        }
        totalSent += sent;
    }

    return true;
}

void TcpTransport::Close() {
    m_isRunning = false;
    m_isConnected = false;

    if (m_listenSocket != INVALID_SOCKET) {
        closesocket(m_listenSocket);
        m_listenSocket = INVALID_SOCKET;
    }

    if (m_clientSocket != INVALID_SOCKET) {
        closesocket(m_clientSocket);
        m_clientSocket = INVALID_SOCKET;
    }

    if (m_workerThread.joinable()) {
        m_workerThread.join();
    }
}

} // namespace PhoneKey
