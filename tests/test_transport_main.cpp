#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <cassert>
#include "../windows/common/TransportInterface.h"
#include "../windows/common/FrameProtocol.h"
#include "../windows/common/TcpTransport.h"
#include "../windows/common/BluetoothTransport.h"

using namespace PhoneKey;

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << " [FAIL] " << msg << " (Line " << __LINE__ << ")" << std::endl; \
        return false; \
    } else { \
        std::cout << " [PASS] " << msg << std::endl; \
    }

bool TestFrameProtocolSerialization() {
    std::cout << "--- Running Frame Protocol Serialization & CRC32 Tests ---" << std::endl;

    TransportFrame frame;
    frame.messageType = TransportMessageType::UNLOCK_REQ;
    frame.flags = 0;
    frame.sequenceNumber = 42;
    frame.payload = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};

    std::vector<uint8_t> serialized = FrameProtocol::SerializeFrame(frame);
    TEST_ASSERT(serialized.size() == 14 + 8 + 4, "Serialized frame total length is 26 bytes");

    TransportFrame outFrame;
    std::string err;
    bool desRes = FrameProtocol::DeserializeFrame(serialized.data(), serialized.size(), outFrame, err);
    TEST_ASSERT(desRes && err.empty(), "Frame deserialization succeeded");
    TEST_ASSERT(outFrame.magic == FRAME_MAGIC, "Magic PKFR matches");
    TEST_ASSERT(outFrame.messageType == TransportMessageType::UNLOCK_REQ, "Message type matches");
    TEST_ASSERT(outFrame.sequenceNumber == 42, "Sequence number matches");
    TEST_ASSERT(outFrame.payload == frame.payload, "Payload matches");

    // Test corrupted CRC32 (Bit-flip in payload)
    serialized[16] ^= 0xFF;
    bool corruptRes = FrameProtocol::DeserializeFrame(serialized.data(), serialized.size(), outFrame, err);
    TEST_ASSERT(!corruptRes && err.find("CRC32 checksum mismatch") != std::string::npos, "Corrupted frame rejected by CRC32 check!");

    return true;
}

class TestServerListener : public ITransportListener {
public:
    std::atomic<bool> frameReceived{false};
    TransportFrame lastFrame;
    std::string peer;

    void OnFrameReceived(const TransportFrame& frame) override {
        lastFrame = frame;
        frameReceived = true;
    }

    void OnConnectionStateChanged(bool isConnected, const std::string& peerAddress) override {
        (void)isConnected;
        peer = peerAddress;
    }

    void OnError(const std::string& errorMessage) override {
        (void)errorMessage;
    }
};

class TestClientListener : public ITransportListener {
public:
    std::atomic<bool> frameReceived{false};
    TransportFrame lastFrame;

    void OnFrameReceived(const TransportFrame& frame) override {
        lastFrame = frame;
        frameReceived = true;
    }

    void OnConnectionStateChanged(bool isConnected, const std::string& peerAddress) override {
        (void)isConnected;
        (void)peerAddress;
    }

    void OnError(const std::string& errorMessage) override {
        (void)errorMessage;
    }
};

bool TestTcpLoopbackTransport() {
    std::cout << "--- Running WinSock2 TCP Socket Loopback Transport Test ---" << std::endl;

    TcpTransport server;
    TestServerListener serverListener;
    server.SetListener(&serverListener);

    uint16_t testPort = 9876;
    TEST_ASSERT(server.StartListener(testPort), "TCP Server started listener on port 9876");

    TcpTransport client;
    TestClientListener clientListener;
    client.SetListener(&clientListener);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    TEST_ASSERT(client.Connect("127.0.0.1", testPort), "TCP Client connected to 127.0.0.1:9876");

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    std::vector<uint8_t> payload = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    bool sendRes = client.SendFrame(TransportMessageType::UNLOCK_REQ, payload);
    TEST_ASSERT(sendRes, "Client sent framed UNLOCK_REQ payload over socket");

    // Wait for server reception
    for (int i = 0; i < 20 && !serverListener.frameReceived; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    TEST_ASSERT(serverListener.frameReceived.load(), "Server received framed payload over TCP socket");
    TEST_ASSERT(serverListener.lastFrame.messageType == TransportMessageType::UNLOCK_REQ, "Server received UNLOCK_REQ type");
    TEST_ASSERT(serverListener.lastFrame.payload == payload, "Server received exact payload bytes");

    // Server sends response
    std::vector<uint8_t> respPayload = {0x00, 0x01, 0x02, 0x03};
    bool serverSendRes = server.SendFrame(TransportMessageType::UNLOCK_RESP, respPayload);
    TEST_ASSERT(serverSendRes, "Server sent framed UNLOCK_RESP payload to client");

    for (int i = 0; i < 20 && !clientListener.frameReceived; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    TEST_ASSERT(clientListener.frameReceived.load(), "Client received framed response payload");
    TEST_ASSERT(clientListener.lastFrame.messageType == TransportMessageType::UNLOCK_RESP, "Client received UNLOCK_RESP type");

    client.Close();
    server.Close();

    return true;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "     PHONEKEY MILESTONE 4 TRANSPORT TEST SUITE      " << std::endl;
    std::cout << "====================================================" << std::endl;

    bool allPassed = true;
    allPassed &= TestFrameProtocolSerialization();
    allPassed &= TestTcpLoopbackTransport();

    std::cout << "====================================================" << std::endl;
    if (allPassed) {
        std::cout << "    ALL MILESTONE 4 TRANSPORT TESTS PASSED!       " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 0;
    } else {
        std::cerr << "    SOME TRANSPORT TESTS FAILED!                  " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 1;
    }
}
