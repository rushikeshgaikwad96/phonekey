#include "../windows/common/FrameProtocol.h"
#include <iostream>
#include <vector>
#include <random>
#include <cassert>

using namespace PhoneKey;

void RunFuzzParserTest() {
    std::cout << "--- Running Frame Protocol Parser Fuzz & Bounds Test ---" << std::endl;

    // 1. Test null pointer check
    TransportFrame frame;
    std::string err;
    assert(!FrameProtocol::DeserializeFrame(nullptr, 100, frame, err));
    std::cout << " [PASS] Null pointer input safely rejected: " << err << std::endl;

    // 2. Test under-length buffers (0 to 17 bytes)
    std::vector<uint8_t> shortBuf(17, 0x50);
    assert(!FrameProtocol::DeserializeFrame(shortBuf.data(), shortBuf.size(), frame, err));
    std::cout << " [PASS] Under-length header (<18B) safely rejected: " << err << std::endl;

    // 3. Test invalid magic bytes
    std::vector<uint8_t> badMagic = { 0x00, 0x11, 0x22, 0x33, 0,0,0,0, 0x10, 0, 0,0,0,1, 0,0,0,0 };
    assert(!FrameProtocol::DeserializeFrame(badMagic.data(), badMagic.size(), frame, err));
    std::cout << " [PASS] Invalid magic bytes safely rejected: " << err << std::endl;

    // 4. Test oversized payload ceiling (>64KB limit)
    std::vector<uint8_t> oversized = {
        0x50, 0x4B, 0x46, 0x52, // PKFR
        0x00, 0x02, 0x00, 0x00, // 131,072 bytes (> 65,536 limit)
        0x10, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0,0,0,0
    };
    assert(!FrameProtocol::DeserializeFrame(oversized.data(), oversized.size(), frame, err));
    std::cout << " [PASS] Oversized payload (>64KB) safely rejected: " << err << std::endl;

    // 5. Test invalid message type enum
    std::vector<uint8_t> invalidMsgType = {
        0x50, 0x4B, 0x46, 0x52, // PKFR
        0x00, 0x00, 0x00, 0x00, // 0 payload
        0x7E,                   // Invalid message type 0x7E
        0x00,
        0x00, 0x00, 0x00, 0x01
    };
    // Append CRC32 for 14B header
    uint32_t crc = FrameProtocol::CalculateCrc32(invalidMsgType.data(), 14);
    invalidMsgType.push_back((crc >> 24) & 0xFF);
    invalidMsgType.push_back((crc >> 16) & 0xFF);
    invalidMsgType.push_back((crc >> 8) & 0xFF);
    invalidMsgType.push_back(crc & 0xFF);

    assert(!FrameProtocol::DeserializeFrame(invalidMsgType.data(), invalidMsgType.size(), frame, err));
    std::cout << " [PASS] Invalid message type enum safely rejected: " << err << std::endl;

    // 6. Fuzzing Loop: Generate 5,000 mutated/random byte streams
    std::mt19937 rng(1337);
    std::uniform_int_distribution<int> distByte(0, 255);
    std::uniform_int_distribution<int> distLen(0, 500);

    size_t rejectedCount = 0;
    for (int i = 0; i < 5000; ++i) {
        size_t len = distLen(rng);
        std::vector<uint8_t> randomBuf(len);
        for (size_t j = 0; j < len; ++j) {
            randomBuf[j] = static_cast<uint8_t>(distByte(rng));
        }

        TransportFrame dummyFrame;
        std::string dummyErr;
        bool ok = FrameProtocol::DeserializeFrame(randomBuf.data(), randomBuf.size(), dummyFrame, dummyErr);
        if (!ok) {
            rejectedCount++;
        }
    }

    std::cout << " [PASS] 5,000 random fuzzed byte buffers processed without crash (" << rejectedCount << " rejected safely)" << std::endl;
    std::cout << "====================================================" << std::endl;
    std::cout << "    FRAME PARSER FUZZING TEST COMPLETED (100%)      " << std::endl;
    std::cout << "====================================================" << std::endl;
}

int main() {
    RunFuzzParserTest();
    return 0;
}
