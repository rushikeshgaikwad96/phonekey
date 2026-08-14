#include "FrameProtocol.h"
#include <cstring>
#include <iostream>

namespace PhoneKey {

// IEEE 802.3 CRC32 Implementation
uint32_t FrameProtocol::CalculateCrc32(const uint8_t* data, size_t length) {
    if (!data || length == 0) return 0;
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

std::vector<uint8_t> FrameProtocol::SerializeFrame(const TransportFrame& frame) {
    uint32_t payloadLen = static_cast<uint32_t>(frame.payload.size());
    size_t totalLen = 14 + payloadLen + 4;
    std::vector<uint8_t> buffer(totalLen, 0);

    size_t offset = 0;

    // 1. Magic (4 Bytes, Big-Endian)
    buffer[0] = static_cast<uint8_t>((FRAME_MAGIC >> 24) & 0xFF);
    buffer[1] = static_cast<uint8_t>((FRAME_MAGIC >> 16) & 0xFF);
    buffer[2] = static_cast<uint8_t>((FRAME_MAGIC >> 8) & 0xFF);
    buffer[3] = static_cast<uint8_t>(FRAME_MAGIC & 0xFF);
    offset += 4;

    // 2. FrameLength (4 Bytes, Big-Endian)
    buffer[4] = static_cast<uint8_t>((payloadLen >> 24) & 0xFF);
    buffer[5] = static_cast<uint8_t>((payloadLen >> 16) & 0xFF);
    buffer[6] = static_cast<uint8_t>((payloadLen >> 8) & 0xFF);
    buffer[7] = static_cast<uint8_t>(payloadLen & 0xFF);
    offset += 4;

    // 3. MessageType (1 Byte)
    buffer[8] = static_cast<uint8_t>(frame.messageType);
    offset += 1;

    // 4. Flags (1 Byte)
    buffer[9] = frame.flags;
    offset += 1;

    // 5. SequenceNumber (4 Bytes, Big-Endian)
    buffer[10] = static_cast<uint8_t>((frame.sequenceNumber >> 24) & 0xFF);
    buffer[11] = static_cast<uint8_t>((frame.sequenceNumber >> 16) & 0xFF);
    buffer[12] = static_cast<uint8_t>((frame.sequenceNumber >> 8) & 0xFF);
    buffer[13] = static_cast<uint8_t>(frame.sequenceNumber & 0xFF);
    offset += 4;

    // 6. PayloadBytes (N Bytes)
    if (payloadLen > 0) {
        std::memcpy(&buffer[offset], frame.payload.data(), payloadLen);
        offset += payloadLen;
    }

    // 7. Calculate CRC32 over Header + PayloadBytes (14 + N bytes)
    uint32_t checksum = CalculateCrc32(buffer.data(), 14 + payloadLen);

    // 8. Checksum (4 Bytes, Big-Endian)
    buffer[offset]     = static_cast<uint8_t>((checksum >> 24) & 0xFF);
    buffer[offset + 1] = static_cast<uint8_t>((checksum >> 16) & 0xFF);
    buffer[offset + 2] = static_cast<uint8_t>((checksum >> 8) & 0xFF);
    buffer[offset + 3] = static_cast<uint8_t>(checksum & 0xFF);

    return buffer;
}

bool FrameProtocol::DeserializeFrame(const uint8_t* data, size_t size, TransportFrame& outFrame, std::string& outError) {
    if (!data || size < 18) {
        outError = "Frame too short";
        return false;
    }

    // 1. Magic check
    uint32_t magic = (static_cast<uint32_t>(data[0]) << 24) |
                     (static_cast<uint32_t>(data[1]) << 16) |
                     (static_cast<uint32_t>(data[2]) << 8)  |
                      static_cast<uint32_t>(data[3]);

    if (magic != FRAME_MAGIC) {
        outError = "Invalid magic bytes";
        return false;
    }

    // 2. PayloadLength check
    uint32_t payloadLen = (static_cast<uint32_t>(data[4]) << 24) |
                          (static_cast<uint32_t>(data[5]) << 16) |
                          (static_cast<uint32_t>(data[6]) << 8)  |
                           static_cast<uint32_t>(data[7]);

    if (payloadLen > MAX_PAYLOAD_SIZE) {
        outError = "Frame payload oversized";
        return false;
    }

    if (size < 14 + payloadLen + 4) {
        outError = "Incomplete frame buffer";
        return false;
    }

    // 3. CRC32 Checksum verification
    uint32_t expectedChecksum = (static_cast<uint32_t>(data[14 + payloadLen]) << 24)     |
                                (static_cast<uint32_t>(data[14 + payloadLen + 1]) << 16) |
                                (static_cast<uint32_t>(data[14 + payloadLen + 2]) << 8)  |
                                 static_cast<uint32_t>(data[14 + payloadLen + 3]);

    uint32_t actualChecksum = CalculateCrc32(data, 14 + payloadLen);
    if (actualChecksum != expectedChecksum) {
        outError = "CRC32 checksum mismatch (Frame corrupted)";
        return false;
    }

    // 4. Extract fields
    outFrame.magic = magic;
    outFrame.payloadLength = payloadLen;
    outFrame.messageType = static_cast<TransportMessageType>(data[8]);
    outFrame.flags = data[9];
    outFrame.sequenceNumber = (static_cast<uint32_t>(data[10]) << 24) |
                              (static_cast<uint32_t>(data[11]) << 16) |
                              (static_cast<uint32_t>(data[12]) << 8)  |
                               static_cast<uint32_t>(data[13]);

    outFrame.payload.assign(&data[14], &data[14 + payloadLen]);
    outFrame.checksum = actualChecksum;

    outError = "";
    return true;
}

} // namespace PhoneKey
