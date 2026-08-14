#include "FrameProtocol.h"
#include <cstring>
#include <iostream>
#include <limits>

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
    if (frame.payload.size() > MAX_PAYLOAD_SIZE) {
        return {};
    }

    uint32_t payloadLen = static_cast<uint32_t>(frame.payload.size());
    size_t totalLen = 14 + static_cast<size_t>(payloadLen) + 4;
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
    // 1. Strict null pointer and minimum header check (14B Header + 4B Checksum = 18B)
    if (!data) {
        outError = "Null buffer pointer";
        return false;
    }
    if (size < 18) {
        outError = "Frame buffer under 18 bytes minimum length";
        return false;
    }

    // 2. Validate magic bytes
    uint32_t magic = (static_cast<uint32_t>(data[0]) << 24) |
                     (static_cast<uint32_t>(data[1]) << 16) |
                     (static_cast<uint32_t>(data[2]) << 8)  |
                      static_cast<uint32_t>(data[3]);

    if (magic != FRAME_MAGIC) {
        outError = "Invalid magic bytes";
        return false;
    }

    // 3. Extract and validate payload length against maximum ceiling
    uint32_t payloadLen = (static_cast<uint32_t>(data[4]) << 24) |
                          (static_cast<uint32_t>(data[5]) << 16) |
                          (static_cast<uint32_t>(data[6]) << 8)  |
                           static_cast<uint32_t>(data[7]);

    if (payloadLen > MAX_PAYLOAD_SIZE) {
        outError = "Payload size exceeds 64KB security limit";
        return false;
    }

    // 4. Safe integer overflow check before computing total frame length
    size_t safePayloadLen = static_cast<size_t>(payloadLen);
    if (safePayloadLen > std::numeric_limits<size_t>::max() - 18) {
        outError = "Integer overflow in frame size computation";
        return false;
    }

    size_t totalFrameLen = 14 + safePayloadLen + 4;
    if (size < totalFrameLen) {
        outError = "Incomplete frame buffer: provided size less than calculated frame length";
        return false;
    }

    // 5. CRC32 Checksum verification
    size_t checksumOffset = 14 + safePayloadLen;
    uint32_t expectedChecksum = (static_cast<uint32_t>(data[checksumOffset]) << 24)     |
                                (static_cast<uint32_t>(data[checksumOffset + 1]) << 16) |
                                (static_cast<uint32_t>(data[checksumOffset + 2]) << 8)  |
                                 static_cast<uint32_t>(data[checksumOffset + 3]);

    uint32_t actualChecksum = CalculateCrc32(data, checksumOffset);
    if (actualChecksum != expectedChecksum) {
        outError = "CRC32 checksum mismatch (Frame corrupted)";
        return false;
    }

    // 6. Extract and validate message type enum bounds matching TransportMessageType
    uint8_t rawMessageType = data[8];
    if (rawMessageType != static_cast<uint8_t>(TransportMessageType::PAIR_REQ) &&
        rawMessageType != static_cast<uint8_t>(TransportMessageType::PAIR_RESP) &&
        rawMessageType != static_cast<uint8_t>(TransportMessageType::UNLOCK_REQ) &&
        rawMessageType != static_cast<uint8_t>(TransportMessageType::UNLOCK_RESP) &&
        rawMessageType != static_cast<uint8_t>(TransportMessageType::ERROR_MSG)) {
        outError = "Unknown message type identifier";
        return false;
    }

    outFrame.magic = magic;
    outFrame.payloadLength = payloadLen;
    outFrame.messageType = static_cast<TransportMessageType>(rawMessageType);
    outFrame.flags = data[9];
    outFrame.sequenceNumber = (static_cast<uint32_t>(data[10]) << 24) |
                              (static_cast<uint32_t>(data[11]) << 16) |
                              (static_cast<uint32_t>(data[12]) << 8)  |
                               static_cast<uint32_t>(data[13]);

    if (safePayloadLen > 0) {
        outFrame.payload.assign(&data[14], &data[14 + safePayloadLen]);
    } else {
        outFrame.payload.clear();
    }
    outFrame.checksum = actualChecksum;

    outError = "";
    return true;
}

} // namespace PhoneKey
