#ifndef PHONEKEY_FRAME_PROTOCOL_H
#define PHONEKEY_FRAME_PROTOCOL_H

#include "TransportInterface.h"
#include <vector>
#include <cstdint>
#include <cstddef>

namespace PhoneKey {

class FrameProtocol {
public:
    // Calculates IEEE 802.3 CRC32 checksum over buffer
    static uint32_t CalculateCrc32(const uint8_t* data, size_t length);

    // Serializes TransportFrame into binary byte buffer (14B Header + Payload + 4B Checksum)
    static std::vector<uint8_t> SerializeFrame(const TransportFrame& frame);

    // Deserializes binary byte buffer into TransportFrame, verifying magic and CRC32 checksum
    static bool DeserializeFrame(const uint8_t* data, size_t size, TransportFrame& outFrame, std::string& outError);
};

} // namespace PhoneKey

#endif // PHONEKEY_FRAME_PROTOCOL_H
