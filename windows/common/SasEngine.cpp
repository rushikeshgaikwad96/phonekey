#include "SasEngine.h"
#include "HkdfEngine.h"
#include <sstream>
#include <iomanip>

namespace PhoneKey {

std::string SasEngine::ComputeSasPin(const uint8_t* kSas, size_t keyLen) {
    if (!kSas || keyLen == 0) return "000000";

    std::string infoStr = "PhoneKey-SAS-PIN";
    std::vector<uint8_t> mac = HkdfEngine::HmacSha256(kSas, keyLen, reinterpret_cast<const uint8_t*>(infoStr.data()), infoStr.size());
    if (mac.size() < 4) return "000000";

    uint32_t val = (static_cast<uint32_t>(mac[0]) << 24) |
                   (static_cast<uint32_t>(mac[1]) << 16) |
                   (static_cast<uint32_t>(mac[2]) << 8)  |
                    static_cast<uint32_t>(mac[3]);

    uint32_t pin = (val % 900000) + 100000;

    std::ostringstream oss;
    oss << std::setw(6) << std::setfill('0') << pin;
    return oss.str();
}

} // namespace PhoneKey
