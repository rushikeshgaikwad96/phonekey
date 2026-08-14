#ifndef PHONEKEY_SAS_ENGINE_H
#define PHONEKEY_SAS_ENGINE_H

#include <vector>
#include <cstdint>
#include <string>

namespace PhoneKey {

class SasEngine {
public:
    // Computes 6-digit SAS PIN (string format "100000" to "999999") from K_sas key
    static std::string ComputeSasPin(const uint8_t* kSas, size_t keyLen);
};

} // namespace PhoneKey

#endif // PHONEKEY_SAS_ENGINE_H
