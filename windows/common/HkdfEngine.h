#ifndef PHONEKEY_HKDF_ENGINE_H
#define PHONEKEY_HKDF_ENGINE_H

#include <vector>
#include <cstdint>
#include <string>

namespace PhoneKey {

class HkdfEngine {
public:
    // Computes HMAC-SHA256(key, data)
    static std::vector<uint8_t> HmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen);

    // HKDF-Extract(salt, ikm) -> 32-byte PRK
    static std::vector<uint8_t> Extract(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen);

    // HKDF-Expand(prk, info, outLen) -> derived key bytes
    static std::vector<uint8_t> Expand(const uint8_t* prk, size_t prkLen, const std::string& info, size_t outLen);

    // Full HKDF(salt, ikm, info, outLen)
    static std::vector<uint8_t> DeriveKey(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen, const std::string& info, size_t outLen);
};

} // namespace PhoneKey

#endif // PHONEKEY_HKDF_ENGINE_H
