#include "HkdfEngine.h"
#include <windows.h>
#include <bcrypt.h>
#include <cstring>
#include <algorithm>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace PhoneKey {

std::vector<uint8_t> HkdfEngine::HmacSha256(const uint8_t* key, size_t keyLen, const uint8_t* data, size_t dataLen) {
    if (!key || keyLen == 0) return {};

    BCRYPT_ALG_HANDLE hAlg = NULL;
    NTSTATUS status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
    if (!NT_SUCCESS(status)) return {};

    BCRYPT_HASH_HANDLE hHash = NULL;
    status = BCryptCreateHash(hAlg, &hHash, NULL, 0, const_cast<PUCHAR>(key), static_cast<ULONG>(keyLen), 0);
    if (!NT_SUCCESS(status)) {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return {};
    }

    if (data && dataLen > 0) {
        status = BCryptHashData(hHash, const_cast<PUCHAR>(data), static_cast<ULONG>(dataLen), 0);
        if (!NT_SUCCESS(status)) {
            BCryptDestroyHash(hHash);
            BCryptCloseAlgorithmProvider(hAlg, 0);
            return {};
        }
    }

    std::vector<uint8_t> mac(32, 0);
    status = BCryptFinishHash(hHash, mac.data(), 32, 0);

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    if (!NT_SUCCESS(status)) return {};
    return mac;
}

std::vector<uint8_t> HkdfEngine::Extract(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen) {
    std::vector<uint8_t> actualSalt;
    if (!salt || saltLen == 0) {
        actualSalt.assign(32, 0);
    } else {
        actualSalt.assign(salt, salt + saltLen);
    }
    return HmacSha256(actualSalt.data(), actualSalt.size(), ikm, ikmLen);
}

std::vector<uint8_t> HkdfEngine::Expand(const uint8_t* prk, size_t prkLen, const std::string& info, size_t outLen) {
    if (!prk || prkLen == 0 || outLen == 0) return {};

    std::vector<uint8_t> okm;
    std::vector<uint8_t> t;
    uint8_t counter = 1;

    while (okm.size() < outLen) {
        std::vector<uint8_t> msg;
        msg.reserve(t.size() + info.size() + 1);
        msg.insert(msg.end(), t.begin(), t.end());
        msg.insert(msg.end(), info.begin(), info.end());
        msg.push_back(counter);

        t = HmacSha256(prk, prkLen, msg.data(), msg.size());
        if (t.empty()) return {};

        size_t toCopy = (std::min)(t.size(), outLen - okm.size());
        okm.insert(okm.end(), t.begin(), t.begin() + toCopy);
        counter++;
    }

    return okm;
}

std::vector<uint8_t> HkdfEngine::DeriveKey(const uint8_t* salt, size_t saltLen, const uint8_t* ikm, size_t ikmLen, const std::string& info, size_t outLen) {
    std::vector<uint8_t> prk = Extract(salt, saltLen, ikm, ikmLen);
    if (prk.empty()) return {};
    return Expand(prk.data(), prk.size(), info, outLen);
}

} // namespace PhoneKey
