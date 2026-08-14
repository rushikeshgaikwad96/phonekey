#ifndef PHONEKEY_DPAPI_STORAGE_H
#define PHONEKEY_DPAPI_STORAGE_H

#include <windows.h>
#include <wincrypt.h>
#include <vector>
#include <string>
#include <cstdint>

#pragma comment(lib, "crypt32.lib")

namespace PhoneKey {

class DpapiStorage {
public:
    // Encrypts plaintext bytes using Windows DPAPI (CryptProtectData bound to LOCAL_MACHINE)
    static bool EncryptData(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& outCiphertext);

    // Decrypts ciphertext bytes using Windows DPAPI (CryptUnprotectData)
    static bool DecryptData(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& outPlaintext);

    // Saves encrypted data to file
    static bool SaveToFile(const std::string& filePath, const std::vector<uint8_t>& plaintextData);

    // Loads and decrypts data from file
    static bool LoadFromFile(const std::string& filePath, std::vector<uint8_t>& outPlaintextData);
};

} // namespace PhoneKey

#endif // PHONEKEY_DPAPI_STORAGE_H
