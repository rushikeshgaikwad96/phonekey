#include "DpapiStorage.h"
#include <fstream>
#include <iostream>

namespace PhoneKey {

bool DpapiStorage::EncryptData(const std::vector<uint8_t>& plaintext, std::vector<uint8_t>& outCiphertext) {
    if (plaintext.empty()) return false;

    DATA_BLOB dataIn;
    dataIn.pbData = const_cast<BYTE*>(plaintext.data());
    dataIn.cbData = static_cast<DWORD>(plaintext.size());

    DATA_BLOB dataOut;
    std::wstring desc = L"PhoneKey Encrypted Storage";

    if (!CryptProtectData(&dataIn, desc.c_str(), NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN | CRYPTPROTECT_LOCAL_MACHINE, &dataOut)) {
        return false;
    }

    outCiphertext.assign(dataOut.pbData, dataOut.pbData + dataOut.cbData);
    LocalFree(dataOut.pbData);
    return true;
}

bool DpapiStorage::DecryptData(const std::vector<uint8_t>& ciphertext, std::vector<uint8_t>& outPlaintext) {
    if (ciphertext.empty()) return false;

    DATA_BLOB dataIn;
    dataIn.pbData = const_cast<BYTE*>(ciphertext.data());
    dataIn.cbData = static_cast<DWORD>(ciphertext.size());

    DATA_BLOB dataOut;

    if (!CryptUnprotectData(&dataIn, NULL, NULL, NULL, NULL, CRYPTPROTECT_UI_FORBIDDEN, &dataOut)) {
        return false;
    }

    outPlaintext.assign(dataOut.pbData, dataOut.pbData + dataOut.cbData);
    LocalFree(dataOut.pbData);
    return true;
}

bool DpapiStorage::SaveToFile(const std::string& filePath, const std::vector<uint8_t>& plaintextData) {
    std::vector<uint8_t> encrypted;
    if (!EncryptData(plaintextData, encrypted)) return false;

    std::ofstream outFile(filePath, std::ios::binary);
    if (!outFile.is_open()) return false;

    outFile.write(reinterpret_cast<const char*>(encrypted.data()), encrypted.size());
    return outFile.good();
}

bool DpapiStorage::LoadFromFile(const std::string& filePath, std::vector<uint8_t>& outPlaintextData) {
    std::ifstream inFile(filePath, std::ios::binary);
    if (!inFile.is_open()) return false;

    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    if (encrypted.empty()) return false;

    return DecryptData(encrypted, outPlaintextData);
}

} // namespace PhoneKey
