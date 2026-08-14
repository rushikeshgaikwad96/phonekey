#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <cassert>
#include <cstring>
#include "../windows/common/EcdhKeyExchange.h"
#include "../windows/common/HkdfEngine.h"
#include "../windows/common/SasEngine.h"
#include "../windows/agent/DpapiStorage.h"

using namespace PhoneKey;

// Helper: Convert hex string to byte vector
std::vector<uint8_t> HexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < hex.length(); i += 2) {
        std::string byteString = hex.substr(i, 2);
        uint8_t byte = static_cast<uint8_t>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

// Minimal JSON extractor helper
std::string ExtractJsonField(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\"");
    if (pos == std::string::npos) return "";
    size_t colon = json.find(":", pos);
    if (colon == std::string::npos) return "";
    size_t start = json.find("\"", colon);
    if (start == std::string::npos) return "";
    size_t end = json.find("\"", start + 1);
    if (end == std::string::npos) return "";
    return json.substr(start + 1, end - start - 1);
}

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << " [FAIL] " << msg << " (Line " << __LINE__ << ")" << std::endl; \
        return false; \
    } else { \
        std::cout << " [PASS] " << msg << std::endl; \
    }

bool TestCngEcdhAndHkdf() {
    std::cout << "--- Running CNG Ephemeral ECDH & HKDF Key Exchange Tests ---" << std::endl;

    EcdhKeyExchange pcEcdh;
    TEST_ASSERT(pcEcdh.GenerateEphemeralKeyPair(), "PC Ephemeral ECDH keypair generated");
    std::vector<uint8_t> pcPub = pcEcdh.GetPublicPointUncompressed();
    TEST_ASSERT(pcPub.size() == 65 && pcPub[0] == 0x04, "PC Public Point is uncompressed 65 bytes");

    EcdhKeyExchange phoneEcdh;
    TEST_ASSERT(phoneEcdh.GenerateEphemeralKeyPair(), "Phone Ephemeral ECDH keypair generated");
    std::vector<uint8_t> phonePub = phoneEcdh.GetPublicPointUncompressed();
    TEST_ASSERT(phonePub.size() == 65 && phonePub[0] == 0x04, "Phone Public Point is uncompressed 65 bytes");

    // Perform Secret Agreement on both ends
    std::vector<uint8_t> sPc = pcEcdh.ComputeSharedSecret(phonePub.data(), phonePub.size());
    std::vector<uint8_t> sPhone = phoneEcdh.ComputeSharedSecret(pcPub.data(), pcPub.size());

    TEST_ASSERT(!sPc.empty() && sPc.size() == 32, "PC derived 32-byte shared secret S");
    TEST_ASSERT(!sPhone.empty() && sPhone.size() == 32, "Phone derived 32-byte shared secret S");
    TEST_ASSERT(sPc == sPhone, "Bilateral ECDH shared secrets S match identically!");

    // Test HKDF-SHA256 derivation
    std::vector<uint8_t> sessionId(16, 0xAA);
    std::vector<uint8_t> kEncPc = HkdfEngine::DeriveKey(sessionId.data(), sessionId.size(), sPc.data(), sPc.size(), "PhoneKey-Pairing-Enc", 32);
    std::vector<uint8_t> kSasPc = HkdfEngine::DeriveKey(sessionId.data(), sessionId.size(), sPc.data(), sPc.size(), "PhoneKey-Pairing-SAS", 32);

    TEST_ASSERT(kEncPc.size() == 32, "Derived 32-byte K_enc");
    TEST_ASSERT(kSasPc.size() == 32, "Derived 32-byte K_sas");

    // Test 6-Digit SAS PIN calculation
    std::string pinPc = SasEngine::ComputeSasPin(kSasPc.data(), kSasPc.size());
    TEST_ASSERT(pinPc.length() == 6, "SAS PIN is exactly 6 digits");
    std::cout << " Computed 6-digit SAS PIN: " << pinPc << std::endl;

    return true;
}

bool TestCrossPlatformPairingVector() {
    std::cout << "--- Running Cross-Platform Pairing Test Vector Verification ---" << std::endl;

    std::ifstream fIn("protocol/test-vectors/vector_pairing_valid.json");
    TEST_ASSERT(fIn.is_open(), "vector_pairing_valid.json opened");

    std::stringstream buf; buf << fIn.rdbuf();
    std::string jsonStr = buf.str();

    std::string sessionIdHex = ExtractJsonField(jsonStr, "session_id_hex");
    std::string pcPubHex     = ExtractJsonField(jsonStr, "pc_ecdh_pub_hex");
    std::string phonePubHex  = ExtractJsonField(jsonStr, "phone_ecdh_pub_hex");
    std::string sharedSecretHex = ExtractJsonField(jsonStr, "shared_secret_hex");
    std::string kSasHex      = ExtractJsonField(jsonStr, "k_sas_hex");
    std::string expectedSasPin  = ExtractJsonField(jsonStr, "expected_sas_pin");

    TEST_ASSERT(!sessionIdHex.empty() && !kSasHex.empty() && !expectedSasPin.empty(), "Extracted test vector fields");

    std::vector<uint8_t> kSasBytes = HexToBytes(kSasHex);
    std::string computedPin = SasEngine::ComputeSasPin(kSasBytes.data(), kSasBytes.size());

    TEST_ASSERT(computedPin == expectedSasPin, "Cross-platform SAS 6-digit PIN matches expected vector!");
    std::cout << " Expected SAS: " << expectedSasPin << " | Computed SAS: " << computedPin << std::endl;

    return true;
}

bool TestDpapiStorage() {
    std::cout << "--- Running Windows DPAPI Encrypted Storage Tests ---" << std::endl;

    std::vector<uint8_t> testData = {0x01, 0x02, 0x03, 0x04, 0x05, 0xAA, 0xBB, 0xCC};
    std::vector<uint8_t> encrypted;
    std::vector<uint8_t> decrypted;

    bool encRes = DpapiStorage::EncryptData(testData, encrypted);
    TEST_ASSERT(encRes && !encrypted.empty(), "Windows DPAPI CryptProtectData encrypted plaintext");
    TEST_ASSERT(encrypted != testData, "Ciphertext is encrypted and different from plaintext");

    bool decRes = DpapiStorage::DecryptData(encrypted, decrypted);
    TEST_ASSERT(decRes && decrypted == testData, "Windows DPAPI CryptUnprotectData decrypted data identically");

    // File I/O test
    std::string testFile = "dpapi_test_temp.dat";
    bool saveRes = DpapiStorage::SaveToFile(testFile, testData);
    TEST_ASSERT(saveRes, "Saved DPAPI encrypted data to file");

    std::vector<uint8_t> fileLoaded;
    bool loadRes = DpapiStorage::LoadFromFile(testFile, fileLoaded);
    TEST_ASSERT(loadRes && fileLoaded == testData, "Loaded and decrypted DPAPI file identically");

    std::remove(testFile.c_str());
    return true;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "      PHONEKEY MILESTONE 3 PAIRING TEST SUITE       " << std::endl;
    std::cout << "====================================================" << std::endl;

    bool allPassed = true;
    allPassed &= TestCngEcdhAndHkdf();
    allPassed &= TestCrossPlatformPairingVector();
    allPassed &= TestDpapiStorage();

    std::cout << "====================================================" << std::endl;
    if (allPassed) {
        std::cout << "    ALL MILESTONE 3 PAIRING TESTS PASSED!         " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 0;
    } else {
        std::cerr << "    SOME PAIRING TESTS FAILED!                    " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 1;
    }
}
