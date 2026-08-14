#ifndef PHONEKEY_CRYPTO_ENGINE_H
#define PHONEKEY_CRYPTO_ENGINE_H

#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>
#include <string>
#include "Protocol.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace PhoneKey {

class CryptoEngine {
public:
    CryptoEngine();
    ~CryptoEngine();

    // Initializes BCrypt algorithm providers
    bool Initialize();

    // Generates 32 bytes of cryptographically secure random data via BCryptGenRandom
    bool GenerateRandomBytes(uint8_t* buffer, size_t length);

    // Imports raw uncompressed EC public key (64 bytes: X || Y) into BCRYPT_KEY_HANDLE
    BCRYPT_KEY_HANDLE ImportRawPublicKey(const uint8_t* rawXyBytes, size_t length);

    // Imports DER/X.509 encoded EC public key into BCRYPT_KEY_HANDLE
    BCRYPT_KEY_HANDLE ImportDerPublicKey(const uint8_t* derBytes, size_t length);

    // Verifies an ASN.1 DER encoded ECDSA signature over SHA-256 digest of payload
    bool VerifySignature(BCRYPT_KEY_HANDLE hKey, const uint8_t* payloadData, size_t payloadSize, const uint8_t* signatureData, size_t signatureSize);

    // Helper: Converts ASN.1 DER signature to raw (r || s) 64-byte format expected by BCrypt
    static bool ConvertDerToRawRSignature(const uint8_t* derData, size_t derSize, std::vector<uint8_t>& rawRsOut);

private:
    BCRYPT_ALG_HANDLE m_hEcdsaAlg;
    BCRYPT_ALG_HANDLE m_hRngAlg;
    BCRYPT_ALG_HANDLE m_hSha256Alg;
};

} // namespace PhoneKey

#endif // PHONEKEY_CRYPTO_ENGINE_H
