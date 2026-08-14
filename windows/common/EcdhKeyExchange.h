#ifndef PHONEKEY_ECDH_KEY_EXCHANGE_H
#define PHONEKEY_ECDH_KEY_EXCHANGE_H

#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace PhoneKey {

class EcdhKeyExchange {
public:
    EcdhKeyExchange();
    ~EcdhKeyExchange();

    // Initializes CNG ECDH provider and generates an ephemeral P-256 keypair
    bool GenerateEphemeralKeyPair();

    // Gets raw uncompressed public key (65 bytes: 0x04 || X || Y) for QR code / payload
    std::vector<uint8_t> GetPublicPointUncompressed() const;

    // Computes ECDH shared secret S (32 bytes) with peer's raw uncompressed public key
    std::vector<uint8_t> ComputeSharedSecret(const uint8_t* peerPublicXy, size_t length);

private:
    BCRYPT_ALG_HANDLE m_hEcdhAlg;
    BCRYPT_KEY_HANDLE m_hLocalKeyPair;
};

} // namespace PhoneKey

#endif // PHONEKEY_ECDH_KEY_EXCHANGE_H
