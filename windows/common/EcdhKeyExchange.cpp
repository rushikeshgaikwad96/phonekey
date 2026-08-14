#include "EcdhKeyExchange.h"
#include <cstring>
#include <iostream>

#pragma comment(lib, "bcrypt.lib")

namespace PhoneKey {

EcdhKeyExchange::EcdhKeyExchange()
    : m_hEcdhAlg(NULL), m_hLocalKeyPair(NULL) {}

EcdhKeyExchange::~EcdhKeyExchange() {
    if (m_hLocalKeyPair) {
        BCryptDestroyKey(m_hLocalKeyPair);
        m_hLocalKeyPair = NULL;
    }
    if (m_hEcdhAlg) {
        BCryptCloseAlgorithmProvider(m_hEcdhAlg, 0);
        m_hEcdhAlg = NULL;
    }
}

bool EcdhKeyExchange::GenerateEphemeralKeyPair() {
    NTSTATUS status = BCryptOpenAlgorithmProvider(&m_hEcdhAlg, BCRYPT_ECDH_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return false;

    status = BCryptGenerateKeyPair(m_hEcdhAlg, &m_hLocalKeyPair, 256, 0);
    if (!NT_SUCCESS(status)) return false;

    status = BCryptFinalizeKeyPair(m_hLocalKeyPair, 0);
    return NT_SUCCESS(status);
}

std::vector<uint8_t> EcdhKeyExchange::GetPublicPointUncompressed() const {
    if (!m_hLocalKeyPair) return {};

    ULONG cbBlob = 0;
    NTSTATUS status = BCryptExportKey(m_hLocalKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, 0, &cbBlob, 0);
    if (!NT_SUCCESS(status) || cbBlob < sizeof(BCRYPT_ECCKEY_BLOB) + 64) return {};

    std::vector<uint8_t> blob(cbBlob);
    status = BCryptExportKey(m_hLocalKeyPair, NULL, BCRYPT_ECCPUBLIC_BLOB, blob.data(), cbBlob, &cbBlob, 0);
    if (!NT_SUCCESS(status)) return {};

    // BCRYPT_ECCKEY_BLOB layout: header followed by X (32 bytes) and Y (32 bytes)
    const uint8_t* xyData = blob.data() + sizeof(BCRYPT_ECCKEY_BLOB);

    std::vector<uint8_t> uncompressed(65);
    uncompressed[0] = 0x04; // Uncompressed EC point tag
    std::memcpy(uncompressed.data() + 1, xyData, 64);

    return uncompressed;
}

std::vector<uint8_t> EcdhKeyExchange::ComputeSharedSecret(const uint8_t* peerPublicXy, size_t length) {
    if (!m_hLocalKeyPair || !peerPublicXy || (length != 64 && length != 65)) return {};

    const uint8_t* xy = peerPublicXy;
    if (length == 65 && peerPublicXy[0] == 0x04) {
        xy = peerPublicXy + 1; // Skip 0x04 tag
    }

    // Build BCRYPT_ECCKEY_BLOB for peer's public key
    ULONG blobSize = sizeof(BCRYPT_ECCKEY_BLOB) + 64;
    std::vector<uint8_t> blob(blobSize, 0);

    BCRYPT_ECCKEY_BLOB* pEccBlob = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    pEccBlob->dwMagic = BCRYPT_ECDH_PUBLIC_P256_MAGIC;
    pEccBlob->cbKey = 32;

    std::memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), xy, 64);

    BCRYPT_KEY_HANDLE hPeerKey = NULL;
    NTSTATUS status = BCryptImportKeyPair(m_hEcdhAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hPeerKey, blob.data(), blobSize, 0);
    if (!NT_SUCCESS(status)) return {};

    // Perform secret agreement
    BCRYPT_SECRET_HANDLE hSecret = NULL;
    status = BCryptSecretAgreement(m_hLocalKeyPair, hPeerKey, &hSecret, 0);
    BCryptDestroyKey(hPeerKey);
    if (!NT_SUCCESS(status)) return {};

    // Derive raw shared secret S
    ULONG cbSecret = 0;
    status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, NULL, 0, &cbSecret, 0);
    if (!NT_SUCCESS(status) || cbSecret == 0) {
        BCryptDestroySecret(hSecret);
        return {};
    }

    std::vector<uint8_t> sharedSecret(cbSecret);
    status = BCryptDeriveKey(hSecret, BCRYPT_KDF_RAW_SECRET, NULL, sharedSecret.data(), cbSecret, &cbSecret, 0);
    BCryptDestroySecret(hSecret);
    if (!NT_SUCCESS(status)) return {};

    return sharedSecret;
}

} // namespace PhoneKey
