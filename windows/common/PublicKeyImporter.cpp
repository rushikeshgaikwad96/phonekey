#include "PublicKeyImporter.h"
#include <cstring>

namespace PhoneKey {

BCRYPT_KEY_HANDLE PublicKeyImporter::ImportRawPublicKey(BCRYPT_ALG_HANDLE hEcdsaAlg, const uint8_t* rawXyBytes, size_t length) {
    if (!hEcdsaAlg || !rawXyBytes || (length != 64 && length != 65)) return NULL;

    const uint8_t* xy = rawXyBytes;
    if (length == 65 && rawXyBytes[0] == 0x04) {
        xy = rawXyBytes + 1; // Skip 0x04 uncompressed point marker if present
    }

    ULONG blobSize = sizeof(BCRYPT_ECCKEY_BLOB) + 64;
    std::vector<uint8_t> blob(blobSize, 0);

    BCRYPT_ECCKEY_BLOB* pEccBlob = reinterpret_cast<BCRYPT_ECCKEY_BLOB*>(blob.data());
    pEccBlob->dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
    pEccBlob->cbKey = 32;

    std::memcpy(blob.data() + sizeof(BCRYPT_ECCKEY_BLOB), xy, 64);

    BCRYPT_KEY_HANDLE hKey = NULL;
    NTSTATUS status = BCryptImportKeyPair(hEcdsaAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hKey, blob.data(), blobSize, 0);
    if (!NT_SUCCESS(status)) return NULL;

    return hKey;
}

BCRYPT_KEY_HANDLE PublicKeyImporter::ImportDerPublicKey(BCRYPT_ALG_HANDLE hEcdsaAlg, const uint8_t* derBytes, size_t length) {
    if (!hEcdsaAlg || !derBytes || length < 64) return NULL;

    // Search for 64-byte uncompressed EC point or 0x04 header inside DER structure
    for (size_t i = 0; i <= length - 64; ++i) {
        if (length - i >= 65 && derBytes[i] == 0x04) {
            BCRYPT_KEY_HANDLE hKey = ImportRawPublicKey(hEcdsaAlg, &derBytes[i + 1], 64);
            if (hKey) return hKey;
        }
        BCRYPT_KEY_HANDLE hKey = ImportRawPublicKey(hEcdsaAlg, &derBytes[i], 64);
        if (hKey) return hKey;
    }
    return NULL;
}

} // namespace PhoneKey
