#ifndef PHONEKEY_PUBLIC_KEY_IMPORTER_H
#define PHONEKEY_PUBLIC_KEY_IMPORTER_H

#include <windows.h>
#include <bcrypt.h>
#include <vector>
#include <cstdint>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace PhoneKey {

class PublicKeyImporter {
public:
    // Imports raw uncompressed EC point (64 bytes: X || Y, or 65 bytes: 0x04 || X || Y) into CNG BCRYPT_KEY_HANDLE
    static BCRYPT_KEY_HANDLE ImportRawPublicKey(BCRYPT_ALG_HANDLE hEcdsaAlg, const uint8_t* rawXyBytes, size_t length);

    // Imports X.509 SubjectPublicKeyInfo / DER encoded EC public key into CNG BCRYPT_KEY_HANDLE
    static BCRYPT_KEY_HANDLE ImportDerPublicKey(BCRYPT_ALG_HANDLE hEcdsaAlg, const uint8_t* derBytes, size_t length);
};

} // namespace PhoneKey

#endif // PHONEKEY_PUBLIC_KEY_IMPORTER_H
