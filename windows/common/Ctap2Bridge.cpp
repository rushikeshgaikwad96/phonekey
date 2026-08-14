#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "Ctap2Bridge.h"
#include <windows.h>
#include <bcrypt.h>
#include <cstring>

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

namespace PhoneKey {

std::vector<uint8_t> Ctap2Bridge::BuildAuthenticatorData(const std::string& relyingPartyId, uint32_t signCount, bool userVerified) {
    std::vector<uint8_t> authData(37, 0);

    // Compute SHA-256 hash of relyingPartyId -> rpidHash (32 Bytes)
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;

    if (NT_SUCCESS(BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) {
        if (NT_SUCCESS(BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0))) {
            BCryptHashData(hHash, reinterpret_cast<PUCHAR>(const_cast<char*>(relyingPartyId.data())), static_cast<ULONG>(relyingPartyId.size()), 0);
            BCryptFinishHash(hHash, authData.data(), 32, 0);
            BCryptDestroyHash(hHash);
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }

    // Flags: User Present (0x01) | User Verified (0x04)
    uint8_t flags = 0x01;
    if (userVerified) {
        flags |= 0x04;
    }
    authData[32] = flags;

    // Sign Counter (4 Bytes Big-Endian)
    authData[33] = static_cast<uint8_t>((signCount >> 24) & 0xFF);
    authData[34] = static_cast<uint8_t>((signCount >> 16) & 0xFF);
    authData[35] = static_cast<uint8_t>((signCount >> 8) & 0xFF);
    authData[36] = static_cast<uint8_t>(signCount & 0xFF);

    return authData;
}

AuthPayload Ctap2Bridge::TranslateToPhoneKeyPayload(
    const Ctap2GetAssertionRequest& req,
    const std::array<uint8_t, UUID_SIZE>& deviceId,
    const std::array<uint8_t, UUID_SIZE>& sessionId,
    const std::array<uint8_t, UUID_SIZE>& pcId,
    uint64_t expirationMs
) {
    AuthPayload p;
    p.protocolVersion = CURRENT_PROTOCOL_VERSION;
    p.algorithmId = ALGORITHM_ECDSA_P256_SHA256;
    p.deviceId = deviceId;
    p.sessionId = sessionId;
    p.pcId = pcId;
    p.challenge = req.clientDataHash;
    p.expirationTimestampMs = expirationMs;
    return p;
}

Ctap2GetAssertionResponse Ctap2Bridge::FormatAssertionResponse(
    const std::vector<uint8_t>& authData,
    const std::vector<uint8_t>& signatureDer
) {
    Ctap2GetAssertionResponse resp;
    resp.status = 0x00; // CTAP1_ERR_SUCCESS
    resp.authenticatorData = authData;
    resp.signatureDer = signatureDer;
    resp.userHandle = {0x01, 0x02, 0x03, 0x04};
    return resp;
}

} // namespace PhoneKey
