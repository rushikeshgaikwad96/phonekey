#include "CryptoEngine.h"
#include "PublicKeyImporter.h"
#include <iostream>
#include <vector>
#include <cstring>

#pragma comment(lib, "bcrypt.lib")

namespace PhoneKey {

CryptoEngine::CryptoEngine()
    : m_hEcdsaAlg(NULL), m_hRngAlg(NULL), m_hSha256Alg(NULL) {}

CryptoEngine::~CryptoEngine() {
    if (m_hEcdsaAlg) {
        BCryptCloseAlgorithmProvider(m_hEcdsaAlg, 0);
    }
    if (m_hRngAlg) {
        BCryptCloseAlgorithmProvider(m_hRngAlg, 0);
    }
    if (m_hSha256Alg) {
        BCryptCloseAlgorithmProvider(m_hSha256Alg, 0);
    }
}

bool CryptoEngine::Initialize() {
    NTSTATUS status = BCryptOpenAlgorithmProvider(&m_hEcdsaAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return false;

    status = BCryptOpenAlgorithmProvider(&m_hRngAlg, BCRYPT_RNG_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return false;

    status = BCryptOpenAlgorithmProvider(&m_hSha256Alg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) return false;

    return true;
}

bool CryptoEngine::GenerateRandomBytes(uint8_t* buffer, size_t length) {
    if (!buffer || length == 0) return false;
    NTSTATUS status = BCryptGenRandom(m_hRngAlg, buffer, static_cast<ULONG>(length), 0);
    return NT_SUCCESS(status);
}

BCRYPT_KEY_HANDLE CryptoEngine::ImportRawPublicKey(const uint8_t* rawXyBytes, size_t length) {
    return PublicKeyImporter::ImportRawPublicKey(m_hEcdsaAlg, rawXyBytes, length);
}

BCRYPT_KEY_HANDLE CryptoEngine::ImportDerPublicKey(const uint8_t* derBytes, size_t length) {
    return PublicKeyImporter::ImportDerPublicKey(m_hEcdsaAlg, derBytes, length);
}

bool CryptoEngine::ConvertDerToRawRSignature(const uint8_t* derData, size_t derSize, std::vector<uint8_t>& rawRsOut) {
    if (!derData || derSize < 8 || derSize > 139) return false;
    if (derData[0] != 0x30) return false; // Must start with DER Sequence tag

    size_t idx = 2; // Skip 0x30 and sequence length

    // Parse r
    if (idx >= derSize || derData[idx] != 0x02) return false;
    idx++;
    size_t rLen = derData[idx++];
    if (idx + rLen > derSize) return false;

    const uint8_t* rBytes = &derData[idx];
    idx += rLen;

    // Parse s
    if (idx >= derSize || derData[idx] != 0x02) return false;
    idx++;
    size_t sLen = derData[idx++];
    if (idx + sLen > derSize) return false;

    const uint8_t* sBytes = &derData[idx];

    // Strip leading 0x00 bytes added for positive integer sign in DER
    while (rLen > 32 && rBytes[0] == 0x00) { rBytes++; rLen--; }
    while (sLen > 32 && sBytes[0] == 0x00) { sBytes++; sLen--; }

    if (rLen > 32 || sLen > 32) return false;

    rawRsOut.assign(64, 0);
    // Right-align r into first 32 bytes
    std::memcpy(rawRsOut.data() + (32 - rLen), rBytes, rLen);
    // Right-align s into second 32 bytes
    std::memcpy(rawRsOut.data() + 32 + (32 - sLen), sBytes, sLen);

    return true;
}

bool CryptoEngine::VerifySignature(BCRYPT_KEY_HANDLE hKey, const uint8_t* payloadData, size_t payloadSize, const uint8_t* signatureData, size_t signatureSize) {
    if (!hKey || !payloadData || payloadSize == 0 || !signatureData || signatureSize == 0) {
        return false;
    }

    // 1. Hash payload with SHA-256
    BCRYPT_HASH_HANDLE hHash = NULL;
    NTSTATUS status = BCryptCreateHash(m_hSha256Alg, &hHash, NULL, 0, NULL, 0, 0);
    if (!NT_SUCCESS(status)) return false;

    status = BCryptHashData(hHash, const_cast<UCHAR*>(payloadData), static_cast<ULONG>(payloadSize), 0);
    if (!NT_SUCCESS(status)) {
        BCryptDestroyHash(hHash);
        return false;
    }

    std::vector<uint8_t> hashBuf(32, 0);
    status = BCryptFinishHash(hHash, hashBuf.data(), 32, 0);
    BCryptDestroyHash(hHash);
    if (!NT_SUCCESS(status)) return false;

    // 2. Convert DER signature to Raw 64-byte (r || s)
    std::vector<uint8_t> rawRs;
    if (signatureSize == 64) {
        rawRs.assign(signatureData, signatureData + 64);
    } else {
        if (!ConvertDerToRawRSignature(signatureData, signatureSize, rawRs)) {
            return false; // Malformed DER signature
        }
    }

    // 3. Verify signature via CNG BCryptVerifySignature
    status = BCryptVerifySignature(hKey, NULL, hashBuf.data(), 32, rawRs.data(), static_cast<ULONG>(rawRs.size()), 0);
    return NT_SUCCESS(status);
}

} // namespace PhoneKey
