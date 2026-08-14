# PhoneKey Architecture Specification

## 1. Overview
PhoneKey is an open-source, local-only authentication system enabling an Android smartphone's hardware-backed biometric security (fingerprint/face) to authorize unlocking a Windows PC.

PhoneKey adheres to zero-trust principles for local network environments. Fingerprint and biometric template data **NEVER** leave the Android hardware isolate (TEE/StrongBox). The phone functions purely as an asymmetric cryptographic signing token.

---

## 2. Component Architecture (Milestone 2 Scope)

```
+-----------------------------------------------------------------------------------+
|                                  PHONEKEY SYSTEM                                  |
|                                                                                   |
|  +------------------------+                        +---------------------------+  |
|  |     ANDROID DEVICE     |                        |        WINDOWS PC         |  |
|  |                        |                        |                           |  |
|  |  +------------------+  |                        |  +---------------------+  |  |
|  |  | KeyManager &     |  |                        |  | ChallengeGenerator  |  |  |
|  |  | ProtocolEncoder  |  |                        |  | & ChallengeStore    |  |  |
|  |  +------------------+  |                        |  +---------------------+  |  |
|  |           |            |                        |             |             |  |
|  |           v            |                        |             v             |  |
|  |  +------------------+  |                        |  +---------------------+  |  |
|  |  | BiometricSigner  |  |  Canonical Auth        |  | SignatureVerifier   |  |  |
|  |  | AndroidX Gate    |  |  Payload (108 Bytes)   |  | (CNG BCrypt P-256)  |  |  |
|  |  +------------------+  | <====================> |  +---------------------+  |  |
|  |           |            |                        |             |             |  |
|  |           v            |                        |             v             |  |
|  |  +------------------+  |                        |  +---------------------+  |  |
|  |  | Android Keystore |  |                        |  | DeviceRegistry      |  |  |
|  |  | TEE / StrongBox  |  |                        |  | (Dev Registered PK) |  |  |
|  |  | ECDSA P-256 Sign |  |                        |  +---------------------+  |  |
|  |  +------------------+  |                        +---------------------------+  |
|  +------------------------+                                                       |
+-----------------------------------------------------------------------------------+
```

---

## 3. Subsystem Breakdown (Milestone 2)

### 3.1 Android Cryptographic Component
- **Language**: Kotlin / Java.
- **Biometrics**: AndroidX `BiometricPrompt` API. Requests `BIOMETRIC_STRONG` authentication.
- **Key Storage**: Android Keystore (`AndroidKeyStore` provider) utilizing `KeyGenParameterSpec`. Keys are ECDSA P-256 (secp256r1), non-exportable, hardware-backed in TEE or StrongBox Keymaster when available.
- **Security Constraints**: Key usage requires per-operation user authentication (`setUserAuthenticationRequired(true)`, validity 0s). Key invalidated if new fingerprints are enrolled (`setInvalidatedByBiometricEnrollment(true)`).
- **Domain-Separated Encoding**: `ProtocolEncoder` packs fields deterministically into a 108-byte binary structure prefixed with `PhoneKey-Auth-v1`.

### 3.2 Windows Cryptographic Component
- **Language & Stack**: Modern C++ (C++20), Windows Cryptography Next Generation (CNG API: `BCrypt`).
- **Function**: Generates 256-bit cryptographically secure random challenges using `BCryptGenRandom`, manages active single-use challenge states with 30s TTL, and verifies ECDSA SHA-256 DER signatures using CNG `BCryptVerifySignature`.
- **Registry**: Manages development public key imports without trusting network-supplied public keys during authentication.

---

## 4. Milestone Roadmap & Scope Mapping

| Feature | Milestone Status | Implementation Status |
| :--- | :--- | :--- |
| **Android Keystore ECDSA P-256 Key Gen** | **Milestone 2** | **Implemented** |
| **BiometricPrompt Hardware Gate** | **Milestone 2** | **Implemented** |
| **Windows CNG BCrypt Signature Verifier** | **Milestone 2** | **Implemented** |
| **Challenge Store & 30s TTL Replay Defense** | **Milestone 2** | **Implemented** |
| **Deterministic Cross-Platform Test Vectors** | **Milestone 2** | **Implemented** |
| **QR Code / ECDH / HKDF / SAS Pairing** | Milestone 3 | Future / Out of Scope for M2 |
| **Network Transport (Wi-Fi / BLE / Noise)** | Milestone 4 | Future / Out of Scope for M2 |
| **End-to-End App Integration** | Milestone 5 | Future / Out of Scope for M2 |
| **Windows Credential Provider (COM DLL)** | Milestone 6 | Future / Out of Scope for M2 |
| **Installer & Packaging** | Milestone 7 | Future / Out of Scope for M2 |
