# PhoneKey Security Self-Assessment & Internal Design Review

> [!NOTE]
> This document is an **internal design review and self-assessment** conducted by the author. It has **not** been audited or verified by an independent third-party security firm.

## 1. Executive Summary

PhoneKey was designed around zero-trust local authentication principles. The architecture ensures that biometric data **never** leaves the Android device, private keys remain inside hardware isolates (TEE/StrongBox), and plaintext passwords or NT hashes are **never** transmitted over network or Bluetooth interfaces.

This document reviews the specific implementation mechanisms, exact source code citations, and realistic assessment statuses for each core security claim.

---

## 2. Security Guarantees & Implementation Citations

### Guarantee 1: Zero Biometric Data Exposure
- **Claim**: Raw biometric images or templates never leave the Android TEE/StrongBox or get transmitted over network interfaces.
- **Status**: **Implemented as designed (Self-reviewed)**
- **Code Citation**:
  - [BiometricSigner.kt](file:///d:/projects/fingerprintapp/android/app/src/main/java/com/phonekey/crypto/BiometricSigner.kt#L33-L41): Interacts with AndroidX `BiometricPrompt` using `BiometricPrompt.CryptoObject(signature)`. On biometric success, it receives only an authenticated `Signature` instance to produce a 64-byte DER signature. No biometric template data is accessible or exported.

### Guarantee 2: Hardware Private Key Isolation & Invalidation
- **Claim**: Android authentication private keys are non-exportable, hardware-backed, enforce `AUTH_BIOMETRIC_STRONG`, and invalidate upon new biometric enrollment.
- **Status**: **Implemented as designed (Self-reviewed)**
- **Code Citation**:
  - [KeyManager.kt](file:///d:/projects/fingerprintapp/android/app/src/main/java/com/phonekey/crypto/KeyManager.kt#L48-L68): Configures `KeyGenParameterSpec` with `setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))`, `setUserAuthenticationRequired(true)`, `setInvalidatedByBiometricEnrollment(true)`, and `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`.

### Guarantee 3: Zero Network Password Transmissions
- **Claim**: Windows user credentials are never transmitted over network or Bluetooth sockets.
- **Status**: **Implemented as designed (Self-reviewed)**
- **Code Citation**:
  - [DpapiStorage.cpp](file:///d:/projects/fingerprintapp/windows/agent/DpapiStorage.cpp#L18-L45): Local credentials are encrypted using Windows DPAPI (`CryptProtectData`) with `CRYPTPROTECT_UI_FORBIDDEN` and stored locally on disk.
  - [NamedPipeIpc.cpp](file:///d:/projects/fingerprintapp/windows/common/NamedPipeIpc.cpp#L12-L85): Decrypted logon buffers are transmitted exclusively over local Windows Named Pipes (`\\.\pipe\PhoneKeyIPC`) directly to `logonui.exe`.

### Guarantee 4: Replay & Challenge Expiration Defense
- **Claim**: Challenges are 256-bit CSPRNG nonces with a 30-second TTL and single-use state transitions (`OUTSTANDING` $\rightarrow$ `CONSUMED`).
- **Status**: **Implemented as designed (Self-reviewed)**
- **Code Citation**:
  - [ChallengeGenerator.cpp](file:///d:/projects/fingerprintapp/windows/agent/ChallengeGenerator.cpp#L12-L28): Generates 256-bit nonces using Windows CNG `BCryptGenRandom`.
  - [ChallengeStore.cpp](file:///d:/projects/fingerprintapp/windows/agent/ChallengeStore.cpp#L64-L103): Validates TTL and marks challenge state `CONSUMED`.

### Guarantee 5: Out-of-Process Logon UI Isolation
- **Claim**: Credential Provider COM DLL in `logonui.exe` contains zero socket/network code.
- **Status**: **Implemented as designed (Self-reviewed)**
- **Code Citation**:
  - [PhoneKeyCredentialProvider.cpp](file:///d:/projects/fingerprintapp/windows/credential-provider/PhoneKeyCredentialProvider.cpp): `logonui.exe` loads only the COM DLL, which uses `NamedPipeIpcClient` to communicate locally with background agent `PhoneKeyAgent.exe`.

### Guarantee 6: Fail-Closed Security Guarantee
- **Claim**: Network failures, timeouts, frame corruption, or invalid signatures cause the provider to safely fail back to standard Windows Password/PIN tiles.
- **Status**: **Implemented as designed (Self-reviewed)**
- **Code Citation**:
  - [PhoneKeyCredential.cpp](file:///d:/projects/fingerprintapp/windows/credential-provider/PhoneKeyCredential.cpp#L80-L115): Returns `CPGSR_NO_CREDENTIAL_FINISHED` on error or invalid response, ensuring standard Windows logon tiles remain active.

---

## 3. Implementation Verification & Testing Matrix

| Security Claim | Implementation Mechanism | Author Self-Review Status | Independent 3rd-Party Audit |
| :--- | :--- | :--- | :--- |
| **Zero Biometric Exposure** | `BiometricPrompt.CryptoObject` binding | Implemented as designed | Not independently tested |
| **Hardware Key Isolation** | Keystore `KeyGenParameterSpec` | Implemented as designed | Not independently tested |
| **Zero Network Passwords** | Windows DPAPI + Local Named Pipe | Implemented as designed | Not independently tested |
| **Replay Defense** | CNG CSPRNG + 30s TTL | Implemented as designed | Not independently tested |
| **LogonUI Isolation** | Out-of-process COM DLL IPC | Implemented as designed | Not independently tested |
| **Fail-Closed Fallback** | `CPGSR_NO_CREDENTIAL_FINISHED` | Implemented as designed | Not independently tested |
