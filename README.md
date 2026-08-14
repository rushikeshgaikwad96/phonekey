# PhoneKey — Open-Source Android Fingerprint → Windows Unlock

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Android%2010%2B-brightgreen)
![Security Review](https://img.shields.io/badge/security-self--assessed-blue)
![Build](https://img.shields.io/badge/build-MSVC%20C%2B%2B20%20%7C%20Gradle-orange)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-blue)

**PhoneKey** is an open-source project by [@rushikeshgaikwad96](https://github.com/rushikeshgaikwad96) that allows an Android smartphone's hardware-backed biometric authentication (fingerprint/face) to authorize unlocking a Windows PC over local encrypted transport channels (Wi-Fi Sockets / Bluetooth LE).

The phone acts as a cryptographic authentication token. The user's fingerprint or biometric data **NEVER** leaves the Android device.

---

## 🏛️ System Architecture & Process Isolation

```
   Windows Desktop Agent Host                                    Android Device
   ==========================                                    ==============
[1. User Initiates Unlock / Connection]
[2. ChallengeGenerator creates 256-bit Nonce C]
[3. ChallengeStore saves Nonce C (30s TTL)]
[4. Construct UNLOCK_REQ Frame]
[5. Send via TcpTransport / BleTransport]  === Frame (0x10) ===> [6. TcpTransportClient receives frame]
                                                                 [7. ProtocolValidator checks PC ID & Expiry]
                                                                 [8. Trigger BiometricPrompt ("Unlock Windows")]
                                                                 [9. User Scans Fingerprint (BIOMETRIC_STRONG)]
                                                                 [10. Android Keystore authorizes P-256 Sign]
                                                                 [11. Construct 108-byte Canonical Payload P]
                                                                 [12. Signature.sign(P) -> DER Signature]
                                                                 [13. Construct UNLOCK_RESP Frame]
                                           <=== Frame (0x11) === [14. Send back to Windows Agent]
[15. Windows Agent parses UNLOCK_RESP]
[16. DeviceRegistry looks up trusted Public Key]
[17. CryptoEngine performs CNG BCryptVerifySignature]
[18. ChallengeStore atomically consumes Nonce C]
[19. Return AUTHENTICATION SUCCESS (0x0000)]
                                 |
                     Protected Local Named Pipe
                       (\\.\pipe\PhoneKeyIPC)
                                 v
[20. Windows Credential Provider (PhoneKeyCredentialProvider.dll inside logonui.exe)]
[21. Windows Unlocks Safely & Authentically via LSA KERB_INTERACTIVE_LOGON]
```

---

## 🔒 Security Guarantees & Implementation Status

| Security Guarantee | Technical Implementation & Code Location | Verification Status |
| :--- | :--- | :--- |
| **1. Zero Biometric Exposure** | `BiometricPrompt.CryptoObject` ([BiometricSigner.kt](file:///d:/projects/fingerprintapp/android/app/src/main/java/com/phonekey/crypto/BiometricSigner.kt#L33-L41)) | Implemented as designed (Author self-reviewed) |
| **2. Non-Exportable Private Keys** | Keystore `KeyGenParameterSpec` ([KeyManager.kt](file:///d:/projects/fingerprintapp/android/app/src/main/java/com/phonekey/crypto/KeyManager.kt#L48-L68)) | Implemented as designed (Author self-reviewed) |
| **3. Zero Network Password Transmissions** | Windows DPAPI + Local Named Pipe ([DpapiStorage.cpp](file:///d:/projects/fingerprintapp/windows/agent/DpapiStorage.cpp#L18)) | Implemented as designed (Author self-reviewed) |
| **4. Replay & TTL Defense** | 256-bit CSPRNG nonces + 30s TTL ([ChallengeStore.cpp](file:///d:/projects/fingerprintapp/windows/agent/ChallengeStore.cpp#L64)) | Implemented as designed (Author self-reviewed) |
| **5. Out-of-Process Logon UI Isolation** | COM DLL IPC over Local Pipe ([PhoneKeyCredentialProvider.cpp](file:///d:/projects/fingerprintapp/windows/credential-provider/PhoneKeyCredentialProvider.cpp)) | Implemented as designed (Author self-reviewed) |
| **6. Fail-Closed Guarantee** | `CPGSR_NO_CREDENTIAL_FINISHED` ([PhoneKeyCredential.cpp](file:///d:/projects/fingerprintapp/windows/credential-provider/PhoneKeyCredential.cpp#L80)) | Implemented as designed (Author self-reviewed) |

> [!NOTE]
> Detailed self-assessment breakdown, threat model details, and known architectural limitations are documented in [docs/security_self_assessment.md](docs/security_self_assessment.md) and [docs/known_limitations.md](docs/known_limitations.md).

---

## 🛠️ Automated Test Suite Breakdown

PhoneKey includes automated test suites covering core cryptographic functions, framing, transport, E2E unlock flows, and Phase 2 enhancements:

| Test Runner Executable | Subsystems Tested | Unit Tests | Verification Coverage Bounds |
| :--- | :--- | :--- | :--- |
| **`test_master_runner.exe`** | Crypto, Pairing, Framing, E2E, IPC | 26 Tests | **Covered**: CNG Signature Verification, CSPRNG Nonce TTL, ECDH Key Exchange, HKDF-SHA256, SAS PIN Truncation, Frame CRC32 Checksum, Named Pipe IPC.<br>**Not Covered**: Android UI Compose rendering, physical Bluetooth LE radio hardware, OS-level `logonui.exe` COM loader. |
| **`test_phase2_suite.exe`** | Multi-Device & CTAP2 Bridge | 12 Tests | **Covered**: Multi-device registration/revocation, DPAPI encrypted device registry, CTAP2 37-byte `authenticatorData` formatting.<br>**Not Covered**: Browser WebAuthn API drivers. |

---

## 📄 License & Documentation
- **Security Self-Assessment**: [docs/security_self_assessment.md](docs/security_self_assessment.md)
- **Threat Model**: [docs/threat-model.md](docs/threat-model.md)
- **Known Limitations**: [docs/known_limitations.md](docs/known_limitations.md)
- **Setup Guide**: [docs/user_setup_guide.md](docs/user_setup_guide.md)
- **License**: Apache License 2.0 ([LICENSE](LICENSE))
