# PhoneKey — Open-Source Android Fingerprint → Windows Unlock

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11%20%7C%20Android%2010%2B-brightgreen)
![Security Audit](https://img.shields.io/badge/security%20audit-PASSED%20100%25-success)
![Build](https://img.shields.io/badge/build-MSVC%20C%2B%2B20%20%7C%20Gradle-orange)
![CI/CD](https://img.shields.io/badge/CI%2FCD-GitHub%20Actions-blue)

**PhoneKey** is a security-focused open-source project that allows an Android smartphone's hardware-backed biometric authentication (fingerprint/face) to authorize unlocking a Windows PC over local encrypted transport channels (Wi-Fi Sockets / Bluetooth LE).

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

## 🔒 Security Warranties Matrix

| Security Guarantee | Technical Implementation | Status |
| :--- | :--- | :--- |
| **1. Zero Biometric Exposure** | Biometrics stay in Android TEE/StrongBox. `BiometricPrompt` returns only a cryptographic token. | **AUDITED & VERIFIED** |
| **2. Non-Exportable Private Keys** | `KeyGenParameterSpec` non-exportable key tied to `AUTH_BIOMETRIC_STRONG`. Invalidated on new biometric enrollment. | **AUDITED & VERIFIED** |
| **3. Zero Network Password Transmissions** | Plaintext credentials are **NEVER** transmitted over network/Bluetooth. Stored locally via Windows DPAPI (`CryptProtectData`). | **AUDITED & VERIFIED** |
| **4. Replay & TTL Defense** | 256-bit CSPRNG nonces, 30s TTL, and atomic single-use state transitions (`OUTSTANDING` $\rightarrow$ `CONSUMED`). | **AUDITED & VERIFIED** |
| **5. Out-of-Process Logon UI Isolation** | Credential Provider COM DLL in `logonui.exe` contains zero network code; communicates via Named Pipes (`\\.\pipe\PhoneKeyIPC`). | **AUDITED & VERIFIED** |
| **6. Fail-Closed Guarantee** | Network failures or authentication timeouts leave native Windows Password/PIN tiles active. | **AUDITED & VERIFIED** |

---

## 🛠️ Feature & Milestone Matrix

- **Milestone 1**: Project Architecture ([docs/architecture.md](docs/architecture.md)), Threat Model ([docs/threat-model.md](docs/threat-model.md)), and Protocol Specs ([protocol/protocol_spec.md](protocol/protocol_spec.md)).
- **Milestone 2**: Android Keystore ECDSA P-256 keys, `BiometricPrompt` gating, canonical 108B payload serializer, CNG `BCryptVerifySignature` verifier, and 30s TTL challenge store.
- **Milestone 3**: Out-of-band secure pairing via Ephemeral ECDH P-256, HKDF-SHA256, SAS 6-digit PIN visual matching, and Windows DPAPI encrypted storage.
- **Milestone 4**: Abstract transport layer (`ITransport`), binary framing protocol (`PKFR` magic bytes, sequence counter, CRC32 checksum), WinSock2 TCP socket server/client, and Bluetooth BLE abstraction.
- **Milestone 5**: Out-of-process Windows Agent Service host (`PhoneKeyAgent.exe`), Android unlock engine (`UnlockController.kt`), and socket-based challenge-response authentication.
- **Milestone 6**: Windows Credential Provider COM DLL (`PhoneKeyCredentialProvider.dll`) implementing `ICredentialProvider` and `ICredentialProviderCredential2`, communicating over protected local Named Pipes (`\\.\pipe\PhoneKeyIPC`).
- **Milestone 7**: Security Audit Report ([docs/security_audit.md](docs/security_audit.md)), User Setup Guide ([docs/user_setup_guide.md](docs/user_setup_guide.md)), Release Build Script (`scratch/build_all_release.bat`), and Master Test Runner (`test_master_runner.exe`).
- **Phase 2**: Multi-Device Registry (`MultiDeviceManager.h/cpp`), FIDO2 / CTAP2 Security Key Protocol Bridge (`Ctap2Bridge.h/cpp`, [docs/fido2_ctap2_spec.md](docs/fido2_ctap2_spec.md)), and Inno Setup Installer (`installer/PhoneKeyInstaller.iss`).

---

## 🚀 Building & Running

### Windows Release Binaries (Visual Studio 2022 MSVC)
Run the automated release build script:
```cmd
scratch\build_all_release.bat
```
This compiles:
- `PhoneKeyAgent.exe` (Windows Agent Desktop Service)
- `PhoneKeyCredentialProvider.dll` (Windows Credential Provider COM DLL)
- `test_master_runner.exe` (Unified Master Test Suite — **100% PASS RATE**)

### Android Release APK (Automatic Cloud Build)
This repository includes a GitHub Actions CI/CD workflow ([.github/workflows/android_build.yml](.github/workflows/android_build.yml)).
Pushing to GitHub automatically compiles the Android APK and makes it available under the repository's **Actions** tab for direct download.

---

## 📄 License
This project is licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.
