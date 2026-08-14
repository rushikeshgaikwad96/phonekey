# PhoneKey Threat Model & Risk Mitigation Matrix

## 1. Overview
PhoneKey assumes a **hostile local network environment**. Wi-Fi networks (home, public, and corporate) are assumed to be susceptible to packet sniffing, ARP spoofing, rogue access points, and active network tampering.

---

## 2. Threat Analysis & Defense Matrix

| Threat Category | Specific Threat | Severity | Defense Mechanism & Implementation | Reality & Status |
| :--- | :--- | :--- | :--- | :--- |
| **Data Corruption** | Accidental Network Packet Corruption | Low | **IEEE 802.3 CRC32 Checksum**: `FrameProtocol::CalculateCrc32` verifies frame integrity before parsing payload bytes. | **Mitigates accidental noise/corruption only.** *Not a security control.* |
| **Network Forgery** | Active Packet Tampering / Signature Forgery | Critical | **ECDSA P-256 Signature Verification**: CNG `BCryptVerifySignature` checks 64-byte signature over canonical 108B payload $P$. Network attacker cannot forge valid signatures without private key. | **Implemented as designed.** Cryptographic tamper resistance. |
| **Replay Attacks** | Intercepted Response Retransmission | High | **CSPRNG Nonces & 30s Host TTL**: 256-bit nonces generated via CNG `BCryptGenRandom`. Host `ChallengeStore` enforces 30s TTL and single-use state transition (`OUTSTANDING` $\rightarrow$ `CONSUMED`). | **Implemented as designed.** Prevents challenge reuse. |
| **Key Exfiltration** | Android Private Key Extraction | Critical | **Hardware Keystore Isolation**: Key generated in Android TEE/StrongBox with `setUserAuthenticationRequired(true)` and `setInvalidatedByBiometricEnrollment(true)`. Private key is non-exportable. | **Implemented as designed.** Hardware isolated. |
| **Biometric Theft** | Raw Biometric Data Interception | Critical | **Architectural Isolation**: Biometric images/templates stay in Android TEE. `BiometricPrompt.CryptoObject` returns only a signature token. | **Implemented as designed.** Zero biometric exposure. |
| **Password Theft** | Windows Logon Credential Interception | Critical | **DPAPI Encryption & Local Pipe IPC**: Plaintext credentials stored locally via Windows DPAPI (`CryptProtectData`) and sent strictly via local Named Pipe (`\\.\pipe\PhoneKeyIPC`). | **Implemented as designed.** Zero network password transmission. |

---

## 3. Additional Threat Scenarios & Mitigations

### Scenario A: Unlocked Phone Stolen Mid-Session
- **Risk**: An attacker steals an unlocked Android phone while the owner is nearby.
- **Mitigation**: `BiometricSigner.kt` enforces `setUserAuthenticationParameters(0, AUTH_BIOMETRIC_STRONG)`. Every single unlock signature requires a fresh biometric scan (fingerprint/face) at the exact moment of signing. Being unlocked on home screen does **not** grant authorization to sign.

### Scenario B: Lost or Stolen Paired Smartphone
- **Risk**: A paired smartphone is lost or stolen permanently.
- **Mitigation**: Windows `MultiDeviceManager` provides device revocation (`RevokeDevice(deviceId)`). Revoking a device removes its public key from DPAPI storage, immediately invalidating all future authentication attempts from that smartphone.

### Scenario C: Rate Limiting & Lockout Behavior
- **Risk**: Automated network attacker attempts brute-force signature or challenge guesses over port 8443.
- **Mitigation**: `ChallengeStore` limits active challenges and enforces 30-second TTL expiration. Invalid signature responses trigger error code `0x0002`. Standard Windows account lockout policies apply at the OS level on repeated failed logon attempts.

### Scenario D: Multi-Device Compromise Isolation
- **Risk**: User has paired two smartphones (Primary & Backup), and one phone is compromised.
- **Mitigation**: Each paired smartphone generates an independent ECDSA P-256 keypair. Revoking or compromising Device A has zero cryptographic impact on Device B.

---

## 4. Network Exposure & Firewall Guidance
- **TcpTransport Bind Scope**: Listens on `0.0.0.0` (all interfaces) port 8443.
- **Recommendation**: Restrict incoming traffic on port 8443 via Windows Defender Firewall to trusted local IP subnets (`192.168.x.x` / `10.x.x.x`), or use Bluetooth LE.
