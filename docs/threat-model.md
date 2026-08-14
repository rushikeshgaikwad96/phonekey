# PhoneKey Threat Model & Risk Mitigation Matrix

## 1. Overview
PhoneKey assumes a **hostile network environment**. Wi-Fi networks (including home and corporate Wi-Fi) are assumed to be susceptible to packet sniffing, ARP spoofing, rogue access points, and active Man-in-the-Middle (MITM) attacks.

---

## 2. Threat Analysis Matrix (Milestone 2 Protections)

| Threat | Attack Vector | Severity | Milestone 2 Defense Mechanism | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Biometric Exfiltration** | Attacker attempts to intercept or extract user fingerprint data over network or IPC. | Critical | **Architectural Impossibility**: Biometric image/template never leaves Android TEE/StrongBox. Android `BiometricPrompt` returns only success/fail boolean to app code. | **Protected in M2** |
| **Replay Attack** | Attacker intercepts a valid signed unlock response and retransmits it to unlock the PC later. | High | **Single-use Ephemeral Challenges**: Each unlock request generates a 256-bit CSPRNG challenge with a strictly enforced 30-second TTL. The Windows verifier maintains single-use state (`OUTSTANDING`, `CONSUMED`, `EXPIRED`). | **Protected in M2** |
| **Private Key Exfiltration** | Attacker attempts to read private key from Android storage. | Critical | **Hardware Keystore Isolation**: Key created via `KeyGenParameterSpec` with non-exportable flag in Android TEE/StrongBox. | **Protected in M2** |
| **Unauthorized Signing** | Attacker uses unlocked phone to produce signature without biometric auth. | High | **Per-operation Biometric Gate**: Android private key requires `BIOMETRIC_STRONG` with validity 0s. Every signature requires explicit biometric scan. | **Protected in M2** |
| **Payload Tampering** | Attacker modifies challenge, timestamp, or target PC ID in transit. | High | **Cryptographic Binding**: ECDSA signature covers canonical 108-byte payload prefixed with `PhoneKey-Auth-v1`. Any modification invalidates signature. | **Protected in M2** |
| **Expired Challenge Reuse** | Attacker sends signature after 30-second window. | Medium | **Authoritative Host TTL**: Windows enforces 30s TTL check locally. | **Protected in M2** |
| **Rogue Device Signature** | Unpaired device attempts to send signature. | High | **Dev Device Registry**: Windows verifies signatures using locally registered public keys only. Network-supplied public keys are rejected. | **Protected in M2** |

---

## 3. Out-of-Scope Threat Matrix (Future Milestones)

| Threat | Future Milestone Target | Description & Planned Defense |
| :--- | :--- | :--- |
| **Active Transport MITM** | Milestone 4 | Protected via AES-256-GCM / Noise Protocol transport encryption. |
| **Pairing Interception** | Milestone 3 | Protected via QR scanning, Ephemeral ECDH, and 6-digit SAS PIN matching. |
| **Credential Provider Exploits**| Milestone 6 | Protected via out-of-process Named Pipe IPC isolation and Windows LSA credential security. |

---

## 4. Mandatory Security Rules
1. **Zero Biometric Exposure**: Biometric data never leaves Android device hardware.
2. **Hardware Key Enclosure**: Private keys never leave hardware TEE/StrongBox.
3. **Fail-Closed Security**: Any verification exception, expired challenge, or signature mismatch fails safely.
4. **Windows Authoritative Control**: Windows strictly decides challenge freshness, single-use state, and signature validity.
