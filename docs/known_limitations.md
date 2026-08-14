# PhoneKey Known Limitations & Security Trade-offs

This document explicitly outlines known architectural limitations, assumptions, and security trade-offs in the current PhoneKey implementation.

---

## 1. Out-of-Band (OOB) Pairing & User SAS Verification
- **Mechanism**: Ephemeral ECDH P-256 key exchange combined with HKDF-SHA256 derives a 6-digit Short Authentication String (SAS) PIN.
- **Limitation**: The system relies on the user to visually inspect and confirm that the 6-digit PIN matches on both the PC screen and phone screen before confirming pairing.
- **Security Impact**: If a user approves pairing without visually checking the 6-digit SAS PIN, an active network attacker could execute a Man-in-the-Middle (MITM) key substitution attack during the initial pairing phase.

---

## 2. ChallengeStore Concurrency & Atomic State Transitions
- **Mechanism**: `ChallengeStore::ValidateChallenge` verifies challenge parameters, and `ChallengeStore::ConsumeChallenge` marks the state `CONSUMED`.
- **Limitation**: In earlier iterations, calling `ValidateChallenge` followed by `ConsumeChallenge` in two separate mutex lock acquisitions left a microsecond window between validation and consumption.
- **Security Impact**: If two concurrent threads execute verification on the exact same challenge simultaneously, both might pass `ValidateChallenge` before the first completes `ConsumeChallenge`.
- **Remediation**: `ChallengeStore` has been updated with `ValidateAndConsumeChallenge` which executes validation, expiration check, and state transition to `CONSUMED` under a single atomic lock acquisition.

---

## 3. TCP Listener Bind Scope (`0.0.0.0`)
- **Mechanism**: `TcpTransport::StartListener` binds socket `sin_addr.s_addr = INADDR_ANY` (`0.0.0.0`) to accept connections over Wi-Fi.
- **Limitation**: Binds to all network interfaces on the Windows PC.
- **Security Impact**: Any device on the same local network subnet can send authentication requests or attempt frame fuzzing against the listener port (default 8443).
- **Recommendation**: Users should configure Windows Defender Firewall to restrict port 8443 incoming traffic strictly to local subnet IP ranges, or connect via Bluetooth LE.

---

## 4. Single-Connection Listener State
- **Mechanism**: `TcpTransport` accepts one incoming client connection at a time.
- **Limitation**: If an untrusted network client connects to port 8443 and keeps the socket open without sending data, legitimate unlock connections will be blocked until the connection drops or times out.
- **Security Impact**: Potential Denial of Service (DoS) against the unlock listener interface.

---

## 5. Hardware Keystore & Biometric Fallback Scope
- **Mechanism**: `KeyManager.kt` requests `AUTH_BIOMETRIC_STRONG`.
- **Limitation**: On Android devices lacking dedicated TEE/StrongBox hardware (e.g. legacy or low-cost budget phones), key generation falls back to software-emulated keystore backed by Android system key.
- **Verification**: App UI displays whether the generated key is `StrongBox-backed` or `Software/TEE-backed`.
