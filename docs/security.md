# PhoneKey Security Guidelines — Milestone 2

## Core Security Properties Demonstrated in Milestone 2

### 1. Biometric Never Leaves Android
Android code handles `BiometricPrompt` strictly to authorize cryptographic key use. No biometric raw data, templates, or images are acquired, stored, or transmitted over network or IPC.

### 2. Private Key Never Leaves Keystore
The Android private key is generated with `KeyGenParameterSpec` marked non-exportable and hardware-backed (TEE/StrongBox). The application layer can only obtain public keys and sign payloads authorized by `BiometricPrompt`.

### 3. Per-Operation Biometric Authorization
Every signing operation requires fresh `BIOMETRIC_STRONG` authentication (validity duration 0s). An unlocked phone state without biometric authorization will fail to produce a signature.

### 4. Hardware Key Invalidation
Keys created with `setInvalidatedByBiometricEnrollment(true)` automatically invalidate if new biometric enrollments (fingerprints) occur on the device.

### 5. Windows Authoritative Challenge Verification
Windows generates 256-bit CSPRNG challenges (`BCryptGenRandom`) and maintains authoritative local state. Challenges have a strict 30-second TTL and can be consumed only once (atomic state transition from `OUTSTANDING` -> `CONSUMED`).

### 6. Domain-Separated Deterministic Binary Payload
Payload signed by Android is prefixed with ASCII string `PhoneKey-Auth-v1` and encoded deterministically (108 bytes).

### 7. Non-Trusted Network Public Keys
Windows verifies signatures against locally registered development device keys only. Public keys transmitted over network connections during authentication attempts are explicitly ignored.
