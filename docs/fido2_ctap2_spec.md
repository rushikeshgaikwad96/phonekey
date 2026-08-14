# PhoneKey FIDO2 / CTAP2 Protocol Bridge Specification (Phase 2)

## 1. Overview
PhoneKey Phase 2 introduces an abstract **CTAP2 (Client-to-Authenticator Protocol 2)** bridge. This enables PhoneKey to act as a software WebAuthn security key, translating Android biometric hardware signatures into standard FIDO2 authentication assertions for web browsers and system logins.

---

## 2. CTAP2 Command Architecture

```
   Web Browser / Windows WebAuthn API                   PhoneKey CTAP2 Bridge                  Android Phone
   =================================                   =====================                  =============
[1. WebAuthn GetAssertion Request]
  - Relying Party ID (rpId)
  - ClientDataHash (32 Bytes)
  - AllowList (Credential IDs)  ---> [2. Translate to AuthPayload P]
                                     - deviceId, sessionId, pcId
                                     - challenge = ClientDataHash
                                     - Transmit UNLOCK_REQ via Socket ---> [3. Trigger BiometricPrompt]
                                                                           [4. Compute ECDSA Signature]
                                 <--- [5. Return UNLOCK_RESP Signature] <--- [5. Send UNLOCK_RESP Frame]
[6. Package CTAP2 GetAssertion Response]
  - AuthenticatorData (rpidHash, flags, counter)
  - Signature (DER ECDSA P-256)
  - UserHandle
```

---

## 3. Data Formats
- **rpIdHash**: SHA-256 hash of Relying Party ID (e.g. `sha256("accounts.google.com")`).
- **Flags**: `0x01` (User Present - UP) | `0x04` (User Verified - UV).
- **Signature**: Standard DER-encoded ECDSA P-256 signature produced by Android Keystore.
