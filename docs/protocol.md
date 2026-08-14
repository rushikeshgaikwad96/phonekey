# PhoneKey Cryptographic & Pairing Protocol Specification

## 1. Cryptographic Primitives
- **Asymmetric Signature Keypair**: ECDSA P-256 (secp256r1) with SHA-256 digest, generated in Android Keystore with `setUserAuthenticationRequired(true)`.
- **Ephemeral Key Agreement (Pairing)**: ECDH over Curve256r1.
- **Key Derivation Function**: HKDF-SHA256 (RFC 5869).
- **Symmetric Cipher**: AES-256-GCM (12-byte IV, 16-byte Auth Tag).
- **Entropy Generation**: Windows `BCryptGenRandom` (PC) / `java.security.SecureRandom` (Android).

---

## 2. Pairing Protocol (Phase 1)

```
   Windows PC                                                  Android Device
   ==========                                                  ==============
[Generate Ephemeral ECDH Keypair]
[Generate SessionID, PC_ID]
Display QR Code: 
{session_id, pc_id, pc_ecdh_pub, ip/port}
                                   ---- Scan QR Code ---->   [Generate Android Auth Keypair (Keystore)]
                                                             [Generate Ephemeral ECDH Keypair]
                                                             Compute Shared Secret S = ECDH(Android_Priv, PC_Pub)
                                                             Derive Keys: K_enc, K_sas = HKDF(S, "PhoneKey-Pairing")
                                                             Display 6-Digit SAS Code: Truncate(HMAC-SHA256(K_sas, "SAS"), 6)

                               <-- Pairing Request Packet --
                                   (Android_ID, Android_Auth_Pub, 
                                    Android_ECDH_Pub, EncryptedMetadata)

Compute Shared Secret S = ECDH(PC_Priv, Android_ECDH_Pub)
Derive K_enc, K_sas
Display 6-Digit SAS Code

[User verifies 6-digit SAS matches on BOTH screens and confirms]

                               <-- Confirm Pairing (Encrypted) --
[Save Paired Android_Auth_Pub to DPAPI Store]               [Save Paired PC_ID & PC_Pub to EncryptedPrefs]
```

---

## 3. Unlock Authentication Protocol (Phase 2)

```
   Windows PC                                                  Android Device
   ==========                                                  ==============
[LogonUI Selected / Unlock Triggered]
Generate 256-bit Challenge C
Generate SessionID S_ID, Timestamp T, Expiry T_exp (T + 30s)

                               --- UNLOCK_REQUEST ------------>
                               (ProtocolVersion, S_ID, PC_ID, 
                                Challenge C, T, T_exp)

                                                             [Receive Unlock Request]
                                                             Verify T < CurrentTime < T_exp
                                                             Verify PC_ID matches stored paired PC

                                                             Trigger Android BiometricPrompt ("Unlock Windows")
                                                             [User Scans Fingerprint]
                                                             Hardware TEE unlocks Private Key for signing

                                                             Construct Payload:
                                                             P = ProtocolVersion || DeviceID || S_ID || PC_ID || Challenge C || T_exp
                                                             Signature Sig = Sign_TEE(SHA256(P))

                               <-- UNLOCK_RESPONSE -----------
                               (DeviceID, S_ID, Sig, Metadata)

Verify S_ID matches active challenge
Verify CurrentTime < T_exp
Verify Challenge C has not been used (Replay Check)
Verify Sig using Paired Device Public Key over P

[If Signature Valid]:
  Retrieve Encrypted Local Logon Credential from DPAPI
  Pass KERB_INTERACTIVE_LOGON structure to LSA via Credential Provider
  Windows Unlocks Successfully!
```

---

## 4. Binary Payload Structures

### 4.1 Signature Payload Construction (`P`)
```
Field              Type        Size (Bytes)   Description
--------------------------------------------------------------------------------
ProtocolVersion    uint16      2              Protocol version (e.g. 0x0100 for v1.0)
DeviceID           bytes       16             UUID v4 of Android Device
SessionID          bytes       16             UUID v4 of current unlock session
IntendedPCID       bytes       16             UUID v4 of Windows PC
Challenge          bytes       32             256-bit CSPRNG Challenge
ExpirationTimestamp uint64     8              Unix Epoch Timestamp in Milliseconds
```
Total Signature Payload Length: **90 Bytes**.
