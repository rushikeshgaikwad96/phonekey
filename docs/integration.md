# PhoneKey End-to-End Integration Specification (Milestone 5)

## 1. Overview
Milestone 5 combines the cryptographic signing engine (Milestone 2), out-of-band paired device store (Milestone 3), and transport framing layer (Milestone 4) into a cohesive, production-ready local authentication host service.

---

## 2. Windows Agent Host Architecture (`AgentService`)

The **PhoneKey Windows Desktop Agent** is an out-of-process service managing:
1. **Transport Listener**: Listens for incoming socket or Bluetooth connections from paired Android devices (`TcpTransport` / `BluetoothTransport`).
2. **Device Registry**: Looks up registered device public key handles (`DeviceRegistry` & `DpapiStorage`).
3. **Challenge Generator & Store**: Issues 256-bit CSPRNG nonces with 30-second TTL and enforces single-use challenge consumption (`ChallengeGenerator` & `ChallengeStore`).
4. **CNG Crypto Verifier**: Hashes canonical 108-byte binary payloads and verifies ECDSA SHA-256 DER signatures using Windows CNG `BCryptVerifySignature` (`CryptoEngine`).

```
+-------------------------------------------------------------------------------+
|                           PHONEKEY AGENT SERVICE                              |
|                                                                               |
|  +-----------------------+   +-------------------+   +---------------------+  |
|  | TcpTransport Listener |-->| ChallengeGenerator|-->| DeviceRegistry      |  |
|  | (Frame Protocol PKFR) |   | (256-bit Nonces)  |   | (DPAPI Public Keys) |  |
|  +-----------------------+   +-------------------+   +---------------------+  |
|              |                         |                        |             |
|              v                         v                        v             |
|  +-------------------------------------------------------------------------+  |
|  |                     CryptoEngine & ChallengeStore                       |  |
|  |         - Verifies ECDSA P-256 DER Signature via CNG BCrypt            |  |
|  |         - Atomically Consumes Single-Use Nonce (30s TTL Check)          |  |
|  +-------------------------------------------------------------------------+  |
+-------------------------------------------------------------------------------+
```

---

## 3. End-to-End Authentication Sequence

```
Step  Sender      Receiver    Action / Payload
-------------------------------------------------------------------------------------------------------
1.    Agent       Phone       Sends UNLOCK_REQ Frame (0x10) containing SessionID, PC_ID, Challenge C
2.    Phone       -           Validates PC_ID match and timestamp TTL
3.    Phone       User        Triggers AndroidX BiometricPrompt ("Unlock Windows PC")
4.    User        Phone       Scans fingerprint -> Hardware TEE authorizes Keystore signing
5.    Phone       -           Constructs 108-byte canonical payload P and computes DER Signature
6.    Phone       Agent       Sends UNLOCK_RESP Frame (0x11) containing DeviceID, SessionID, Signature
7.    Agent       -           Imports device Public Key, calls BCryptVerifySignature(P, Signature)
8.    Agent       -           Validates Challenge Store state: OUTSTANDING -> CONSUMED
9.    Agent       Phone       Returns SUCCESS status response (0x0000)
```
