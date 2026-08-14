# PhoneKey Out-of-Band Pairing Protocol Specification (Milestone 3)

## 1. Overview
Pairing establishes mutual cryptographic trust between an Android phone and a Windows PC without relying on a trusted central authority or local network security.

Pairing is **out-of-band** and requires visual inspection of a 6-digit Short Authentication String (SAS) PIN on both screens by the user before public keys are saved to persistent storage.

---

## 2. QR Code Payload Schema
The Windows PC generates a QR code containing a JSON payload formatted as follows:

```json
{
  "protocol_version": "0100",
  "session_id": "aaaaaaaa000011112222bbbbbbbbbbbb",
  "pc_id": "99999999888877776666555555555555",
  "pc_ecdh_pub_hex": "04...",
  "host_info": "DESKTOP-WIN11 (192.168.1.50:8443)"
}
```

### Fields
- `protocol_version`: Must be `"0100"` (v1.0).
- `session_id`: 32-character hex (16 bytes) UUID of the pairing session.
- `pc_id`: 32-character hex (16 bytes) UUID of the Windows host.
- `pc_ecdh_pub_hex`: 130-character hex (65 bytes: `04` || X || Y) uncompressed Ephemeral ECDH P-256 Public Key.
- `host_info`: Human-readable device name and connection endpoint.

---

## 3. Cryptographic Derivation Formulas

### 3.1 Ephemeral ECDH Shared Secret
Both devices perform ECDH over NIST P-256 (secp256r1):
$$S = \text{ECDH}(\text{Local\_Ephemeral\_Private\_Key}, \text{Remote\_Ephemeral\_Public\_Key})$$
where $S$ is a 32-byte raw shared secret.

### 3.2 Key Derivation Function (HKDF-SHA256)
Using RFC 5869 HKDF-SHA256 with $\text{Salt} = \text{SessionID}$ (16 bytes) and $\text{IKM} = S$ (32 bytes):

$$\text{PRK} = \text{HKDF-Extract}(\text{Salt}, S)$$
$$K_{enc} = \text{HKDF-Expand}(\text{PRK}, \text{"PhoneKey-Pairing-Enc"}, 32)$$
$$K_{sas} = \text{HKDF-Expand}(\text{PRK}, \text{"PhoneKey-Pairing-SAS"}, 32)$$

### 3.3 Short Authentication String (SAS) 6-Digit PIN
$$\text{Mac} = \text{HMAC-SHA256}(K_{sas}, \text{"PhoneKey-SAS-PIN"})$$
$$\text{Value} = (\text{Mac}[0] \ll 24) \mid (\text{Mac}[1] \ll 16) \mid (\text{Mac}[2] \ll 8) \mid \text{Mac}[3]$$
$$\text{SAS\_PIN} = (\text{Value} \bmod 900000) + 100000$$

The output $\text{SAS\_PIN}$ is a 6-digit decimal integer in the range `100000` to `999999`.

---

## 4. Persistent Key Storage Security
- **Windows Host**: Stores paired phone public key and metadata in `%ProgramData%\PhoneKey\paired_devices.bin` encrypted using Windows DPAPI (`CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE`).
- **Android Device**: Stores paired PC ID and public key in `EncryptedSharedPreferences` backed by Android Keystore master key (`MasterKeys.AES256_GCM`).
