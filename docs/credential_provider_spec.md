# PhoneKey Windows Credential Provider Specification (Milestone 6)

## 1. Overview
The **PhoneKey Credential Provider** (`PhoneKeyCredentialProvider.dll`) is a native C++ COM DLL implementing `ICredentialProvider` and `ICredentialProviderCredential2`.

It registers with the Windows Authentication system and renders a "PhoneKey Biometric Unlock" tile on the Windows Lock and Logon UI screens (`logonui.exe`).

---

## 2. COM Registration Metadata
- **Provider CLSID**: `{8B67D3A1-7E9B-4D1C-9E3A-2B5C1D0E4F8A}`
- **Credential CLSID**: `{9C78E4B2-8FA0-5E2D-0F4B-3C6D2E1F5A9B}`
- **Registry Registration Key**:  
  `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{8B67D3A1-7E9B-4D1C-9E3A-2B5C1D0E4F8A}`
- **DLL Path**: `%ProgramFiles%\PhoneKey\PhoneKeyCredentialProvider.dll`
- **Threading Model**: `Apartment`

---

## 3. Out-of-Process Named Pipe IPC Protocol

To maintain security isolation, no network or socket code runs inside `logonui.exe`. The Credential Provider acts as a client connecting over local Windows Named Pipes to the PhoneKey Desktop Agent:

- **Named Pipe Endpoint**: `\\.\pipe\PhoneKeyIPC`
- **IPC Message Types**:
  - `0x0001` `IPC_REQ_STATUS`: Credential Provider queries Agent for connected phone status.
  - `0x0002` `IPC_REQ_UNLOCK`: Credential Provider requests unlock authorization for selected Windows user.
  - `0x0003` `IPC_RESP_UNLOCK`: Agent returns authentication result and encrypted DPAPI logon payload.

---

## 4. Windows LSA Authentication Buffer Packaging (`KERB_INTERACTIVE_LOGON`)

Upon successful biometric authorization and ECDSA signature verification by the Desktop Agent, the local logon credential buffer is constructed for the Windows Local Security Authority (LSA):

```cpp
typedef struct _KERB_INTERACTIVE_LOGON {
    KERB_LOGON_SUBMIT_TYPE MessageType; // KerbInteractiveLogon
    UNICODE_STRING LogonDomainName;
    UNICODE_STRING UserName;
    UNICODE_STRING Password;
} KERB_INTERACTIVE_LOGON, *PKERB_INTERACTIVE_LOGON;
```

### Security Rules
1. Password bytes inside `UNICODE_STRING` are stored locally using Windows DPAPI (`CryptProtectData`) and decrypted in-memory only at the instant of LSA handoff (`GetSerialization`).
2. Plaintext passwords are **NEVER** transmitted over network, Wi-Fi, BLE, or socket channels.
