#include "PhoneKeyCredential.h"
#include "PhoneKeyCredentialProvider.h"
#include <ntsecapi.h>
#include <iostream>

namespace PhoneKey {

PhoneKeyCredential::PhoneKeyCredential()
    : m_cRef(1), m_pcpce(nullptr) {}

PhoneKeyCredential::~PhoneKeyCredential() {}

IFACEMETHODIMP PhoneKeyCredential::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(PhoneKeyCredential, ICredentialProviderCredential2),
        QITABENT(PhoneKeyCredential, ICredentialProviderCredential),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

IFACEMETHODIMP_(ULONG) PhoneKeyCredential::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

IFACEMETHODIMP_(ULONG) PhoneKeyCredential::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

IFACEMETHODIMP PhoneKeyCredential::Advise(ICredentialProviderCredentialEvents* pcpce) {
    m_pcpce = pcpce;
    if (m_pcpce) m_pcpce->AddRef();
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::UnAdvise() {
    if (m_pcpce) {
        m_pcpce->Release();
        m_pcpce = nullptr;
    }
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::SetSelected(BOOL* pbAutoLogon) {
    if (pbAutoLogon) *pbAutoLogon = FALSE;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::SetDeselected() {
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::GetFieldState(DWORD dwFieldCallout, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) {
    (void)dwFieldCallout;
    if (pcpfs) *pcpfs = CPFS_DISPLAY_IN_BOTH;
    if (pcpfis) *pcpfis = CPFIS_NONE;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::GetStringValue(DWORD dwFieldCallout, LPWSTR* ppsz) {
    (void)dwFieldCallout;
    if (!ppsz) return E_POINTER;
    return SHStrDupW(L"PhoneKey Biometric Unlock", ppsz);
}

IFACEMETHODIMP PhoneKeyCredential::GetBitmapValue(DWORD dwFieldCallout, HBITMAP* phbmp) {
    (void)dwFieldCallout;
    if (phbmp) *phbmp = NULL;
    return E_NOTIMPL;
}

IFACEMETHODIMP PhoneKeyCredential::GetCheckboxValue(DWORD dwFieldCallout, BOOL* pbChecked, LPWSTR* ppszLabel) {
    (void)dwFieldCallout;
    if (pbChecked) *pbChecked = FALSE;
    if (ppszLabel) *ppszLabel = NULL;
    return E_NOTIMPL;
}

IFACEMETHODIMP PhoneKeyCredential::GetSubmitButtonValue(DWORD dwFieldCallout, DWORD* pdwSubmitButtonValue) {
    (void)dwFieldCallout;
    if (pdwSubmitButtonValue) *pdwSubmitButtonValue = 0;
    return E_NOTIMPL;
}

IFACEMETHODIMP PhoneKeyCredential::GetComboBoxValueCount(DWORD dwFieldCallout, DWORD* pcItems, DWORD* pdwDefault) {
    (void)dwFieldCallout;
    if (pcItems) *pcItems = 0;
    if (pdwDefault) *pdwDefault = 0;
    return E_NOTIMPL;
}

IFACEMETHODIMP PhoneKeyCredential::GetComboBoxValueAt(DWORD dwFieldCallout, DWORD dwItem, LPWSTR* ppszItem) {
    (void)dwFieldCallout;
    (void)dwItem;
    if (ppszItem) *ppszItem = NULL;
    return E_NOTIMPL;
}

IFACEMETHODIMP PhoneKeyCredential::SetStringValue(DWORD dwFieldCallout, LPCWSTR psz) {
    (void)dwFieldCallout;
    (void)psz;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::SetCheckboxValue(DWORD dwFieldCallout, BOOL bChecked) {
    (void)dwFieldCallout;
    (void)bChecked;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::SetComboBoxSelectedValue(DWORD dwFieldCallout, DWORD dwItem) {
    (void)dwFieldCallout;
    (void)dwItem;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::CommandLinkClicked(DWORD dwFieldCallout) {
    (void)dwFieldCallout;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::GetUserSid(LPWSTR* ppszSid) {
    if (!ppszSid) return E_POINTER;
    *ppszSid = NULL;
    return E_NOTIMPL;
}

IFACEMETHODIMP PhoneKeyCredential::GetSerialization(
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs,
    LPWSTR* ppszOptionalStatusText,
    CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiStatusIcon
) {
    if (!pcpgsr || !pcpcs) return E_POINTER;

    // Connect to PhoneKey Agent via local Named Pipe IPC
    IpcPacket req;
    req.type = IpcMessageType::REQ_UNLOCK;
    req.statusCode = 0;

    IpcPacket resp;
    bool ipcOk = NamedPipeClient::SendIpcRequest(req, resp, 5000);

    if (!ipcOk || resp.statusCode != 0x0000 || resp.payload.empty()) {
        *pcpgsr = CPGSR_NO_CREDENTIAL_FINISHED;
        if (ppszOptionalStatusText) {
            SHStrDupW(L"PhoneKey Biometric Authentication Failed or Timed Out", ppszOptionalStatusText);
        }
        if (pcpsiStatusIcon) *pcpsiStatusIcon = CPSI_ERROR;
        return S_OK;
    }

    // Success: Package LSA KERB_INTERACTIVE_LOGON buffer returned from Agent via IPC
    BYTE* pBuffer = static_cast<BYTE*>(CoTaskMemAlloc(resp.payload.size()));
    if (!pBuffer) return E_OUTOFMEMORY;

    std::memcpy(pBuffer, resp.payload.data(), resp.payload.size());

    pcpcs->clsidCredentialProvider = CLSID_PhoneKeyCredentialProvider;
    pcpcs->cbSerialization = static_cast<ULONG>(resp.payload.size());
    pcpcs->rgbSerialization = pBuffer;

    *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
    if (ppszOptionalStatusText) {
        SHStrDupW(L"PhoneKey Biometric Unlock Authorized", ppszOptionalStatusText);
    }
    if (pcpsiStatusIcon) *pcpsiStatusIcon = CPSI_SUCCESS;

    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredential::ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiStatusIcon) {
    (void)ntsStatus;
    (void)ntsSubstatus;
    if (ppszOptionalStatusText) *ppszOptionalStatusText = NULL;
    if (pcpsiStatusIcon) *pcpsiStatusIcon = CPSI_SUCCESS;
    return S_OK;
}

} // namespace PhoneKey
