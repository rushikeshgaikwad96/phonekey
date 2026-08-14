#include "PhoneKeyCredentialProvider.h"
#include "PhoneKeyCredential.h"

namespace PhoneKey {

PhoneKeyCredentialProvider::PhoneKeyCredentialProvider()
    : m_cRef(1), m_cpus(CPUS_LOGON), m_pcpe(nullptr), m_upRef(0) {}

PhoneKeyCredentialProvider::~PhoneKeyCredentialProvider() {}

IFACEMETHODIMP PhoneKeyCredentialProvider::QueryInterface(REFIID riid, void** ppv) {
    static const QITAB qit[] = {
        QITABENT(PhoneKeyCredentialProvider, ICredentialProvider),
        { 0 },
    };
    return QISearch(this, qit, riid, ppv);
}

IFACEMETHODIMP_(ULONG) PhoneKeyCredentialProvider::AddRef() {
    return InterlockedIncrement(&m_cRef);
}

IFACEMETHODIMP_(ULONG) PhoneKeyCredentialProvider::Release() {
    LONG cRef = InterlockedDecrement(&m_cRef);
    if (cRef == 0) {
        delete this;
    }
    return cRef;
}

IFACEMETHODIMP PhoneKeyCredentialProvider::SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) {
    (void)dwFlags;
    m_cpus = cpus;
    switch (cpus) {
        case CPUS_LOGON:
        case CPUS_UNLOCK_WORKSTATION:
            return S_OK;
        default:
            return E_NOTIMPL;
    }
}

IFACEMETHODIMP PhoneKeyCredentialProvider::SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) {
    (void)pcpcs;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredentialProvider::Advise(ICredentialProviderEvents* pcpe, UINT_PTR upRef) {
    m_pcpe = pcpe;
    m_upRef = upRef;
    if (m_pcpe) m_pcpe->AddRef();
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredentialProvider::UnAdvise() {
    if (m_pcpe) {
        m_pcpe->Release();
        m_pcpe = nullptr;
    }
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredentialProvider::GetFieldDescriptorCount(DWORD* pdwCount) {
    if (!pdwCount) return E_POINTER;
    *pdwCount = 1;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredentialProvider::GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) {
    if (dwIndex != 0 || !ppcpfd) return E_INVALIDARG;
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR* pcpfd = static_cast<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR*>(CoTaskMemAlloc(sizeof(CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR)));
    if (!pcpfd) return E_OUTOFMEMORY;

    pcpfd->dwFieldID = 0;
    pcpfd->cpft = CPFT_LARGE_TEXT;
    SHStrDupW(L"PhoneKey Biometric Unlock", &pcpfd->pszLabel);
    pcpfd->guidFieldType = GUID_NULL;

    *ppcpfd = pcpfd;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredentialProvider::GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) {
    if (!pdwCount || !pdwDefault || !pbAutoLogonWithDefault) return E_POINTER;
    *pdwCount = 1;
    *pdwDefault = 0;
    *pbAutoLogonWithDefault = FALSE;
    return S_OK;
}

IFACEMETHODIMP PhoneKeyCredentialProvider::GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) {
    if (dwIndex != 0 || !ppcpc) return E_INVALIDARG;
    PhoneKeyCredential* pCred = new (std::nothrow) PhoneKeyCredential();
    if (!pCred) return E_OUTOFMEMORY;

    HRESULT hr = pCred->QueryInterface(IID_PPV_ARGS(ppcpc));
    pCred->Release();
    return hr;
}

} // namespace PhoneKey
