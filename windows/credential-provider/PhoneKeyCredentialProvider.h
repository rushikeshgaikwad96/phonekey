#ifndef PHONEKEY_CREDENTIAL_PROVIDER_H
#define PHONEKEY_CREDENTIAL_PROVIDER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <credentialprovider.h>
#include <shlwapi.h>
#include <unknwn.h>
#include <string>

#pragma comment(lib, "shlwapi.lib")

namespace PhoneKey {

// CLSID: {8B67D3A1-7E9B-4D1C-9E3A-2B5C1D0E4F8A}
static const GUID CLSID_PhoneKeyCredentialProvider = 
{ 0x8b67d3a1, 0x7e9b, 0x4d1c, { 0x9e, 0x3a, 0x2b, 0x5c, 0x1d, 0x0e, 0x4f, 0x8a } };

class PhoneKeyCredentialProvider : public ICredentialProvider {
public:
    PhoneKeyCredentialProvider();
    virtual ~PhoneKeyCredentialProvider();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProvider
    IFACEMETHODIMP SetUsageScenario(CREDENTIAL_PROVIDER_USAGE_SCENARIO cpus, DWORD dwFlags) override;
    IFACEMETHODIMP SetSerialization(const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs) override;
    IFACEMETHODIMP Advise(ICredentialProviderEvents* pcpe, UINT_PTR upRef) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP GetFieldDescriptorCount(DWORD* pdwCount) override;
    IFACEMETHODIMP GetFieldDescriptorAt(DWORD dwIndex, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR** ppcpfd) override;
    IFACEMETHODIMP GetCredentialCount(DWORD* pdwCount, DWORD* pdwDefault, BOOL* pbAutoLogonWithDefault) override;
    IFACEMETHODIMP GetCredentialAt(DWORD dwIndex, ICredentialProviderCredential** ppcpc) override;

private:
    LONG m_cRef;
    CREDENTIAL_PROVIDER_USAGE_SCENARIO m_cpus;
    ICredentialProviderEvents* m_pcpe;
    UINT_PTR m_upRef;
};

} // namespace PhoneKey

#endif // PHONEKEY_CREDENTIAL_PROVIDER_H
