#ifndef PHONEKEY_CREDENTIAL_H
#define PHONEKEY_CREDENTIAL_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <credentialprovider.h>
#include <shlwapi.h>
#include <unknwn.h>
#include <string>
#include "../common/NamedPipeIpc.h"

#pragma comment(lib, "shlwapi.lib")

namespace PhoneKey {

class PhoneKeyCredential : public ICredentialProviderCredential2 {
public:
    PhoneKeyCredential();
    virtual ~PhoneKeyCredential();

    // IUnknown
    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override;
    IFACEMETHODIMP_(ULONG) AddRef() override;
    IFACEMETHODIMP_(ULONG) Release() override;

    // ICredentialProviderCredential
    IFACEMETHODIMP Advise(ICredentialProviderCredentialEvents* pcpce) override;
    IFACEMETHODIMP UnAdvise() override;
    IFACEMETHODIMP SetSelected(BOOL* pbAutoLogon) override;
    IFACEMETHODIMP SetDeselected() override;
    IFACEMETHODIMP GetFieldState(DWORD dwFieldCallout, CREDENTIAL_PROVIDER_FIELD_STATE* pcpfs, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE* pcpfis) override;
    IFACEMETHODIMP GetStringValue(DWORD dwFieldCallout, LPWSTR* ppsz) override;
    IFACEMETHODIMP GetBitmapValue(DWORD dwFieldCallout, HBITMAP* phbmp) override;
    IFACEMETHODIMP GetCheckboxValue(DWORD dwFieldCallout, BOOL* pbChecked, LPWSTR* ppszLabel) override;
    IFACEMETHODIMP GetSubmitButtonValue(DWORD dwFieldCallout, DWORD* pdwSubmitButtonValue) override;
    IFACEMETHODIMP GetComboBoxValueCount(DWORD dwFieldCallout, DWORD* pcItems, DWORD* pdwDefault) override;
    IFACEMETHODIMP GetComboBoxValueAt(DWORD dwFieldCallout, DWORD dwItem, LPWSTR* ppszItem) override;
    IFACEMETHODIMP SetStringValue(DWORD dwFieldCallout, LPCWSTR psz) override;
    IFACEMETHODIMP SetCheckboxValue(DWORD dwFieldCallout, BOOL bChecked) override;
    IFACEMETHODIMP SetComboBoxSelectedValue(DWORD dwFieldCallout, DWORD dwItem) override;
    IFACEMETHODIMP CommandLinkClicked(DWORD dwFieldCallout) override;
    IFACEMETHODIMP GetSerialization(CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE* pcpgsr, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION* pcpcs, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiStatusIcon) override;
    IFACEMETHODIMP ReportResult(NTSTATUS ntsStatus, NTSTATUS ntsSubstatus, LPWSTR* ppszOptionalStatusText, CREDENTIAL_PROVIDER_STATUS_ICON* pcpsiStatusIcon) override;

    // ICredentialProviderCredential2
    IFACEMETHODIMP GetUserSid(LPWSTR* ppszSid) override;

private:
    LONG m_cRef;
    ICredentialProviderCredentialEvents* m_pcpce;
    std::wstring m_username;
    std::wstring m_domain;
};

} // namespace PhoneKey

#endif // PHONEKEY_CREDENTIAL_H
