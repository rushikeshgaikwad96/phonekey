#include <windows.h>
#include <unknwn.h>
#include "PhoneKeyCredentialProvider.h"

HINSTANCE g_hInst = NULL;
static LONG g_cRefModule = 0;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    (void)lpReserved;
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            g_hInst = hModule;
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}

STDAPI DllCanUnloadNow(void) {
    return (g_cRefModule == 0) ? S_OK : S_FALSE;
}

class PhoneKeyClassFactory : public IClassFactory {
public:
    PhoneKeyClassFactory() : m_cRef(1) {}
    virtual ~PhoneKeyClassFactory() {}

    IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv) override {
        static const QITAB qit[] = {
            QITABENT(PhoneKeyClassFactory, IClassFactory),
            { 0 },
        };
        return QISearch(this, qit, riid, ppv);
    }

    IFACEMETHODIMP_(ULONG) AddRef() override {
        return InterlockedIncrement(&m_cRef);
    }

    IFACEMETHODIMP_(ULONG) Release() override {
        LONG cRef = InterlockedDecrement(&m_cRef);
        if (cRef == 0) {
            delete this;
        }
        return cRef;
    }

    IFACEMETHODIMP CreateInstance(IUnknown* pUnkOuter, REFIID riid, void** ppv) override {
        if (pUnkOuter != NULL) return CLASS_E_NOAGGREGATION;
        PhoneKey::PhoneKeyCredentialProvider* pProvider = new (std::nothrow) PhoneKey::PhoneKeyCredentialProvider();
        if (!pProvider) return E_OUTOFMEMORY;
        HRESULT hr = pProvider->QueryInterface(riid, ppv);
        pProvider->Release();
        return hr;
    }

    IFACEMETHODIMP LockServer(BOOL fLock) override {
        if (fLock) {
            InterlockedIncrement(&g_cRefModule);
        } else {
            InterlockedDecrement(&g_cRefModule);
        }
        return S_OK;
    }

private:
    LONG m_cRef;
};

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, void** ppv) {
    if (rclsid == PhoneKey::CLSID_PhoneKeyCredentialProvider) {
        PhoneKeyClassFactory* pFactory = new (std::nothrow) PhoneKeyClassFactory();
        if (!pFactory) return E_OUTOFMEMORY;
        HRESULT hr = pFactory->QueryInterface(riid, ppv);
        pFactory->Release();
        return hr;
    }
    return CLASS_E_CLASSNOTAVAILABLE;
}

STDAPI DllRegisterServer(void) {
    // Registers PhoneKey Credential Provider in HKLM
    HKEY hKey = NULL;
    const wchar_t* subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{8B67D3A1-7E9B-4D1C-9E3A-2B5C1D0E4F8A}";
    LONG lRes = RegCreateKeyExW(HKEY_LOCAL_MACHINE, subkey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);
    if (lRes == ERROR_SUCCESS) {
        const wchar_t* val = L"PhoneKeyCredentialProvider";
        RegSetValueExW(hKey, NULL, 0, REG_SZ, reinterpret_cast<const BYTE*>(val), static_cast<DWORD>((wcslen(val) + 1) * sizeof(wchar_t)));
        RegCloseKey(hKey);
        return S_OK;
    }
    return E_FAIL;
}

STDAPI DllUnregisterServer(void) {
    const wchar_t* subkey = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{8B67D3A1-7E9B-4D1C-9E3A-2B5C1D0E4F8A}";
    RegDeleteKeyW(HKEY_LOCAL_MACHINE, subkey);
    return S_OK;
}
