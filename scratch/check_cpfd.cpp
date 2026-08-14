#include <windows.h>
#include <credentialprovider.h>
#include <iostream>

int main() {
    CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR c = { 0, CPFT_LARGE_TEXT, NULL, GUID_NULL };
    std::cout << "Size of CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR: " << sizeof(c) << std::endl;
    return 0;
}
