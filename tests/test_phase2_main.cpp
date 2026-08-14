#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <iostream>
#include <vector>
#include <string>
#include <array>
#include <chrono>
#include <cassert>
#include "../windows/agent/MultiDeviceManager.h"
#include "../windows/common/Ctap2Bridge.h"
#include "../windows/common/CryptoEngine.h"

using namespace PhoneKey;

#define TEST_ASSERT(cond, msg) \
    if (!(cond)) { \
        std::cerr << " [FAIL] " << msg << " (Line " << __LINE__ << ")" << std::endl; \
        return false; \
    } else { \
        std::cout << " [PASS] " << msg << std::endl; \
    }

bool TestMultiDeviceManagement() {
    std::cout << "--- Running Multi-Device Management Subsystem Test ---" << std::endl;

    CryptoEngine crypto;
    TEST_ASSERT(crypto.Initialize(), "CryptoEngine initialized");

    MultiDeviceManager mgr(crypto);

    PairedDeviceInfo dev1;
    dev1.deviceId.fill(0x11);
    dev1.nickname = "Galaxy S24 Ultra (Primary)";
    dev1.rawPublicKey = std::vector<uint8_t>(64, 0xAA);
    dev1.isPrimary = true;
    dev1.pairedTimestampMs = 1776182400000;
    dev1.lastUsedTimestampMs = 1776182400000;

    PairedDeviceInfo dev2;
    dev2.deviceId.fill(0x22);
    dev2.nickname = "Pixel 8 Pro (Backup)";
    dev2.rawPublicKey = std::vector<uint8_t>(64, 0xBB);
    dev2.isPrimary = false;
    dev2.pairedTimestampMs = 1776182400000;
    dev2.lastUsedTimestampMs = 1776182400000;

    TEST_ASSERT(mgr.RegisterDevice(dev1), "Registered Primary Phone device");
    TEST_ASSERT(mgr.RegisterDevice(dev2), "Registered Backup Phone device");

    auto list = mgr.ListDevices();
    TEST_ASSERT(list.size() == 2, "ListDevices returned 2 registered phones");

    PairedDeviceInfo retrieved;
    TEST_ASSERT(mgr.GetDevice(dev1.deviceId, retrieved), "GetDevice retrieved Primary Phone by ID");
    TEST_ASSERT(retrieved.nickname == "Galaxy S24 Ultra (Primary)", "Retrieved correct nickname");

    // Revoke Backup Phone
    TEST_ASSERT(mgr.RevokeDevice(dev2.deviceId), "Revoked Backup Phone device");
    list = mgr.ListDevices();
    TEST_ASSERT(list.size() == 1, "ListDevices count updated to 1 after revocation");

    return true;
}

bool TestCtap2Fido2Bridge() {
    std::cout << "--- Running FIDO2 / CTAP2 Security Key Protocol Bridge Test ---" << std::endl;

    std::string rpId = "accounts.google.com";
    std::vector<uint8_t> authData = Ctap2Bridge::BuildAuthenticatorData(rpId, 42, true);

    TEST_ASSERT(authData.size() == 37, "BuildAuthenticatorData produced 37-byte CTAP2 buffer");
    TEST_ASSERT((authData[32] & 0x05) == 0x05, "Flags bitmask contains User Present (0x01) and User Verified (0x04)");
    TEST_ASSERT(authData[36] == 42, "Sign counter set to 42");

    Ctap2GetAssertionRequest req;
    req.relyingPartyId = rpId;
    req.clientDataHash.fill(0x77);

    std::array<uint8_t, UUID_SIZE> devId; devId.fill(0x11);
    std::array<uint8_t, UUID_SIZE> sessId; sessId.fill(0xAA);
    std::array<uint8_t, UUID_SIZE> pcId; pcId.fill(0x99);

    AuthPayload p = Ctap2Bridge::TranslateToPhoneKeyPayload(req, devId, sessId, pcId, 1776182400000);
    TEST_ASSERT(p.challenge == req.clientDataHash, "WebAuthn clientDataHash mapped directly to challenge");

    std::vector<uint8_t> mockSig = {0x30, 0x44, 0x02, 0x20, 0x11, 0x22};
    Ctap2GetAssertionResponse resp = Ctap2Bridge::FormatAssertionResponse(authData, mockSig);

    TEST_ASSERT(resp.status == 0x00, "Formatted CTAP2 response status is 0x00 (SUCCESS)");
    TEST_ASSERT(!resp.signatureDer.empty(), "Response contains non-empty DER signature");

    return true;
}

int main() {
    std::cout << "====================================================" << std::endl;
    std::cout << "     PHONEKEY PHASE 2 AUTOMATED TEST SUITE        " << std::endl;
    std::cout << "====================================================" << std::endl;

    bool allPassed = true;
    allPassed &= TestMultiDeviceManagement();
    allPassed &= TestCtap2Fido2Bridge();

    std::cout << "====================================================" << std::endl;
    if (allPassed) {
        std::cout << "    ALL PHASE 2 ENHANCEMENT TESTS PASSED! (100%)   " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 0;
    } else {
        std::cerr << "    SOME PHASE 2 TESTS FAILED!                    " << std::endl;
        std::cout << "====================================================" << std::endl;
        return 1;
    }
}
