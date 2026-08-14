#ifndef PHONEKEY_CTAP2_BRIDGE_H
#define PHONEKEY_CTAP2_BRIDGE_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <vector>
#include <string>
#include <array>
#include "Protocol.h"

namespace PhoneKey {

struct Ctap2GetAssertionRequest {
    std::string relyingPartyId;
    std::array<uint8_t, 32> clientDataHash;
    std::vector<uint8_t> allowCredentialId;
};

struct Ctap2GetAssertionResponse {
    uint8_t status; // 0x00 = CTAP1_ERR_SUCCESS
    std::vector<uint8_t> authenticatorData;
    std::vector<uint8_t> signatureDer;
    std::vector<uint8_t> userHandle;
};

class Ctap2Bridge {
public:
    // Constructs 37-byte CTAP2 AuthenticatorData buffer (rpidHash (32B) || flags (1B) || counter (4B))
    static std::vector<uint8_t> BuildAuthenticatorData(const std::string& relyingPartyId, uint32_t signCount, bool userVerified);

    // Maps WebAuthn GetAssertion request into PhoneKey AuthPayload challenge bytes
    static AuthPayload TranslateToPhoneKeyPayload(
        const Ctap2GetAssertionRequest& req,
        const std::array<uint8_t, UUID_SIZE>& deviceId,
        const std::array<uint8_t, UUID_SIZE>& sessionId,
        const std::array<uint8_t, UUID_SIZE>& pcId,
        uint64_t expirationMs
    );

    // Formats full CTAP2 GetAssertion response containing authenticatorData & signature
    static Ctap2GetAssertionResponse FormatAssertionResponse(
        const std::vector<uint8_t>& authData,
        const std::vector<uint8_t>& signatureDer
    );
};

} // namespace PhoneKey

#endif // PHONEKEY_CTAP2_BRIDGE_H
