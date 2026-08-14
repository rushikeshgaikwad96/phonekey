#ifndef PHONEKEY_MULTI_DEVICE_MANAGER_H
#define PHONEKEY_MULTI_DEVICE_MANAGER_H

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <array>
#include <vector>
#include <string>
#include <memory>
#include "../common/CryptoEngine.h"
#include "../common/Protocol.h"

namespace PhoneKey {

struct PairedDeviceInfo {
    std::array<uint8_t, UUID_SIZE> deviceId;
    std::string nickname;
    std::vector<uint8_t> rawPublicKey;
    bool isPrimary;
    uint64_t pairedTimestampMs;
    uint64_t lastUsedTimestampMs;
};

class MultiDeviceManager {
public:
    explicit MultiDeviceManager(CryptoEngine& cryptoEngine);
    ~MultiDeviceManager();

    // Register a new phone device or update an existing one
    bool RegisterDevice(const PairedDeviceInfo& info);

    // Revoke/Delete a device by ID
    bool RevokeDevice(const std::array<uint8_t, UUID_SIZE>& deviceId);

    // Set a device as primary
    bool SetPrimaryDevice(const std::array<uint8_t, UUID_SIZE>& deviceId);

    // Retrieve device info by ID
    bool GetDevice(const std::array<uint8_t, UUID_SIZE>& deviceId, PairedDeviceInfo& outInfo);

    // List all registered devices
    std::vector<PairedDeviceInfo> ListDevices() const;

    // Get public key handle for CNG verification
    BCRYPT_KEY_HANDLE GetPublicKeyHandle(const std::array<uint8_t, UUID_SIZE>& deviceId);

    // Load / Save encrypted device store using DPAPI
    bool LoadStore();
    bool SaveStore();

private:
    CryptoEngine& m_crypto;
    std::vector<PairedDeviceInfo> m_devices;
};

} // namespace PhoneKey

#endif // PHONEKEY_MULTI_DEVICE_MANAGER_H
