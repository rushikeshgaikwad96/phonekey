#ifndef PHONEKEY_DEVICE_REGISTRY_H
#define PHONEKEY_DEVICE_REGISTRY_H

#include "../common/CryptoEngine.h"
#include "../common/Protocol.h"
#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <array>

namespace PhoneKey {

struct RegisteredDevice {
    std::array<uint8_t, UUID_SIZE> deviceId;
    std::string deviceName;
    BCRYPT_KEY_HANDLE hPublicKey;
    bool isEnabled;

    RegisteredDevice() : hPublicKey(NULL), isEnabled(true) {
        deviceId.fill(0);
    }
};

class DeviceRegistry {
public:
    explicit DeviceRegistry(CryptoEngine& cryptoEngine);
    ~DeviceRegistry();

    // Registers a development device with raw uncompressed 64-byte EC public key
    bool RegisterDevice(const std::array<uint8_t, UUID_SIZE>& deviceId, const std::string& deviceName, const uint8_t* rawPublicKeyXy, size_t keyLen);

    // Registers a development device with DER encoded EC public key
    bool RegisterDeviceDer(const std::array<uint8_t, UUID_SIZE>& deviceId, const std::string& deviceName, const uint8_t* derPublicKey, size_t keyLen);

    // Retrieves BCRYPT_KEY_HANDLE for a registered device
    BCRYPT_KEY_HANDLE GetDevicePublicKey(const std::array<uint8_t, UUID_SIZE>& deviceId);

    // Checks if a device is registered and enabled
    bool IsDeviceRegistered(const std::array<uint8_t, UUID_SIZE>& deviceId);

    // Unregisters a device and cleans up key handle
    bool UnregisterDevice(const std::array<uint8_t, UUID_SIZE>& deviceId);

private:
    CryptoEngine& m_cryptoEngine;
    std::mutex m_mutex;
    std::unordered_map<std::string, RegisteredDevice> m_devices;

    static std::string BytesToKey(const uint8_t* data, size_t len);
};

} // namespace PhoneKey

#endif // PHONEKEY_DEVICE_REGISTRY_H
