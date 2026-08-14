#include "DeviceRegistry.h"
#include <sstream>
#include <iomanip>

namespace PhoneKey {

DeviceRegistry::DeviceRegistry(CryptoEngine& cryptoEngine)
    : m_cryptoEngine(cryptoEngine) {}

DeviceRegistry::~DeviceRegistry() {
    std::lock_guard<std::mutex> lock(m_mutex);
    for (auto& pair : m_devices) {
        if (pair.second.hPublicKey) {
            BCryptDestroyKey(pair.second.hPublicKey);
            pair.second.hPublicKey = NULL;
        }
    }
}

std::string DeviceRegistry::BytesToKey(const uint8_t* data, size_t len) {
    std::ostringstream oss;
    for (size_t i = 0; i < len; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return oss.str();
}

bool DeviceRegistry::RegisterDevice(const std::array<uint8_t, UUID_SIZE>& deviceId, const std::string& deviceName, const uint8_t* rawPublicKeyXy, size_t keyLen) {
    std::lock_guard<std::mutex> lock(m_mutex);
    BCRYPT_KEY_HANDLE hKey = m_cryptoEngine.ImportRawPublicKey(rawPublicKeyXy, keyLen);
    if (!hKey) return false;

    std::string keyStr = BytesToKey(deviceId.data(), UUID_SIZE);
    
    // Destroy previous key if existing
    auto it = m_devices.find(keyStr);
    if (it != m_devices.end() && it->second.hPublicKey) {
        BCryptDestroyKey(it->second.hPublicKey);
    }

    RegisteredDevice dev;
    dev.deviceId = deviceId;
    dev.deviceName = deviceName;
    dev.hPublicKey = hKey;
    dev.isEnabled = true;

    m_devices[keyStr] = dev;
    return true;
}

bool DeviceRegistry::RegisterDeviceDer(const std::array<uint8_t, UUID_SIZE>& deviceId, const std::string& deviceName, const uint8_t* derPublicKey, size_t keyLen) {
    std::lock_guard<std::mutex> lock(m_mutex);
    BCRYPT_KEY_HANDLE hKey = m_cryptoEngine.ImportDerPublicKey(derPublicKey, keyLen);
    if (!hKey) return false;

    std::string keyStr = BytesToKey(deviceId.data(), UUID_SIZE);

    auto it = m_devices.find(keyStr);
    if (it != m_devices.end() && it->second.hPublicKey) {
        BCryptDestroyKey(it->second.hPublicKey);
    }

    RegisteredDevice dev;
    dev.deviceId = deviceId;
    dev.deviceName = deviceName;
    dev.hPublicKey = hKey;
    dev.isEnabled = true;

    m_devices[keyStr] = dev;
    return true;
}

BCRYPT_KEY_HANDLE DeviceRegistry::GetDevicePublicKey(const std::array<uint8_t, UUID_SIZE>& deviceId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string keyStr = BytesToKey(deviceId.data(), UUID_SIZE);
    auto it = m_devices.find(keyStr);
    if (it != m_devices.end() && it->second.isEnabled) {
        return it->second.hPublicKey;
    }
    return NULL;
}

bool DeviceRegistry::IsDeviceRegistered(const std::array<uint8_t, UUID_SIZE>& deviceId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string keyStr = BytesToKey(deviceId.data(), UUID_SIZE);
    auto it = m_devices.find(keyStr);
    return (it != m_devices.end() && it->second.isEnabled);
}

bool DeviceRegistry::UnregisterDevice(const std::array<uint8_t, UUID_SIZE>& deviceId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    std::string keyStr = BytesToKey(deviceId.data(), UUID_SIZE);
    auto it = m_devices.find(keyStr);
    if (it != m_devices.end()) {
        if (it->second.hPublicKey) {
            BCryptDestroyKey(it->second.hPublicKey);
        }
        m_devices.erase(it);
        return true;
    }
    return false;
}

} // namespace PhoneKey
