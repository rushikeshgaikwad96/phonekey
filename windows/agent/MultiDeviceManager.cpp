#include "MultiDeviceManager.h"
#include "DpapiStorage.h"
#include <algorithm>
#include <cstring>

namespace PhoneKey {

MultiDeviceManager::MultiDeviceManager(CryptoEngine& cryptoEngine)
    : m_crypto(cryptoEngine) {}

MultiDeviceManager::~MultiDeviceManager() {}

bool MultiDeviceManager::RegisterDevice(const PairedDeviceInfo& info) {
    auto it = std::find_if(m_devices.begin(), m_devices.end(), [&](const PairedDeviceInfo& d) {
        return d.deviceId == info.deviceId;
    });

    if (it != m_devices.end()) {
        *it = info;
    } else {
        m_devices.push_back(info);
    }
    return SaveStore();
}

bool MultiDeviceManager::RevokeDevice(const std::array<uint8_t, UUID_SIZE>& deviceId) {
    auto it = std::remove_if(m_devices.begin(), m_devices.end(), [&](const PairedDeviceInfo& d) {
        return d.deviceId == deviceId;
    });

    if (it != m_devices.end()) {
        m_devices.erase(it, m_devices.end());
        return SaveStore();
    }
    return false;
}

bool MultiDeviceManager::SetPrimaryDevice(const std::array<uint8_t, UUID_SIZE>& deviceId) {
    bool found = false;
    for (auto& dev : m_devices) {
        if (dev.deviceId == deviceId) {
            dev.isPrimary = true;
            found = true;
        } else {
            dev.isPrimary = false;
        }
    }
    return found ? SaveStore() : false;
}

bool MultiDeviceManager::GetDevice(const std::array<uint8_t, UUID_SIZE>& deviceId, PairedDeviceInfo& outInfo) {
    for (const auto& dev : m_devices) {
        if (dev.deviceId == deviceId) {
            outInfo = dev;
            return true;
        }
    }
    return false;
}

std::vector<PairedDeviceInfo> MultiDeviceManager::ListDevices() const {
    return m_devices;
}

BCRYPT_KEY_HANDLE MultiDeviceManager::GetPublicKeyHandle(const std::array<uint8_t, UUID_SIZE>& deviceId) {
    PairedDeviceInfo info;
    if (!GetDevice(deviceId, info) || info.rawPublicKey.empty()) {
        return NULL;
    }
    return m_crypto.ImportRawPublicKey(info.rawPublicKey.data(), info.rawPublicKey.size());
}

bool MultiDeviceManager::LoadStore() {
    // Simple mock / in-memory store backed by DPAPI persistence test
    return true;
}

bool MultiDeviceManager::SaveStore() {
    // Serializes devices to buffer and encrypts via DPAPI
    std::vector<uint8_t> buffer;
    for (const auto& dev : m_devices) {
        buffer.insert(buffer.end(), dev.deviceId.begin(), dev.deviceId.end());
        buffer.push_back(dev.isPrimary ? 1 : 0);
        buffer.insert(buffer.end(), dev.rawPublicKey.begin(), dev.rawPublicKey.end());
    }
    std::vector<uint8_t> encrypted;
    return DpapiStorage::EncryptData(buffer, encrypted);
}

} // namespace PhoneKey
