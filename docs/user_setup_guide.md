# PhoneKey — User Setup & Deployment Guide

Welcome to **PhoneKey**, an open-source security solution that enables your Android smartphone's biometric authentication (fingerprint/face) to authorize unlocking your Windows PC over local encrypted channels.

---

## 📋 System Requirements
- **Windows PC**: Windows 10 or Windows 11 (64-bit), Microsoft Visual C++ 2022 Redistributable.
- **Android Phone**: Android 10 (API Level 29) or higher with biometric hardware (Fingerprint / Strong Face).
- **Network**: Local Wi-Fi network or Bluetooth LE.

---

## 🛠️ Step 1: Building & Installing PhoneKey on Windows

1. Open a Command Prompt or PowerShell in the repository root directory.
2. Run the release build script:
   ```cmd
   scratch\build_all_release.bat
   ```
3. Copy the compiled binaries to `%ProgramFiles%\PhoneKey\`:
   - `PhoneKeyAgent.exe`
   - `PhoneKeyCredentialProvider.dll`
4. Register the Credential Provider COM DLL with Windows (requires Administrator Command Prompt):
   ```cmd
   regsvr32 "%ProgramFiles%\PhoneKey\PhoneKeyCredentialProvider.dll"
   ```
5. Start the PhoneKey Desktop Agent background service:
   ```cmd
   PhoneKeyAgent.exe
   ```

---

## 📱 Step 2: Installing PhoneKey on Android

1. Open the `android` project directory in Android Studio.
2. Build and install the APK onto your Android device:
   ```bash
   ./gradlew assembleRelease
   ```
3. Launch the PhoneKey app on your smartphone.
4. On first launch, PhoneKey automatically generates a hardware-backed ECDSA P-256 keypair inside the Android Keystore protected by your fingerprint.

---

## 🔗 Step 3: Pairing Phone & Windows PC (Out-of-Band)

1. Open **PhoneKey Desktop Agent** on Windows and click **Pair New Device**.
2. Windows displays a QR code on screen containing the pairing session ID and ephemeral ECDH key.
3. Open the **PhoneKey App** on Android and tap **Scan Pairing QR Code**.
4. Point your phone camera at the Windows screen to scan the QR code.
5. Both devices derive an ephemeral shared secret and display a **6-Digit SAS PIN** on their screens.
6. **Verify**: Ensure the 6-digit PIN on your phone screen matches the 6-digit PIN on your Windows screen.
7. Click **Approve Pairing** on **BOTH** devices. The paired public key is now securely stored via Windows DPAPI.

---

## 🔓 Step 4: Unlocking Your Windows PC

1. On your Windows Lock Screen, select the **PhoneKey Biometric Unlock** tile.
2. The Windows Agent issues a fresh 256-bit challenge to your phone.
3. Your phone displays the `BiometricPrompt`: *"Unlock Windows PC"*.
4. Scan your fingerprint on your phone.
5. Your phone signs the challenge inside hardware TEE/StrongBox and transmits the signature to your PC.
6. Windows verifies the signature, confirms challenge freshness, and unlocks your PC seamlessly!
