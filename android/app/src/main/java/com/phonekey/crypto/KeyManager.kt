package com.phonekey.crypto

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class KeyManager(private val keyAlias: String = DEFAULT_KEY_ALIAS) {

    companion object {
        const val DEFAULT_KEY_ALIAS = "PhoneKeyAuthKey"
        const val KEYSTORE_PROVIDER = "AndroidKeyStore"
    }

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE_PROVIDER).apply { load(null) }

    /**
     * Generates an ECDSA P-256 (secp256r1) signing keypair in Android Keystore.
     * Enforces hardware protection, non-exportable private key, BIOMETRIC_STRONG requirement,
     * and invalidation upon new biometric enrollment.
     */
    fun generateKey(): KeyMetadata {
        var isStrongBox = false

        // Attempt StrongBox hardware key generation first
        try {
            generateKeyInternal(useStrongBox = true)
            isStrongBox = true
        } catch (e: Exception) {
            // Fall back to standard TEE AndroidKeyStore if StrongBox is unavailable on device
            generateKeyInternal(useStrongBox = false)
            isStrongBox = false
        }

        return getKeyMetadata(isStrongBox)
    }

    private fun generateKeyInternal(useStrongBox: Boolean) {
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE_PROVIDER)
        val builder = KeyGenParameterSpec.Builder(
            keyAlias,
            KeyProperties.PURPOSE_SIGN
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }

        if (useStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            try {
                builder.setIsStrongBoxBacked(true)
            } catch (ignored: Exception) {}
        }

        kpg.initialize(builder.build())
        kpg.generateKeyPair()
    }

    fun getPrivateKey(): PrivateKey? {
        return keyStore.getKey(keyAlias, null) as? PrivateKey
    }

    fun getPublicKey(): PublicKey? {
        val cert = keyStore.getCertificate(keyAlias) ?: return null
        return cert.publicKey
    }

    fun getPublicKeyDer(): ByteArray? {
        return getPublicKey()?.encoded
    }

    /**
     * Returns 64-byte uncompressed EC point (X || Y) for Windows CNG import.
     */
    fun getPublicKeyUncompressedXy(): ByteArray? {
        val ecPubKey = getPublicKey() as? ECPublicKey ?: return null
        val w = ecPubKey.w
        val xBytes = getFixedLengthBytes(w.affineX.toByteArray(), 32)
        val yBytes = getFixedLengthBytes(w.affineY.toByteArray(), 32)
        return xBytes + yBytes
    }

    private fun getFixedLengthBytes(bigIntBytes: ByteArray, length: Int): ByteArray {
        val result = ByteArray(length)
        if (bigIntBytes.size == length) {
            return bigIntBytes
        } else if (bigIntBytes.size > length) {
            // Strip leading sign byte if present
            System.arraycopy(bigIntBytes, bigIntBytes.size - length, result, 0, length)
        } else {
            // Right-align with leading zeros
            System.arraycopy(bigIntBytes, 0, result, length - bigIntBytes.size, bigIntBytes.size)
        }
        return result
    }

    fun isKeyPresent(): Boolean {
        return keyStore.containsAlias(keyAlias)
    }

    fun isKeyInvalidated(): Boolean {
        return try {
            val privateKey = getPrivateKey() ?: return true
            // Attempting to query key info will throw if permanently invalidated
            val factory = KeyFactory.getInstance(privateKey.algorithm, KEYSTORE_PROVIDER)
            val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
            keyInfo.isUserAuthenticationRequired
            false
        } catch (e: KeyPermanentlyInvalidatedException) {
            true
        } catch (e: Exception) {
            false
        }
    }

    fun getKeyMetadata(isStrongBox: Boolean = false): KeyMetadata {
        val privateKey = getPrivateKey()
        var isHardware = true
        if (privateKey != null) {
            try {
                val factory = KeyFactory.getInstance(privateKey.algorithm, KEYSTORE_PROVIDER)
                val keyInfo = factory.getKeySpec(privateKey, KeyInfo::class.java)
                isHardware = keyInfo.isInsideSecureHardware
            } catch (ignored: Exception) {}
        }

        return KeyMetadata(
            alias = keyAlias,
            algorithm = "EC",
            curve = "secp256r1",
            digest = "SHA-256",
            isUserAuthenticationRequired = true,
            userAuthenticationValidityDurationSeconds = 0,
            isInvalidatedByBiometricEnrollment = true,
            isStrongBoxBacked = isStrongBox,
            isHardwareBacked = isHardware,
            isKeyInvalidated = isKeyInvalidated()
        )
    }

    fun deleteKey() {
        if (keyStore.containsAlias(keyAlias)) {
            keyStore.deleteEntry(keyAlias)
        }
    }
}
