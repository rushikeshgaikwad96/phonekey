package com.phonekey.crypto

/**
 * Development and runtime security metadata reporting Android Keystore properties.
 */
data class KeyMetadata(
    val alias: String,
    val algorithm: String = "EC",
    val curve: String = "secp256r1",
    val digest: String = "SHA-256",
    val isUserAuthenticationRequired: Boolean = true,
    val userAuthenticationValidityDurationSeconds: Int = 0,
    val isInvalidatedByBiometricEnrollment: Boolean = true,
    val isStrongBoxBacked: Boolean = false,
    val isHardwareBacked: Boolean = true,
    val isKeyInvalidated: Boolean = false
)
