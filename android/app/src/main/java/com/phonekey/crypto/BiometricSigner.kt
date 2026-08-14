package com.phonekey.crypto

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import java.security.Signature

class BiometricSigner(private val activity: FragmentActivity) {

    interface SignCallback {
        fun onSuccess(signatureDerBytes: ByteArray)
        fun onError(errorCode: Int, errorMessage: String)
        fun onFailed()
    }

    /**
     * Shows AndroidX BiometricPrompt gated by BIOMETRIC_STRONG.
     * Binds signature to BiometricPrompt.CryptoObject.
     * Explicitly disables PIN/Password fallback for Phase 1 authentication keys.
     */
    fun authenticateAndSign(
        signature: Signature,
        payloadBytes: ByteArray,
        callback: SignCallback
    ) {
        val executor = ContextCompat.getMainExecutor(activity)

        val biometricPrompt = BiometricPrompt(
            activity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    val authenticatedSignature = result.cryptoObject?.signature
                    if (authenticatedSignature != null) {
                        try {
                            authenticatedSignature.update(payloadBytes)
                            val derSignature = authenticatedSignature.sign()
                            callback.onSuccess(derSignature)
                        } catch (e: Exception) {
                            callback.onError(-1, "Signing failed: ${e.message}")
                        }
                    } else {
                        callback.onError(-2, "CryptoObject signature missing")
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    callback.onError(errorCode, errString.toString())
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    callback.onFailed()
                }
            }
        )

        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle("PhoneKey — Unlock Windows PC")
            .setSubtitle("Authenticate with your fingerprint to sign unlock challenge")
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_STRONG)
            .build()

        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(signature))
    }
}
