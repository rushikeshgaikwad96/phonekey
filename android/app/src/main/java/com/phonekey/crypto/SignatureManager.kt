package com.phonekey.crypto

import java.security.PrivateKey
import java.security.Signature

class SignatureManager {

    companion object {
        const val SIGNATURE_ALGORITHM = "SHA256withECDSA"
    }

    /**
     * Instantiates an uninitialized Signature object for SHA256withECDSA.
     */
    fun createSignature(): Signature {
        return Signature.getInstance(SIGNATURE_ALGORITHM)
    }

    /**
     * Initializes signature object with private key for signing.
     */
    fun initSign(privateKey: PrivateKey): Signature {
        val signature = createSignature()
        signature.initSign(privateKey)
        return signature
    }

    /**
     * Signs canonical payload bytes using initialized Signature object after biometric authorization.
     */
    fun signPayload(signature: Signature, payloadBytes: ByteArray): ByteArray {
        signature.update(payloadBytes)
        return signature.sign()
    }
}
