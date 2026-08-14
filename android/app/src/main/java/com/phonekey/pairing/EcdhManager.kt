package com.phonekey.pairing

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

class EcdhManager {

    private var localKeyPair: KeyPair? = null

    fun generateEphemeralKeyPair(): KeyPair {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val keyPair = kpg.generateKeyPair()
        this.localKeyPair = keyPair
        return keyPair
    }

    /**
     * Gets 65-byte uncompressed EC point (0x04 || X || Y) for QR code exchange.
     */
    fun getPublicPointUncompressed(): ByteArray? {
        val ecPubKey = localKeyPair?.public as? ECPublicKey ?: return null
        val w = ecPubKey.w
        val xBytes = getFixedLengthBytes(w.affineX.toByteArray(), 32)
        val yBytes = getFixedLengthBytes(w.affineY.toByteArray(), 32)
        return byteArrayOf(0x04) + xBytes + yBytes
    }

    /**
     * Computes 32-byte raw ECDH shared secret S with peer's uncompressed public key point.
     */
    fun computeSharedSecret(peerPublicXy: ByteArray): ByteArray? {
        val localPriv = localKeyPair?.private ?: return null
        val peerPubKey = parseUncompressedPublicKey(peerPublicXy) ?: return null

        val keyAgreement = KeyAgreement.getInstance("ECDH")
        keyAgreement.init(localPriv)
        keyAgreement.doPhase(peerPubKey, true)

        return keyAgreement.generateSecret()
    }

    private fun parseUncompressedPublicKey(xyBytes: ByteArray): PublicKey? {
        val offset = if (xyBytes.size == 65 && xyBytes[0] == 0x04.toByte()) 1 else 0
        if (xyBytes.size - offset != 64) return null

        val xBytes = ByteArray(32)
        val yBytes = ByteArray(32)
        System.arraycopy(xyBytes, offset, xBytes, 0, 32)
        System.arraycopy(xyBytes, offset + 32, yBytes, 0, 32)

        val x = java.math.BigInteger(1, xBytes)
        val y = java.math.BigInteger(1, yBytes)
        val point = ECPoint(x, y)

        val kf = KeyFactory.getInstance("EC")
        val params = (localKeyPair?.public as? ECPublicKey)?.params ?: return null
        val pubSpec = ECPublicKeySpec(point, params)

        return kf.generatePublic(pubSpec)
    }

    private fun getFixedLengthBytes(bigIntBytes: ByteArray, length: Int): ByteArray {
        val result = ByteArray(length)
        if (bigIntBytes.size == length) {
            return bigIntBytes
        } else if (bigIntBytes.size > length) {
            System.arraycopy(bigIntBytes, bigIntBytes.size - length, result, 0, length)
        } else {
            System.arraycopy(bigIntBytes, 0, result, length - bigIntBytes.size, bigIntBytes.size)
        }
        return result
    }
}
