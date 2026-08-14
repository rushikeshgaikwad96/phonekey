package com.phonekey.engine

import androidx.fragment.app.FragmentActivity
import com.phonekey.crypto.BiometricSigner
import com.phonekey.crypto.KeyManager
import com.phonekey.crypto.ProtocolEncoder
import com.phonekey.crypto.SignatureManager
import com.phonekey.transport.ITransport
import com.phonekey.transport.ITransportListener
import com.phonekey.transport.TcpTransportClient
import com.phonekey.transport.TransportFrame
import com.phonekey.transport.TransportMessageType
import java.nio.ByteBuffer
import java.nio.ByteOrder

class UnlockController(
    private val activity: FragmentActivity,
    private val deviceId: ByteArray,
    private val keyManager: KeyManager = KeyManager()
) : ITransportListener {

    private val transport: ITransport = TcpTransportClient()
    private val signatureManager = SignatureManager()
    private val biometricSigner = BiometricSigner(activity)

    interface UnlockStatusCallback {
        fun onStatusUpdate(status: String)
        fun onUnlockSuccess()
        fun onUnlockFailed(error: String)
    }

    private var statusCallback: UnlockStatusCallback? = null

    fun setStatusCallback(callback: UnlockStatusCallback) {
        this.statusCallback = callback
    }

    fun startConnection(host: String, port: Int) {
        transport.setListener(this)
        statusCallback?.onStatusUpdate("Connecting to Windows host $host:$port...")
        Thread {
            transport.connect(host, port)
        }.start()
    }

    override fun onFrameReceived(frame: TransportFrame) {
        if (frame.messageType == TransportMessageType.UNLOCK_REQ) {
            handleUnlockRequest(frame.payload)
        }
    }

    private fun handleUnlockRequest(payload: ByteArray) {
        if (payload.size < 80) {
            statusCallback?.onUnlockFailed("Malformed UNLOCK_REQ payload size")
            return
        }

        val buffer = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)

        val sessionId = ByteArray(16)
        buffer.get(sessionId)

        val pcId = ByteArray(16)
        buffer.get(pcId)

        val challenge = ByteArray(32)
        buffer.get(challenge)

        val createdTime = buffer.long
        val expireTime = buffer.long

        val nowMs = System.currentTimeMillis()
        if (nowMs > expireTime) {
            statusCallback?.onUnlockFailed("Received expired challenge from Windows host")
            return
        }

        activity.runOnUiThread {
            statusCallback?.onStatusUpdate("Biometric authorization required to unlock Windows PC...")

            val privateKey = keyManager.getPrivateKey()
            if (privateKey == null) {
                statusCallback?.onUnlockFailed("Android Keystore private key not found")
                return@runOnUiThread
            }

            val signature = signatureManager.initSign(privateKey)

            // Construct 108-byte canonical payload P
            val authPayload = ProtocolEncoder.AuthPayload(
                deviceId = deviceId,
                sessionId = sessionId,
                pcId = pcId,
                challenge = challenge,
                expirationTimestampMs = expireTime
            )

            val canonicalBytes = ProtocolEncoder.encode(authPayload)

            biometricSigner.authenticateAndSign(
                signature,
                canonicalBytes,
                object : BiometricSigner.SignCallback {
                    override fun onSuccess(signatureDerBytes: ByteArray) {
                        statusCallback?.onStatusUpdate("Biometric authentication successful! Transmitting signature...")

                        // Full payload = Canonical Payload P (108 Bytes) || Signature DER Bytes
                        val fullPayload = canonicalBytes + signatureDerBytes
                        val sendOk = transport.sendFrame(TransportMessageType.UNLOCK_RESP, fullPayload)

                        if (sendOk) {
                            statusCallback?.onUnlockSuccess()
                        } else {
                            statusCallback?.onUnlockFailed("Failed to transmit UNLOCK_RESP over transport")
                        }
                    }

                    override fun onError(errorCode: Int, errorMessage: String) {
                        statusCallback?.onUnlockFailed("Biometric error [$errorCode]: $errorMessage")
                    }

                    override fun onFailed() {
                        statusCallback?.onUnlockFailed("Biometric scan failed")
                    }
                }
            )
        }
    }

    override fun onConnectionStateChanged(isConnected: Boolean, peerAddress: String) {
        statusCallback?.onStatusUpdate(if (isConnected) "Connected to $peerAddress" else "Disconnected")
    }

    override fun onError(errorMessage: String) {
        statusCallback?.onUnlockFailed("Transport error: $errorMessage")
    }

    fun stop() {
        transport.close()
    }
}
