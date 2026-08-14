package com.phonekey.transport

class BleTransportHandler : ITransport {

    private var listener: ITransportListener? = null
    private var isConnected = false

    override fun setListener(listener: ITransportListener) {
        this.listener = listener
    }

    override fun isConnected(): Boolean {
        return isConnected
    }

    override fun connect(host: String, port: Int): Boolean {
        isConnected = true
        listener?.onConnectionStateChanged(true, "BLE:$host")
        return true
    }

    override fun sendFrame(messageType: TransportMessageType, payload: ByteArray): Boolean {
        if (!isConnected) return false
        val frame = TransportFrame(
            messageType = messageType,
            sequenceNumber = 1,
            payloadLength = payload.size,
            payload = payload,
            checksum = 0
        )
        val serialized = FrameProtocol.serializeFrame(frame)
        return serialized.isNotEmpty()
    }

    override fun close() {
        isConnected = false
        listener?.onConnectionStateChanged(false, "BLE:Disconnected")
    }
}
