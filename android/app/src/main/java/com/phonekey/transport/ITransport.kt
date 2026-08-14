package com.phonekey.transport

enum class TransportMessageType(val code: Byte) {
    PAIR_REQ(0x01),
    PAIR_RESP(0x02),
    UNLOCK_REQ(0x10),
    UNLOCK_RESP(0x11),
    ERROR_MSG(0xFF.toByte());

    companion object {
        fun fromCode(code: Byte): TransportMessageType {
            return values().firstOrNull { it.code == code } ?: ERROR_MSG
        }
    }
}

data class TransportFrame(
    val magic: Int = 0x504B4652, // "PKFR"
    val payloadLength: Int,
    val messageType: TransportMessageType,
    val flags: Byte = 0,
    val sequenceNumber: Int,
    val payload: ByteArray,
    val checksum: Int
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is TransportFrame) return false
        return magic == other.magic &&
               payloadLength == other.payloadLength &&
               messageType == other.messageType &&
               flags == other.flags &&
               sequenceNumber == other.sequenceNumber &&
               payload.contentEquals(other.payload) &&
               checksum == other.checksum
    }

    override fun hashCode(): Int {
        var result = magic
        result = 31 * result + payloadLength
        result = 31 * result + messageType.hashCode()
        result = 31 * result + flags
        result = 31 * result + sequenceNumber
        result = 31 * result + payload.contentHashCode()
        result = 31 * result + checksum
        return result
    }
}

interface ITransportListener {
    fun onFrameReceived(frame: TransportFrame)
    fun onConnectionStateChanged(isConnected: Boolean, peerAddress: String)
    fun onError(errorMessage: String)
}

interface ITransport {
    fun connect(host: String, port: Int): Boolean
    fun sendFrame(messageType: TransportMessageType, payload: ByteArray): Boolean
    fun setListener(listener: ITransportListener)
    fun isConnected(): Boolean
    fun close()
}
