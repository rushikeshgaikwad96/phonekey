package com.phonekey.transport

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.CRC32

object FrameProtocol {

    const val FRAME_MAGIC = 0x504B4652 // "PKFR"
    const val MAX_PAYLOAD_SIZE = 65536   // 64 KB limit

    fun calculateCrc32(data: ByteArray, length: Int): Long {
        val crc = CRC32()
        crc.update(data, 0, length)
        return crc.value
    }

    fun serializeFrame(frame: TransportFrame): ByteArray {
        val payloadLen = frame.payload.size
        val totalLen = 14 + payloadLen + 4
        val buffer = ByteBuffer.allocate(totalLen).order(ByteOrder.BIG_ENDIAN)

        // 1. Magic (4 Bytes)
        buffer.putInt(FRAME_MAGIC)

        // 2. FrameLength (4 Bytes)
        buffer.putInt(payloadLen)

        // 3. MessageType (1 Byte)
        buffer.put(frame.messageType.code)

        // 4. Flags (1 Byte)
        buffer.put(frame.flags)

        // 5. SequenceNumber (4 Bytes)
        buffer.putInt(frame.sequenceNumber)

        // 6. PayloadBytes (N Bytes)
        if (payloadLen > 0) {
            buffer.put(frame.payload)
        }

        // 7. Calculate CRC32 over Header + PayloadBytes (14 + N Bytes)
        val crcVal = calculateCrc32(buffer.array(), 14 + payloadLen).toInt()

        // 8. Checksum (4 Bytes)
        buffer.putInt(crcVal)

        return buffer.array()
    }

    fun deserializeFrame(data: ByteArray): TransportFrame? {
        if (data.size < 18) return null

        val buffer = ByteBuffer.wrap(data).order(ByteOrder.BIG_ENDIAN)

        val magic = buffer.int
        if (magic != FRAME_MAGIC) return null

        val payloadLen = buffer.int
        if (payloadLen < 0 || payloadLen > MAX_PAYLOAD_SIZE) return null
        if (data.size < 14 + payloadLen + 4) return null

        val messageTypeCode = buffer.get()
        val flags = buffer.get()
        val seqNum = buffer.int

        val payload = ByteArray(payloadLen)
        if (payloadLen > 0) {
            buffer.get(payload)
        }

        val expectedChecksum = buffer.int
        val actualChecksum = calculateCrc32(data, 14 + payloadLen).toInt()

        if (actualChecksum != expectedChecksum) {
            return null // CRC32 checksum mismatch
        }

        return TransportFrame(
            magic = magic,
            payloadLength = payloadLen,
            messageType = TransportMessageType.fromCode(messageTypeCode),
            flags = flags,
            sequenceNumber = seqNum,
            payload = payload,
            checksum = actualChecksum
        )
    }
}
