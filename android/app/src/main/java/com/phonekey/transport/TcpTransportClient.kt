package com.phonekey.transport

import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

class TcpTransportClient : ITransport {

    private var socket: Socket? = null
    private var inputStream: InputStream? = null
    private var outputStream: OutputStream? = null
    private var listener: ITransportListener? = null
    private val isConnected = AtomicBoolean(false)
    private val sequenceCounter = AtomicInteger(1)
    private var workerThread: Thread? = null

    override fun setListener(listener: ITransportListener) {
        this.listener = listener
    }

    override fun isConnected(): Boolean {
        return isConnected.get() && socket?.isConnected == true
    }

    override fun connect(host: String, port: Int): Boolean {
        close()
        return try {
            val sock = Socket(host, port)
            this.socket = sock
            this.inputStream = sock.getInputStream()
            this.outputStream = sock.getOutputStream()
            this.isConnected.set(true)

            listener?.onConnectionStateChanged(true, "$host:$port")

            workerThread = Thread { receiverLoop() }.apply { start() }
            true
        } catch (e: Exception) {
            listener?.onError("TCP Connect failed: ${e.message}")
            close()
            false
        }
    }

    private fun receiverLoop() {
        val inStream = inputStream ?: return
        val buffer = ByteArray(4096)
        val rxBuffer = java.io.ByteArrayOutputStream()

        try {
            while (isConnected.get()) {
                val read = inStream.read(buffer)
                if (read <= 0) break

                rxBuffer.write(buffer, 0, read)

                var rxBytes = rxBuffer.toByteArray()
                while (rxBytes.size >= 18) {
                    val headerBuf = ByteBuffer.wrap(rxBytes, 0, 8).order(ByteOrder.BIG_ENDIAN)
                    val magic = headerBuf.int
                    val payloadLen = headerBuf.int

                    if (magic != FrameProtocol.FRAME_MAGIC || payloadLen > FrameProtocol.MAX_PAYLOAD_SIZE) {
                        listener?.onError("Corrupted stream magic/length")
                        break
                    }

                    val totalFrameLen = 14 + payloadLen + 4
                    if (rxBytes.size < totalFrameLen) break

                    val frameData = ByteArray(totalFrameLen)
                    System.arraycopy(rxBytes, 0, frameData, 0, totalFrameLen)

                    val frame = FrameProtocol.deserializeFrame(frameData)
                    if (frame != null) {
                        listener?.onFrameReceived(frame)
                    } else {
                        listener?.onError("CRC32 mismatch or frame deserialization error")
                    }

                    val remainingLen = rxBytes.size - totalFrameLen
                    val remaining = ByteArray(remainingLen)
                    System.arraycopy(rxBytes, totalFrameLen, remaining, 0, remainingLen)

                    rxBuffer.reset()
                    rxBuffer.write(remaining)
                    rxBytes = remaining
                }
            }
        } catch (e: Exception) {
            listener?.onError("Receiver loop error: ${e.message}")
        } finally {
            isConnected.set(false)
            listener?.onConnectionStateChanged(false, "Disconnected")
        }
    }

    override fun sendFrame(messageType: TransportMessageType, payload: ByteArray): Boolean {
        if (!isConnected()) return false
        val out = outputStream ?: return false

        return try {
            val frame = TransportFrame(
                messageType = messageType,
                sequenceNumber = sequenceCounter.getAndIncrement(),
                payloadLength = payload.size,
                payload = payload,
                checksum = 0
            )

            val serialized = FrameProtocol.serializeFrame(frame)
            synchronized(out) {
                out.write(serialized)
                out.flush()
            }
            true
        } catch (e: Exception) {
            isConnected.set(false)
            listener?.onError("Send frame failed: ${e.message}")
            false
        }
    }

    override fun close() {
        isConnected.set(false)
        try {
            socket?.close()
        } catch (ignored: Exception) {}
        socket = null
        inputStream = null
        outputStream = null
    }
}
