# PhoneKey Transport & Framing Protocol Specification (Milestone 4)

## 1. Overview
PhoneKey protocol messages are transport-agnostic. To support stream-based transports (TCP sockets) and packet-based transports (Bluetooth LE GATT / RFCOMM) without payload truncation or framing ambiguity, all messages are encapsulated inside a **PhoneKey Binary Transport Frame**.

---

## 2. Frame Structure

```
Offset (Bytes)  Field           Type      Size (Bytes)  Description
-------------------------------------------------------------------------------------------------------
0..3            Magic           uint32    4             Magic bytes: 0x504B4652 (ASCII "PKFR")
4..7            FrameLength     uint32    4             Big-Endian uint32: length of PayloadBytes
8               MessageType     uint8     1             0x01 = PAIR_REQ, 0x02 = PAIR_RESP,
                                                        0x10 = UNLOCK_REQ, 0x11 = UNLOCK_RESP,
                                                        0xFF = ERROR
9               Flags           uint8     1             0x00 = Raw, 0x01 = Encrypted
10..13          SequenceNumber  uint32    4             Strictly incrementing frame sequence counter
14..(14+N-1)    PayloadBytes    bytes     N             Raw protocol payload bytes
(14+N)..(17+N)  Checksum        uint32    4             CRC32 checksum over (Header + PayloadBytes)
-------------------------------------------------------------------------------------------------------
Header Length: 14 Bytes | Total Frame Length: 18 + N Bytes
```

### Field Definitions & Encoding Rules
1. **Magic (4 Bytes)**: Must equal `0x504B4652` (`"PKFR"`). Invalid magic bytes MUST result in immediate connection drop.
2. **FrameLength (4 Bytes)**: Big-Endian uint32 specifying length $N$ of `PayloadBytes`. Maximum allowed $N = 65536$ (64 KB). Frames exceeding 64 KB MUST be rejected as `FRAME_OVERSIZED`.
3. **MessageType (1 Byte)**: Identifies payload category (`0x01` Pairing Request, `0x02` Pairing Response, `0x10` Unlock Request, `0x11` Unlock Response, `0xFF` Error).
4. **Flags (1 Byte)**: Bit 0: `1` if payload is encrypted, `0` if raw plaintext payload.
5. **SequenceNumber (4 Bytes)**: Big-Endian uint32 monotonically incremented with each frame to detect missing or reordered frames.
6. **PayloadBytes (N Bytes)**: Raw payload (e.g. 108-byte canonical unlock payload $P$ or JSON pairing payload).
7. **Checksum (4 Bytes)**: IEEE 802.3 CRC32 checksum computed over the preceding $14 + N$ bytes.

---

## 3. Abstract Transport Interface Requirements
Transports implement the following core operations:
- `StartListener(port / service_uuid)`: Binds local listening endpoint.
- `Connect(ip_address / bluetooth_mac)`: Establishes connection to remote peer.
- `SendFrame(message_type, payload)`: Encapsulates payload into frame, computes CRC32, and writes to channel.
- `OnFrameReceivedCallback`: Invoked on complete, verified frame reception.
- `Close()`: Teardown connection and clean up socket handles.
