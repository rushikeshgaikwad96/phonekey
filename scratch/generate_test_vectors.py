import os
import json
import struct
import hashlib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization

def generate_vectors():
    os.makedirs("protocol/test-vectors", exist_ok=True)

    # Generate ECDSA P-256 Private Key
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Get DER Public Key
    pub_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Get Raw Uncompressed (X || Y) 64 bytes
    pub_numbers = public_key.public_numbers()
    x_bytes = pub_numbers.x.to_bytes(32, byteorder='big')
    y_bytes = pub_numbers.y.to_bytes(32, byteorder='big')
    raw_xy = x_bytes + y_bytes

    # Canonical Payload Fields
    domain = b"PhoneKey-Auth-v1"      # 16 Bytes
    protocol_version = 0x0100        # uint16 (2 Bytes)
    algorithm_id = 0x0001            # uint16 (2 Bytes)
    device_id = bytes.fromhex("11111111222233334444555555555555")
    session_id = bytes.fromhex("aaaaaaaa000011112222bbbbbbbbbbbb")
    pc_id = bytes.fromhex("99999999888877776666555555555555")
    challenge = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    expiration_ms = 1776182400000    # Unix timestamp ms

    # Pack 108-byte Canonical Payload
    payload = domain
    payload += struct.pack(">H", protocol_version)
    payload += struct.pack(">H", algorithm_id)
    payload += device_id
    payload += session_id
    payload += pc_id
    payload += challenge
    payload += struct.pack(">Q", expiration_ms)

    assert len(payload) == 108, f"Payload size {len(payload)} != 108"

    # Compute SHA-256 Digest
    digest = hashlib.sha256(payload).digest()

    # Sign Payload using ECDSA SHA-256 (ASN.1 DER signature)
    sig_der = private_key.sign(payload, ec.ECDSA(hashes.SHA256()))

    vector_valid = {
        "description": "Valid PhoneKey Auth Payload and ECDSA P-256 DER Signature",
        "domain": domain.hex(),
        "protocol_version": protocol_version,
        "algorithm_id": algorithm_id,
        "device_id": device_id.hex(),
        "session_id": session_id.hex(),
        "pc_id": pc_id.hex(),
        "challenge": challenge.hex(),
        "expiration_timestamp_ms": expiration_ms,
        "canonical_payload_hex": payload.hex(),
        "sha256_digest_hex": digest.hex(),
        "public_key_der_hex": pub_der.hex(),
        "public_key_raw_xy_hex": raw_xy.hex(),
        "signature_der_hex": sig_der.hex(),
        "expected_verification_result": True
    }

    with open("protocol/test-vectors/vector_valid.json", "w") as f:
        json.dump(vector_valid, f, indent=2)

    # Vector 2: Tampered Payload
    tampered_payload = bytearray(payload)
    tampered_payload[68] ^= 0xFF # Flip bit in challenge
    vector_tampered = dict(vector_valid)
    vector_tampered["description"] = "Tampered Challenge Payload (Bit-flip)"
    vector_tampered["canonical_payload_hex"] = bytes(tampered_payload).hex()
    vector_tampered["expected_verification_result"] = False

    with open("protocol/test-vectors/vector_tampered.json", "w") as f:
        json.dump(vector_tampered, f, indent=2)

    print("Successfully generated test vectors in protocol/test-vectors/")

if __name__ == "__main__":
    generate_vectors()
