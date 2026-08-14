import os
import json
import struct
import hashlib
import hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

def generate_pairing_vectors():
    os.makedirs("protocol/test-vectors", exist_ok=True)

    # 1. Generate Ephemeral ECDH Keypairs for PC and Phone
    pc_ecdh_priv = ec.generate_private_key(ec.SECP256R1())
    pc_ecdh_pub = pc_ecdh_priv.public_key()

    phone_ecdh_priv = ec.generate_private_key(ec.SECP256R1())
    phone_ecdh_pub = phone_ecdh_priv.public_key()

    # Get raw uncompressed (0x04 || X || Y) 65 bytes
    pc_pub_bytes = pc_ecdh_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    phone_pub_bytes = phone_ecdh_pub.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    session_id = bytes.fromhex("aaaaaaaa000011112222bbbbbbbbbbbb")

    # 2. Compute Shared Secret S
    s_pc = pc_ecdh_priv.exchange(ec.ECDH(), phone_ecdh_pub)
    s_phone = phone_ecdh_priv.exchange(ec.ECDH(), pc_ecdh_pub)
    assert s_pc == s_phone, "ECDH shared secrets must match!"

    shared_secret = s_pc

    # 3. Derive K_enc and K_sas via HKDF-SHA256
    hkdf_enc = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id,
        info=b"PhoneKey-Pairing-Enc"
    )
    k_enc = hkdf_enc.derive(shared_secret)

    hkdf_sas = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=session_id,
        info=b"PhoneKey-Pairing-SAS"
    )
    k_sas = hkdf_sas.derive(shared_secret)

    # 4. Compute 6-Digit SAS PIN
    sas_mac = hmac.new(k_sas, b"PhoneKey-SAS-PIN", hashlib.sha256).digest()
    val32 = struct.unpack(">I", sas_mac[:4])[0]
    sas_pin_num = (val32 % 900000) + 100000
    sas_pin_str = f"{sas_pin_num:06d}"

    vector = {
        "description": "PhoneKey Milestone 3 Out-of-Band Pairing Test Vector",
        "session_id_hex": session_id.hex(),
        "pc_ecdh_pub_hex": pc_pub_bytes.hex(),
        "phone_ecdh_pub_hex": phone_pub_bytes.hex(),
        "shared_secret_hex": shared_secret.hex(),
        "k_enc_hex": k_enc.hex(),
        "k_sas_hex": k_sas.hex(),
        "expected_sas_pin": sas_pin_str
    }

    with open("protocol/test-vectors/vector_pairing_valid.json", "w") as f:
        json.dump(vector, f, indent=2)

    print(f"Successfully generated pairing test vector: SAS PIN = {sas_pin_str}")

if __name__ == "__main__":
    generate_pairing_vectors()
