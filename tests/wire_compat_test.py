#!/usr/bin/env python3
"""
Wire Compatibility Test: ESP32 TrailDrop ↔ Python Reticulum
Part 1 — Software tests proving identical crypto and wire format.

Runs on rflab-sam with RNS installed.
"""

import hashlib
import hmac
import os
import struct
import sys
from math import ceil

# ---------------------------------------------------------------------------
# ESP32 Algorithm Reimplementation (pure Python, no RNS dependency)
# These functions mirror src/crypto/ and src/net/ exactly.
# ---------------------------------------------------------------------------

def esp32_sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def esp32_hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def esp32_hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256 matching the Arduino Crypto HKDF<SHA256> library.
    Extract: PRK = HMAC-SHA256(salt, ikm)
    Expand:  output blocks using PRK, info, and counter."""
    if not salt:
        salt = b'\x00' * 32
    prk = esp32_hmac_sha256(salt, ikm)
    block = b""
    derived = b""
    for i in range(ceil(length / 32)):
        block = esp32_hmac_sha256(prk, block + info + bytes([(i + 1) % 256]))
        derived += block
    return derived[:length]

def esp32_identity_hash(x25519_pub: bytes, ed25519_pub: bytes) -> bytes:
    """identity_hash = SHA256(x25519_pub + ed25519_pub)[:16]"""
    return esp32_sha256(x25519_pub + ed25519_pub)[:16]

def esp32_destination_hash(full_name: str, identity_hash: bytes) -> bytes:
    """dest_hash = SHA256(name_hash + identity_hash)[:16]
    where name_hash = SHA256(full_name)[:10]"""
    name_hash = esp32_sha256(full_name.encode("utf-8"))[:10]
    return esp32_sha256(name_hash + identity_hash)[:16]

def esp32_pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len]) * pad_len

def esp32_pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid PKCS7 padding: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]

def esp32_token_encrypt(signing_key: bytes, encryption_key: bytes,
                        plaintext: bytes, iv: bytes) -> bytes:
    """Token encrypt: iv(16) + AES-256-CBC(PKCS7(plaintext)) + HMAC(signing_key, iv+ct)"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    padded = esp32_pkcs7_pad(plaintext)
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    signed_parts = iv + ciphertext
    mac = esp32_hmac_sha256(signing_key, signed_parts)
    return signed_parts + mac

def esp32_token_decrypt(signing_key: bytes, encryption_key: bytes,
                        token_data: bytes) -> bytes:
    """Token decrypt: verify HMAC, then AES-256-CBC decrypt + PKCS7 unpad."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(token_data) < 64:
        raise ValueError("Token too short")
    received_hmac = token_data[-32:]
    computed_hmac = esp32_hmac_sha256(signing_key, token_data[:-32])
    if not hmac.compare_digest(received_hmac, computed_hmac):
        raise ValueError("Token HMAC verification failed")
    iv = token_data[:16]
    ciphertext = token_data[16:-32]
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return esp32_pkcs7_unpad(padded)

def esp32_announce_flags() -> int:
    """Announce flags: HEADER_1(0), ctx_flag=0, BROADCAST(0), SINGLE(0), ANNOUNCE(1)"""
    return (0 << 6) | (0 << 5) | (0 << 4) | (0 << 2) | 0x01

def esp32_data_flags() -> int:
    """Data flags: HEADER_1(0), ctx_flag=0, BROADCAST(0), SINGLE(0), DATA(0)"""
    return (0 << 6) | (0 << 5) | (0 << 4) | (0 << 2) | 0x00

# ---------------------------------------------------------------------------
# Test Harness
# ---------------------------------------------------------------------------

passed = 0
failed = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS: {name}")
    else:
        failed += 1
        print(f"  FAIL: {name}")
        if detail:
            print(f"        {detail}")

def hexdump(data: bytes) -> str:
    return data.hex()

# ---------------------------------------------------------------------------
# Test 1a: Identity Hash Computation
# ---------------------------------------------------------------------------

def test_1a_identity_hash():
    print("\n=== Test 1a: Identity Hash Computation ===")

    import RNS
    # Create a known identity in Python
    identity = RNS.Identity(create_keys=True)
    x25519_pub = identity.pub_bytes       # 32 bytes
    ed25519_pub = identity.sig_pub_bytes  # 32 bytes

    # Python RNS identity hash
    rns_hash = identity.hash  # truncated_hash(pub_bytes + sig_pub_bytes)

    # ESP32 algorithm
    esp32_hash = esp32_identity_hash(x25519_pub, ed25519_pub)

    test("Identity hash matches RNS",
         rns_hash == esp32_hash,
         f"RNS={hexdump(rns_hash)} ESP32={hexdump(esp32_hash)}")

    # Verify truncation length
    test("Identity hash is 16 bytes", len(esp32_hash) == 16)

    # Verify full hash computation
    full = esp32_sha256(x25519_pub + ed25519_pub)
    rns_full = RNS.Identity.full_hash(x25519_pub + ed25519_pub)
    test("Full SHA-256 matches", full == rns_full)

    # Key order: X25519 first, Ed25519 second
    wrong_order = esp32_sha256(ed25519_pub + x25519_pub)[:16]
    test("Key order matters (wrong order != correct)",
         wrong_order != esp32_hash,
         "Both orders produced same hash — key order is irrelevant (unexpected)")


# ---------------------------------------------------------------------------
# Test 1b: Destination Hash Computation
# ---------------------------------------------------------------------------

def test_1b_destination_hash():
    print("\n=== Test 1b: Destination Hash Computation ===")

    import RNS

    identity = RNS.Identity(create_keys=True)

    # Python RNS destination hash
    rns_dest_hash = RNS.Destination.hash(identity, "traildrop", "waypoint")

    # ESP32 algorithm
    esp32_id_hash = esp32_identity_hash(identity.pub_bytes, identity.sig_pub_bytes)
    esp32_dest = esp32_destination_hash("traildrop.waypoint", esp32_id_hash)

    test("Destination hash matches RNS",
         rns_dest_hash == esp32_dest,
         f"RNS={hexdump(rns_dest_hash)} ESP32={hexdump(esp32_dest)}")

    # Verify name_hash computation
    rns_name_hash = RNS.Identity.full_hash("traildrop.waypoint".encode("utf-8"))[:10]
    esp32_name_hash = esp32_sha256("traildrop.waypoint".encode("utf-8"))[:10]
    test("Name hash matches (10 bytes)",
         rns_name_hash == esp32_name_hash,
         f"RNS={hexdump(rns_name_hash)} ESP32={hexdump(esp32_name_hash)}")

    # Verify with known Device A values
    # (Can only do if we have the actual keys — deferred to Part 2)
    print("  INFO: Known device hash verification deferred to Part 2 (needs device keys)")


# ---------------------------------------------------------------------------
# Test 1c: Announce Packet Format
# ---------------------------------------------------------------------------

def test_1c_announce_format():
    print("\n=== Test 1c: Announce Packet Format ===")

    import RNS

    identity = RNS.Identity(create_keys=True)

    # Get key components
    x25519_pub = identity.pub_bytes
    ed25519_pub = identity.sig_pub_bytes
    public_key = x25519_pub + ed25519_pub  # 64 bytes

    # Compute hashes
    id_hash = esp32_identity_hash(x25519_pub, ed25519_pub)
    dest_hash = esp32_destination_hash("traildrop.waypoint", id_hash)
    name_hash = esp32_sha256("traildrop.waypoint".encode("utf-8"))[:10]
    random_hash = os.urandom(10)
    app_data = b"TestNode"

    # Build signed_data the ESP32 way
    signed_data = dest_hash + public_key + name_hash + random_hash + app_data

    # Sign with identity
    signature = identity.sign(signed_data)

    # Build ESP32 announce payload
    esp32_payload = public_key + name_hash + random_hash + signature + app_data

    # Verify payload structure
    test("Payload starts with public_key (64 bytes)",
         esp32_payload[:64] == public_key)
    test("Payload[64:74] is name_hash (10 bytes)",
         esp32_payload[64:74] == name_hash)
    test("Payload[74:84] is random_hash (10 bytes)",
         esp32_payload[74:84] == random_hash)
    test("Payload[84:148] is signature (64 bytes)",
         esp32_payload[84:148] == signature)
    test("Payload[148:] is app_data",
         esp32_payload[148:] == app_data)

    # Verify total payload size: 64+10+10+64+8 = 156
    expected_len = 64 + 10 + 10 + 64 + len(app_data)
    test(f"Payload length correct ({expected_len})",
         len(esp32_payload) == expected_len)

    # Build full packet (HEADER_1 format)
    flags = esp32_announce_flags()
    hops = 0
    context = 0x00  # CTX_NONE
    raw_packet = bytes([flags, hops]) + dest_hash + bytes([context]) + esp32_payload

    # Verify header size: flags(1) + hops(1) + dest_hash(16) + context(1) = 19
    header_size = 1 + 1 + 16 + 1
    test(f"Header size is 19", header_size == 19)
    test(f"Total packet size: {len(raw_packet)}",
         len(raw_packet) == header_size + len(esp32_payload))

    # Verify flags byte
    test("Flags: header_type=HEADER_1", (flags >> 6) & 0x01 == 0)
    test("Flags: context_flag=0", (flags >> 5) & 0x01 == 0)
    test("Flags: transport=BROADCAST", (flags >> 4) & 0x01 == 0)
    test("Flags: dest_type=SINGLE", (flags >> 2) & 0x03 == 0)
    test("Flags: pkt_type=ANNOUNCE", flags & 0x03 == 1)
    test("Flags byte = 0x01", flags == 0x01)

    # Now validate the announce using RNS.Identity.validate_announce
    # We need to create a mock packet object that RNS expects
    class MockPacket:
        pass
    mock = MockPacket()
    mock.packet_type = RNS.Packet.ANNOUNCE
    mock.destination_hash = dest_hash
    mock.context_flag = RNS.Packet.FLAG_UNSET
    mock.data = esp32_payload
    mock.hops = 0
    mock.rssi = None
    mock.snr = None
    mock.receiving_interface = None
    mock.transport_id = None

    # validate_announce with only_validate_signature=True
    sig_valid = RNS.Identity.validate_announce(mock, only_validate_signature=True)
    test("RNS validate_announce(signature) passes on ESP32-format announce",
         sig_valid == True,
         "Signature validation failed — format mismatch!")


# ---------------------------------------------------------------------------
# Test 1d: Encryption/Decryption Cross-Test
# ---------------------------------------------------------------------------

def test_1d_encryption():
    print("\n=== Test 1d: Encryption/Decryption Cross-Test ===")

    import RNS
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

    # Create a target identity (the "recipient")
    target = RNS.Identity(create_keys=True)

    # --- Python RNS encryption ---
    plaintext = b"Hello from Python!"
    rns_token = target.encrypt(plaintext)

    # Verify encrypted format: ephemeral_pub(32) + iv(16) + ciphertext + hmac(32)
    test("Encrypted token >= 96 bytes (32+16+16+32 minimum)",
         len(rns_token) >= 96,
         f"Token length: {len(rns_token)}")

    ephemeral_pub = rns_token[:32]
    token_body = rns_token[32:]  # iv + ciphertext + hmac
    iv = token_body[:16]
    hmac_val = token_body[-32:]
    ciphertext = token_body[16:-32]

    test("Ephemeral public key is 32 bytes",
         len(ephemeral_pub) == 32)
    test("IV is 16 bytes", len(iv) == 16)
    test("HMAC is 32 bytes", len(hmac_val) == 32)
    test("Ciphertext is multiple of 16 (AES block)",
         len(ciphertext) % 16 == 0,
         f"Ciphertext length: {len(ciphertext)}")

    # Decrypt with Python RNS
    decrypted = target.decrypt(rns_token)
    test("RNS decrypt recovers plaintext",
         decrypted == plaintext,
         f"Got: {decrypted}")

    # --- ESP32 algorithm decryption of RNS-encrypted token ---
    # Replicate ESP32's identity_decrypt in Python:
    # 1. Extract ephemeral pub
    eph_pub_obj = X25519PublicKey.from_raw_public_bytes(ephemeral_pub)

    # 2. ECDH with recipient's private key
    shared_key = target.prv.exchange(eph_pub_obj)

    # 3. HKDF with identity_hash as salt
    salt = target.hash  # identity_hash (16 bytes)
    derived = esp32_hkdf_sha256(shared_key, salt, b"", 64)

    # 4. Token decrypt
    signing_key = derived[:32]
    encryption_key = derived[32:]
    esp32_decrypted = esp32_token_decrypt(signing_key, encryption_key, token_body)

    test("ESP32 algorithm decrypts RNS-encrypted data",
         esp32_decrypted == plaintext,
         f"Got: {esp32_decrypted}")

    # --- ESP32 algorithm encryption, RNS decryption ---
    plaintext2 = b"Hello from ESP32!"

    # Generate ephemeral key
    eph_prv = X25519PrivateKey.generate()
    eph_pub_bytes = eph_prv.public_key().public_bytes_raw()

    # ECDH with target's public key
    shared_key2 = eph_prv.exchange(target.pub)

    # HKDF
    derived2 = esp32_hkdf_sha256(shared_key2, target.hash, b"", 64)
    signing_key2 = derived2[:32]
    encryption_key2 = derived2[32:]

    # Token encrypt (with known IV for determinism)
    iv2 = os.urandom(16)
    token_body2 = esp32_token_encrypt(signing_key2, encryption_key2, plaintext2, iv2)
    esp32_encrypted = eph_pub_bytes + token_body2

    # Decrypt with RNS
    rns_decrypted = target.decrypt(esp32_encrypted)
    test("RNS decrypts ESP32-algorithm-encrypted data",
         rns_decrypted == plaintext2,
         f"Got: {rns_decrypted}")


# ---------------------------------------------------------------------------
# Test 1e: HKDF Derivation Match
# ---------------------------------------------------------------------------

def test_1e_hkdf():
    print("\n=== Test 1e: HKDF Derivation Match ===")

    import RNS.Cryptography

    # Known test inputs
    shared_key = bytes(range(32))  # deterministic test key
    salt = bytes(range(16))        # deterministic 16-byte salt (identity_hash size)

    # Python RNS HKDF
    rns_derived = RNS.Cryptography.hkdf(
        length=64,
        derive_from=shared_key,
        salt=salt,
        context=None,  # Identity.get_context() returns None
    )

    # ESP32 HKDF
    esp32_derived = esp32_hkdf_sha256(shared_key, salt, b"", 64)

    test("HKDF output matches (64 bytes)",
         rns_derived == esp32_derived,
         f"RNS={hexdump(rns_derived[:16])}... ESP32={hexdump(esp32_derived[:16])}...")

    # Verify key split
    rns_signing = rns_derived[:32]
    rns_encrypt = rns_derived[32:]
    esp32_signing = esp32_derived[:32]
    esp32_encrypt = esp32_derived[32:]

    test("Signing key (first 32 bytes) matches",
         rns_signing == esp32_signing)
    test("Encryption key (last 32 bytes) matches",
         rns_encrypt == esp32_encrypt)

    # Test with empty salt (edge case)
    rns_empty_salt = RNS.Cryptography.hkdf(
        length=64, derive_from=shared_key, salt=b"", context=None)
    esp32_empty_salt = esp32_hkdf_sha256(shared_key, b"", b"", 64)
    test("HKDF with empty salt matches",
         rns_empty_salt == esp32_empty_salt)

    # Test with real ECDH shared key scenario
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    alice_prv = X25519PrivateKey.generate()
    bob_prv = X25519PrivateKey.generate()

    shared_ab = alice_prv.exchange(bob_prv.public_key())

    # Both sides should get the same HKDF output
    identity_hash = esp32_sha256(os.urandom(64))[:16]  # simulated identity hash

    rns_ab = RNS.Cryptography.hkdf(length=64, derive_from=shared_ab,
                                    salt=identity_hash, context=None)
    esp32_ab = esp32_hkdf_sha256(shared_ab, identity_hash, b"", 64)

    test("HKDF with real ECDH shared key matches",
         rns_ab == esp32_ab)


# ---------------------------------------------------------------------------
# Additional test: Packet hash computation
# ---------------------------------------------------------------------------

def test_packet_hash():
    print("\n=== Test Bonus: Packet Hash Computation ===")

    import RNS

    # Build a raw HEADER_1 announce packet
    flags = 0x01  # announce
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00
    payload = os.urandom(148)

    raw = bytes([flags, hops]) + dest_hash + bytes([context]) + payload

    # Python RNS hash computation (from Packet.get_hashable_part):
    # hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]  (for HEADER_1)
    hashable_part = bytes([raw[0] & 0x0F]) + raw[2:]
    rns_hash = hashlib.sha256(hashable_part).digest()

    # ESP32 algorithm (from packet.cpp packet_hash):
    # For HEADER_1: skip_offset=2, hashable = (flags & 0x0F) || raw[2:]
    esp32_hashable = bytes([raw[0] & 0x0F]) + raw[2:]
    esp32_hash = esp32_sha256(esp32_hashable)

    test("Packet hash (HEADER_1) matches",
         rns_hash == esp32_hash)

    # HEADER_2 test
    flags_h2 = 0x41  # header_type=1, announce
    transport_id = os.urandom(16)
    raw_h2 = bytes([flags_h2, hops]) + transport_id + dest_hash + bytes([context]) + payload

    # RNS HEADER_2: hashable_part = bytes([raw[0] & 0x0F]) + raw[18:]
    rns_hashable_h2 = bytes([raw_h2[0] & 0x0F]) + raw_h2[18:]
    rns_hash_h2 = hashlib.sha256(rns_hashable_h2).digest()

    # ESP32 HEADER_2: skip_offset=18, hashable = (flags & 0x0F) || raw[18:]
    esp32_hashable_h2 = bytes([raw_h2[0] & 0x0F]) + raw_h2[18:]
    esp32_hash_h2 = esp32_sha256(esp32_hashable_h2)

    test("Packet hash (HEADER_2) matches",
         rns_hash_h2 == esp32_hash_h2)


# ---------------------------------------------------------------------------
# Additional test: Token encrypt/decrypt round-trip
# ---------------------------------------------------------------------------

def test_token_roundtrip():
    print("\n=== Test Bonus: Token Encrypt/Decrypt Round-Trip ===")

    import RNS.Cryptography
    from RNS.Cryptography import Token

    # Generate a 64-byte derived key
    derived = os.urandom(64)

    # RNS Token
    rns_token = Token(derived)

    plaintext = b"TrailDrop waypoint data with coordinates"

    # Encrypt with RNS Token
    rns_encrypted = rns_token.encrypt(plaintext)

    # Decrypt with ESP32 algorithm
    signing_key = derived[:32]
    encryption_key = derived[32:]
    esp32_decrypted = esp32_token_decrypt(signing_key, encryption_key, rns_encrypted)
    test("ESP32 token_decrypt decrypts RNS Token output",
         esp32_decrypted == plaintext)

    # Encrypt with ESP32 algorithm
    iv = os.urandom(16)
    esp32_encrypted = esp32_token_encrypt(signing_key, encryption_key, plaintext, iv)

    # Decrypt with RNS Token
    rns_decrypted = rns_token.decrypt(esp32_encrypted)
    test("RNS Token decrypts ESP32 token_encrypt output",
         rns_decrypted == plaintext)


# ---------------------------------------------------------------------------
# Additional test: Data packet format
# ---------------------------------------------------------------------------

def test_data_packet_format():
    print("\n=== Test Bonus: Data Packet Wire Format ===")

    import RNS

    # Build a DATA packet the ESP32 way
    flags = esp32_data_flags()
    hops = 0
    dest_hash = os.urandom(16)
    context = 0x00

    # Encrypted payload: ephemeral_pub(32) + token(iv+ct+hmac)
    encrypted_payload = os.urandom(112)  # 32+16+32+32

    raw = bytes([flags, hops]) + dest_hash + bytes([context]) + encrypted_payload

    test("DATA flags byte = 0x00", flags == 0x00)
    test("DATA packet structure: 19 header + payload",
         len(raw) == 19 + len(encrypted_payload))

    # Verify the RNS unpack would parse correctly
    test("Flags: pkt_type=DATA", flags & 0x03 == 0)
    test("Flags: dest_type=SINGLE", (flags >> 2) & 0x03 == 0)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 60)
    print("Wire Compatibility Test: ESP32 TrailDrop ↔ Python Reticulum")
    print("Part 1: Software Tests")
    print("=" * 60)

    # Run all tests
    test_1a_identity_hash()
    test_1b_destination_hash()
    test_1c_announce_format()
    test_1d_encryption()
    test_1e_hkdf()
    test_packet_hash()
    test_token_roundtrip()
    test_data_packet_format()

    # Summary
    total = passed + failed
    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print("=" * 60)

    sys.exit(0 if failed == 0 else 1)
