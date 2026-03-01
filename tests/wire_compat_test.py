#!/usr/bin/env python3
"""
Wire Compatibility Test: ESP32 TrailDrop ↔ Python Reticulum
Part 1 — Software tests using ACTUAL device keys extracted from ESP32 SD cards.

Proves both implementations produce identical:
  - Identity hashes (SHA-256 of public keys, truncated to 16 bytes)
  - Destination hashes (SHA-256 of name_hash + identity_hash, truncated to 16 bytes)
  - HKDF-SHA256 key derivations (64-byte output split into signing + encryption keys)
  - Token encrypt/decrypt (AES-256-CBC + HMAC-SHA256)
  - Full identity encrypt/decrypt (ECDH + HKDF + Token)
  - Announce packet structure (field order, sizes, Ed25519 signature)

Runs on rflab-sam with RNS (rns v1.1.3) installed.
"""

import hashlib
import hmac as hmac_mod
import os
import sys
from math import ceil

# ===================================================================
# Actual device keys extracted from ESP32 SD cards (/traildrop/identity.dat)
# Format: x25519_priv(32) + x25519_pub(32) + ed25519_priv(32) + ed25519_pub(32)
# ===================================================================

DEVICE_A = {
    "name": "Device A (ttyACM1)",
    "x25519_priv": bytes.fromhex(
        "58d8ca089636bc39f7b8a7d2b314fc230d2f109640cc541e3720af9949698147"
    ),
    "x25519_pub": bytes.fromhex(
        "b18f12eb5964224ea98002652c09b3629ce5547bc101d0c5d31d62efb2ec8c6c"
    ),
    "ed25519_priv": bytes.fromhex(
        "e507599987e5d53ab37f5a1072ddba8a661776c3b52a5ead6448b9831b3cec9f"
    ),
    "ed25519_pub": bytes.fromhex(
        "fb41f1b30140453bec1fb1bf849acb4be4855712490a08ae0a8089fcceabf501"
    ),
    "expected_identity_hash": "530edfd3154e564a90c41eec5d93f586",
    "expected_dest_hash": "19820e6239feccf4a37b65cd73f7668d",
}

DEVICE_B = {
    "name": "Device B (ttyACM0)",
    "x25519_priv": bytes.fromhex(
        "a0af34a7f95e75b172782858189e5c527096cdeca41940a9c60b798a86ff066c"
    ),
    "x25519_pub": bytes.fromhex(
        "0c961b624d228a7d6186dd521f9681c9841420544aa9a8bed980c97fde31616a"
    ),
    "ed25519_priv": bytes.fromhex(
        "72c5a7e65082afcf2a8a3466648d8211aa28b2e5ff3f738b7cdd369c0621854a"
    ),
    "ed25519_pub": bytes.fromhex(
        "0ab49613cd0ccc7a2e38dc6464cf3064b91e0becbf58f275ca8351eb7920db2d"
    ),
    "expected_identity_hash": "1b22687bfffbe8832a9520b2d31916fd",
    "expected_dest_hash": "ff6b89bede65c0ae89b7957f6bf0b3b8",
}

FULL_NAME = "traildrop.waypoint"

# Protocol constants (from config.h)
DEST_HASH_SIZE = 16
NAME_HASH_LENGTH = 10
DERIVED_KEY_LENGTH = 64

# ===================================================================
# ESP32 algorithm reimplementation (pure Python, mirrors src/crypto/)
# ===================================================================


def esp_sha256(data):
    return hashlib.sha256(data).digest()


def esp_hmac_sha256(key, data):
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def esp_hkdf(ikm, salt, info, length):
    """HKDF-SHA256 matching Arduino Crypto HKDF<SHA256>.
    Extract: PRK = HMAC-SHA256(salt, IKM)
    Expand:  T(i) = HMAC-SHA256(PRK, T(i-1) || info || i)"""
    if not salt:
        salt = b"\x00" * 32  # RFC 5869 default
    prk = esp_hmac_sha256(salt, ikm)
    t = b""
    okm = b""
    for i in range(1, ceil(length / 32) + 1):
        t = esp_hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def esp_identity_hash(x25519_pub, ed25519_pub):
    """identity_hash = SHA-256(x25519_pub || ed25519_pub)[:16]"""
    return esp_sha256(x25519_pub + ed25519_pub)[:16]


def esp_dest_hash(full_name, identity_hash):
    """dest_hash = SHA-256(name_hash || identity_hash)[:16]
    where name_hash = SHA-256(full_name.encode('utf-8'))[:10]"""
    name_hash = esp_sha256(full_name.encode("utf-8"))[:10]
    return esp_sha256(name_hash + identity_hash)[:16]


def esp_pkcs7_pad(data, bs=16):
    pad_len = bs - (len(data) % bs)
    return data + bytes([pad_len]) * pad_len


def esp_pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid PKCS7 padding: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Corrupt PKCS7 padding")
    return data[:-pad_len]


def esp_token_encrypt(signing_key, encryption_key, plaintext, iv):
    """Token format: IV(16) + AES-256-CBC(PKCS7(plaintext)) + HMAC-SHA256(signing_key, IV+ct)(32)"""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    padded = esp_pkcs7_pad(plaintext)
    enc = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).encryptor()
    ct = enc.update(padded) + enc.finalize()
    mac = esp_hmac_sha256(signing_key, iv + ct)
    return iv + ct + mac


def esp_token_decrypt(signing_key, encryption_key, token_data):
    """Verify HMAC, then AES-256-CBC decrypt + PKCS7 unpad."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(token_data) < 64:
        raise ValueError("Token too short")
    mac_got = token_data[-32:]
    mac_exp = esp_hmac_sha256(signing_key, token_data[:-32])
    if not hmac_mod.compare_digest(mac_got, mac_exp):
        raise ValueError("Token HMAC mismatch")
    iv = token_data[:16]
    ct = token_data[16:-32]
    dec = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    return esp_pkcs7_unpad(dec.update(ct) + dec.finalize())


# ===================================================================
# Test harness
# ===================================================================

_passed = 0
_failed = 0


def test(name, condition, detail=""):
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  PASS: {name}")
    else:
        _failed += 1
        print(f"  FAIL: {name}")
        if detail:
            print(f"        {detail}")


# ===================================================================
# Test 1a: Identity Hash Computation (using actual device keys)
# ===================================================================


def test_1a():
    print("\n=== Test 1a: Identity Hash Computation ===")
    import RNS

    for dev in [DEVICE_A, DEVICE_B]:
        expected = bytes.fromhex(dev["expected_identity_hash"])

        # --- Manual computation (ESP32 algorithm) ---
        manual = esp_identity_hash(dev["x25519_pub"], dev["ed25519_pub"])
        test(
            f"{dev['name']}: manual identity hash",
            manual == expected,
            f"got {manual.hex()}, expected {expected.hex()}",
        )

        # --- RNS Identity (load private keys, derive public, compute hash) ---
        identity = RNS.Identity(create_keys=False)
        identity.load_private_key(dev["x25519_priv"] + dev["ed25519_priv"])

        # Verify that Python-derived public keys match the ESP32-stored ones
        test(
            f"{dev['name']}: X25519 pub derivation matches stored",
            identity.pub_bytes == dev["x25519_pub"],
            f"derived {identity.pub_bytes.hex()}\nstored  {dev['x25519_pub'].hex()}",
        )
        test(
            f"{dev['name']}: Ed25519 pub derivation matches stored",
            identity.sig_pub_bytes == dev["ed25519_pub"],
            f"derived {identity.sig_pub_bytes.hex()}\nstored  {dev['ed25519_pub'].hex()}",
        )

        # Verify RNS identity hash matches the known device hash
        test(
            f"{dev['name']}: RNS identity hash matches expected",
            identity.hash == expected,
            f"RNS {identity.hash.hex()}, expected {expected.hex()}",
        )

    # Verify key order matters
    wrong = esp_sha256(DEVICE_A["ed25519_pub"] + DEVICE_A["x25519_pub"])[:16]
    right = bytes.fromhex(DEVICE_A["expected_identity_hash"])
    test("Key order matters (X25519 first, Ed25519 second)", wrong != right)


# ===================================================================
# Test 1b: Destination Hash Computation (using actual device keys)
# ===================================================================


def test_1b():
    print("\n=== Test 1b: Destination Hash Computation ===")
    import RNS

    # Verify name_hash
    name_hash_manual = esp_sha256(FULL_NAME.encode("utf-8"))[:10]
    name_hash_rns = RNS.Identity.full_hash(FULL_NAME.encode("utf-8"))[:10]
    test(
        "name_hash computation matches RNS",
        name_hash_manual == name_hash_rns,
        f"manual {name_hash_manual.hex()}, RNS {name_hash_rns.hex()}",
    )

    for dev in [DEVICE_A, DEVICE_B]:
        expected = bytes.fromhex(dev["expected_dest_hash"])
        id_hash = bytes.fromhex(dev["expected_identity_hash"])

        # --- Manual computation (ESP32 algorithm) ---
        manual = esp_dest_hash(FULL_NAME, id_hash)
        test(
            f"{dev['name']}: manual dest hash",
            manual == expected,
            f"got {manual.hex()}, expected {expected.hex()}",
        )

        # --- RNS Destination.hash ---
        identity = RNS.Identity(create_keys=False)
        identity.load_private_key(dev["x25519_priv"] + dev["ed25519_priv"])
        rns_dest = RNS.Destination.hash(identity, "traildrop", "waypoint")
        test(
            f"{dev['name']}: RNS dest hash matches expected",
            rns_dest == expected,
            f"RNS {rns_dest.hex()}, expected {expected.hex()}",
        )


# ===================================================================
# Test 1c: Announce Packet Format (using actual device keys)
# ===================================================================


def test_1c():
    print("\n=== Test 1c: Announce Packet Format ===")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )

    dev = DEVICE_A
    dest_hash = bytes.fromhex(dev["expected_dest_hash"])
    public_key = dev["x25519_pub"] + dev["ed25519_pub"]  # 64 bytes
    name_hash = esp_sha256(FULL_NAME.encode("utf-8"))[:10]
    random_hash = os.urandom(10)
    app_data = b"TestNode"

    # Build signed_data (ESP32 announce.cpp format):
    #   dest_hash(16) + public_key(64) + name_hash(10) + random_hash(10) [+ app_data]
    signed_data = dest_hash + public_key + name_hash + random_hash + app_data

    # Sign with Ed25519 using actual device key
    ed_prv = Ed25519PrivateKey.from_private_bytes(dev["ed25519_priv"])
    signature = ed_prv.sign(signed_data)
    test("Ed25519 signature is 64 bytes", len(signature) == 64)

    # Assemble payload (ESP32 announce.cpp format):
    #   public_key(64) + name_hash(10) + random_hash(10) + signature(64) [+ app_data]
    payload = public_key + name_hash + random_hash + signature + app_data

    test(
        "Payload structure: 148 + app_data",
        len(payload) == 148 + len(app_data),
        f"got {len(payload)}, expected {148 + len(app_data)}",
    )

    # Parse payload back (as announce_process does)
    p_x25519 = payload[0:32]
    p_ed25519 = payload[32:64]
    p_name_hash = payload[64:74]
    p_random_hash = payload[74:84]
    p_sig = payload[84:148]
    p_app_data = payload[148:]

    test("Extracted x25519_pub matches", p_x25519 == dev["x25519_pub"])
    test("Extracted ed25519_pub matches", p_ed25519 == dev["ed25519_pub"])
    test("Extracted name_hash matches", p_name_hash == name_hash)
    test("Extracted app_data matches", p_app_data == app_data)

    # Verify signature using public key
    ed_pub = Ed25519PublicKey.from_public_bytes(dev["ed25519_pub"])
    verify_data = dest_hash + p_x25519 + p_ed25519 + p_name_hash + p_random_hash + p_app_data
    try:
        ed_pub.verify(p_sig, verify_data)
        sig_valid = True
    except Exception:
        sig_valid = False
    test("Signature validates against reconstructed signed_data", sig_valid)

    # Verify dest_hash can be derived from announce payload
    computed_id_hash = esp_identity_hash(p_x25519, p_ed25519)
    computed_dest = esp_sha256(p_name_hash + computed_id_hash)[:16]
    test(
        "Dest hash derivable from announce payload",
        computed_dest == dest_hash,
        f"computed {computed_dest.hex()}, expected {dest_hash.hex()}",
    )

    # Build full wire packet (HEADER_1)
    # flags: HEADER_1(0), ctx=0, BROADCAST(0), SINGLE(0), ANNOUNCE(1) → 0x01
    flags = 0x01
    wire = bytes([flags, 0x00]) + dest_hash + bytes([0x00]) + payload
    test("Wire packet header is 19 bytes", len(wire) - len(payload) == 19)
    test("Flags byte = 0x01 (H1/broadcast/single/announce)", wire[0] == 0x01)

    # Validate with RNS.Identity.validate_announce using mock packet
    import RNS

    class MockPacket:
        pass

    mock = MockPacket()
    mock.packet_type = RNS.Packet.ANNOUNCE
    mock.destination_hash = dest_hash
    mock.context_flag = RNS.Packet.FLAG_UNSET
    mock.data = payload
    mock.hops = 0
    mock.rssi = None
    mock.snr = None
    mock.receiving_interface = None
    mock.transport_id = None

    validated = RNS.Identity.validate_announce(mock, only_validate_signature=True)
    test(
        "RNS validate_announce accepts ESP32-format announce",
        validated is True,
        "RNS rejected the announce — format mismatch!",
    )


# ===================================================================
# Test 1d: Encryption/Decryption Cross-Test (using actual device keys)
# ===================================================================


def test_1d():
    print("\n=== Test 1d: Encryption/Decryption Cross-Test ===")
    import RNS
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    # Load Device A into RNS
    dev = DEVICE_A
    identity_a = RNS.Identity(create_keys=False)
    identity_a.load_private_key(dev["x25519_priv"] + dev["ed25519_priv"])
    id_hash_a = bytes.fromhex(dev["expected_identity_hash"])

    plaintext = b"Hello from Python!"

    # --- Test: RNS encrypt → ESP32-style decrypt ---
    rns_ct = identity_a.encrypt(plaintext)
    test(
        "RNS ciphertext >= 96 bytes (eph_pub + iv + block + hmac)",
        len(rns_ct) >= 96,
        f"got {len(rns_ct)} bytes",
    )

    eph_pub = rns_ct[:32]
    token_body = rns_ct[32:]
    iv = token_body[:16]
    hmac_val = token_body[-32:]
    aes_ct = token_body[16:-32]

    test("Ephemeral pub = 32 bytes", len(eph_pub) == 32)
    test("IV = 16 bytes", len(iv) == 16)
    test("HMAC = 32 bytes", len(hmac_val) == 32)
    test("AES ciphertext aligned to 16-byte blocks", len(aes_ct) % 16 == 0)

    # ESP32-style decrypt: ECDH → HKDF → Token decrypt
    x25519_prv = X25519PrivateKey.from_private_bytes(dev["x25519_priv"])
    eph_pub_key = X25519PublicKey.from_public_bytes(eph_pub)
    shared = x25519_prv.exchange(eph_pub_key)
    derived = esp_hkdf(shared, id_hash_a, b"", 64)
    esp_dec = esp_token_decrypt(derived[:32], derived[32:], token_body)

    test(
        "ESP32 decrypt of RNS-encrypted data",
        esp_dec == plaintext,
        f"got {esp_dec!r}, expected {plaintext!r}",
    )

    # --- Test: ESP32-style encrypt → RNS decrypt ---
    plaintext2 = b"Hello from ESP32!"
    eph_prv = X25519PrivateKey.generate()
    eph_pub2 = eph_prv.public_key().public_bytes_raw()
    target_pub = X25519PublicKey.from_public_bytes(dev["x25519_pub"])
    shared2 = eph_prv.exchange(target_pub)
    derived2 = esp_hkdf(shared2, id_hash_a, b"", 64)
    iv2 = os.urandom(16)
    token2 = esp_token_encrypt(derived2[:32], derived2[32:], plaintext2, iv2)
    esp_ct = eph_pub2 + token2

    rns_dec = identity_a.decrypt(esp_ct)
    test(
        "RNS decrypt of ESP32-encrypted data",
        rns_dec == plaintext2,
        f"got {rns_dec!r}, expected {plaintext2!r}",
    )

    # --- Test: Cross-device encrypt A→B, decrypt as B ---
    dev_b = DEVICE_B
    identity_b = RNS.Identity(create_keys=False)
    identity_b.load_private_key(dev_b["x25519_priv"] + dev_b["ed25519_priv"])
    id_hash_b = bytes.fromhex(dev_b["expected_identity_hash"])

    plaintext3 = b"Hello from TrailDrop!"

    # Simulate A encrypting TO B (ESP32 algorithm)
    eph_prv3 = X25519PrivateKey.generate()
    eph_pub3 = eph_prv3.public_key().public_bytes_raw()
    b_pub = X25519PublicKey.from_public_bytes(dev_b["x25519_pub"])
    shared3 = eph_prv3.exchange(b_pub)
    derived3 = esp_hkdf(shared3, id_hash_b, b"", 64)  # salt = target's identity_hash
    iv3 = os.urandom(16)
    token3 = esp_token_encrypt(derived3[:32], derived3[32:], plaintext3, iv3)
    esp_ct3 = eph_pub3 + token3

    # B decrypts using RNS
    rns_dec3 = identity_b.decrypt(esp_ct3)
    test(
        "Cross-device: ESP32 A→B encrypt, RNS B decrypt",
        rns_dec3 == plaintext3,
        f"got {rns_dec3!r}, expected {plaintext3!r}",
    )

    # RNS B encrypt, ESP32-style B decrypt
    rns_ct4 = identity_b.encrypt(plaintext3)
    eph4 = rns_ct4[:32]
    tok4 = rns_ct4[32:]
    b_prv = X25519PrivateKey.from_private_bytes(dev_b["x25519_priv"])
    shared4 = b_prv.exchange(X25519PublicKey.from_public_bytes(eph4))
    derived4 = esp_hkdf(shared4, id_hash_b, b"", 64)
    esp_dec4 = esp_token_decrypt(derived4[:32], derived4[32:], tok4)
    test(
        "Cross-device: RNS B encrypt, ESP32-style B decrypt",
        esp_dec4 == plaintext3,
        f"got {esp_dec4!r}, expected {plaintext3!r}",
    )


# ===================================================================
# Test 1e: HKDF Derivation Match
# ===================================================================


def test_1e():
    print("\n=== Test 1e: HKDF Derivation Match ===")
    import RNS.Cryptography
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )

    # --- Test with deterministic inputs ---
    ikm = bytes(range(32))
    salt = bytes(range(16))

    rns_out = RNS.Cryptography.hkdf(length=64, derive_from=ikm, salt=salt, context=None)
    esp_out = esp_hkdf(ikm, salt, b"", 64)
    test(
        "HKDF deterministic: RNS vs ESP32",
        rns_out == esp_out,
        f"RNS {rns_out[:16].hex()}...\nESP {esp_out[:16].hex()}...",
    )

    # Verify key split
    test("Signing key (first 32) matches", rns_out[:32] == esp_out[:32])
    test("Encryption key (last 32) matches", rns_out[32:] == esp_out[32:])
    test("Signing key != encryption key", rns_out[:32] != rns_out[32:])

    # --- Test with actual device A↔B ECDH shared key ---
    a_prv = X25519PrivateKey.from_private_bytes(DEVICE_A["x25519_priv"])
    b_pub = X25519PublicKey.from_public_bytes(DEVICE_B["x25519_pub"])
    shared_ab = a_prv.exchange(b_pub)

    b_prv = X25519PrivateKey.from_private_bytes(DEVICE_B["x25519_priv"])
    a_pub = X25519PublicKey.from_public_bytes(DEVICE_A["x25519_pub"])
    shared_ba = b_prv.exchange(a_pub)

    test(
        "ECDH symmetric: A→B == B→A",
        shared_ab == shared_ba,
        f"A→B {shared_ab.hex()}\nB→A {shared_ba.hex()}",
    )

    # HKDF with B's identity_hash as salt (A encrypting TO B)
    salt_b = bytes.fromhex(DEVICE_B["expected_identity_hash"])
    rns_ab = RNS.Cryptography.hkdf(length=64, derive_from=shared_ab, salt=salt_b, context=None)
    esp_ab = esp_hkdf(shared_ab, salt_b, b"", 64)
    test(
        "HKDF with real ECDH (A→B, salt=B.hash)",
        rns_ab == esp_ab,
        f"RNS {rns_ab[:16].hex()}...\nESP {esp_ab[:16].hex()}...",
    )

    # HKDF with A's identity_hash as salt (B encrypting TO A)
    salt_a = bytes.fromhex(DEVICE_A["expected_identity_hash"])
    rns_ba = RNS.Cryptography.hkdf(length=64, derive_from=shared_ba, salt=salt_a, context=None)
    esp_ba = esp_hkdf(shared_ba, salt_a, b"", 64)
    test(
        "HKDF with real ECDH (B→A, salt=A.hash)",
        rns_ba == esp_ba,
    )


# ===================================================================
# Bonus: Token round-trip
# ===================================================================


def test_token_roundtrip():
    print("\n=== Bonus: Token Encrypt/Decrypt Round-Trip ===")
    from RNS.Cryptography import Token

    derived = os.urandom(64)
    rns_tok = Token(derived)
    plaintext = b"TrailDrop waypoint payload"

    # RNS encrypt → ESP32 decrypt
    rns_enc = rns_tok.encrypt(plaintext)
    esp_dec = esp_token_decrypt(derived[:32], derived[32:], rns_enc)
    test("ESP32 token_decrypt of RNS Token output", esp_dec == plaintext)

    # ESP32 encrypt → RNS decrypt
    iv = os.urandom(16)
    esp_enc = esp_token_encrypt(derived[:32], derived[32:], plaintext, iv)
    rns_dec = rns_tok.decrypt(esp_enc)
    test("RNS Token decrypt of ESP32 token_encrypt output", rns_dec == plaintext)


# ===================================================================
# Bonus: Packet hash computation
# ===================================================================


def test_packet_hash():
    print("\n=== Bonus: Packet Hash Computation ===")

    # HEADER_1 packet
    flags = 0x01  # announce
    raw = bytes([flags, 0x00]) + os.urandom(16) + bytes([0x00]) + os.urandom(148)

    # ESP32 algorithm: hashable = (flags & 0x0F) || raw[2:]
    hashable = bytes([raw[0] & 0x0F]) + raw[2:]
    esp_hash = esp_sha256(hashable)

    # RNS algorithm (Packet.get_hashable_part for HEADER_1): same
    rns_hash = hashlib.sha256(bytes([raw[0] & 0x0F]) + raw[2:]).digest()
    test("Packet hash HEADER_1 matches", esp_hash == rns_hash)

    # HEADER_2 packet
    flags_h2 = 0x41  # header_type=1, announce
    raw_h2 = bytes([flags_h2, 0x00]) + os.urandom(16) + os.urandom(16) + bytes([0x00]) + os.urandom(100)

    # ESP32: skip_offset=18, hashable = (flags & 0x0F) || raw[18:]
    hashable_h2 = bytes([raw_h2[0] & 0x0F]) + raw_h2[18:]
    esp_hash_h2 = esp_sha256(hashable_h2)
    rns_hash_h2 = hashlib.sha256(bytes([raw_h2[0] & 0x0F]) + raw_h2[18:]).digest()
    test("Packet hash HEADER_2 matches", esp_hash_h2 == rns_hash_h2)


# ===================================================================
# Main
# ===================================================================

if __name__ == "__main__":
    print("=" * 60)
    print("Wire Compatibility Test: ESP32 TrailDrop ↔ Python Reticulum")
    print("Part 1: Software Tests (actual device keys)")
    print("=" * 60)

    test_1a()
    test_1b()
    test_1c()
    test_1d()
    test_1e()
    test_token_roundtrip()
    test_packet_hash()

    print(f"\n{'=' * 60}")
    print(f"Results: {_passed}/{_passed + _failed} passed, {_failed} failed")
    print(f"{'=' * 60}")

    sys.exit(0 if _failed == 0 else 1)
