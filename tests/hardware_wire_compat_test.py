#!/usr/bin/env python3
"""
Wire Compatibility Test: ESP32 TrailDrop ↔ Python Reticulum
Part 2 — Hardware capture tests.

Captures raw packets from ESP32 devices over serial, parses and
verifies them against Python Reticulum.

Devices:
  Device A: /dev/ttyACM1 (identity hash 530edfd3...)
  Device B: /dev/ttyACM0 (identity hash 1b22687b...)

Flow:
  1. Reset both devices via DTR
  2. Both devices send boot announces
  3. Device B receives Device A's announce (and vice versa)
  4. After 30s, auto-send triggers: Device sends "Hello from TrailDrop!"
  5. Capture [TX_HEX] and [RX_HEX] lines, parse, and verify
"""

import hashlib
import hmac
import os
import re
import serial
import struct
import sys
import time
from math import ceil

# ---------------------------------------------------------------------------
# ESP32 Algorithm Reimplementation (same as Part 1)
# ---------------------------------------------------------------------------

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not salt:
        salt = b'\x00' * 32
    prk = hmac_sha256(salt, ikm)
    block = b""
    derived = b""
    for i in range(ceil(length / 32)):
        block = hmac_sha256(prk, block + info + bytes([(i + 1) % 256]))
        derived += block
    return derived[:length]

def pkcs7_unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid PKCS7 padding: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid PKCS7 padding bytes")
    return data[:-pad_len]

def token_decrypt(signing_key: bytes, encryption_key: bytes,
                  token_data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(token_data) < 64:
        raise ValueError("Token too short")
    received_hmac = token_data[-32:]
    computed_hmac = hmac_sha256(signing_key, token_data[:-32])
    if not hmac.compare_digest(received_hmac, computed_hmac):
        raise ValueError("Token HMAC verification failed")
    iv = token_data[:16]
    ciphertext = token_data[16:-32]
    cipher = Cipher(algorithms.AES(encryption_key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    return pkcs7_unpad(padded)

# ---------------------------------------------------------------------------
# Known device values
# ---------------------------------------------------------------------------

DEVICE_A_PORT = "/dev/ttyACM1"
DEVICE_B_PORT = "/dev/ttyACM0"
BAUD = 115200

DEVICE_A_ID_HASH = bytes.fromhex("530edfd3154e564a90c41eec5d93f586")
DEVICE_A_DEST_HASH = bytes.fromhex("19820e6239feccf4a37b65cd73f7668d")
DEVICE_B_ID_HASH = bytes.fromhex("1b22687bfffbe8832a9520b2d31916fd")
DEVICE_B_DEST_HASH = bytes.fromhex("ff6b89bede65c0ae89b7957f6bf0b3b8")

APP_FULL_NAME = "traildrop.waypoint"
NAME_HASH = sha256(APP_FULL_NAME.encode("utf-8"))[:10]

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
# Serial helpers
# ---------------------------------------------------------------------------

def open_serial(port, baud=BAUD, timeout=1):
    """Open serial port."""
    ser = serial.Serial(port, baud, timeout=timeout)
    return ser

def reset_device(ser):
    """Reset device via DTR toggle."""
    ser.dtr = False
    time.sleep(0.1)
    ser.dtr = True
    time.sleep(0.1)
    ser.dtr = False
    ser.reset_input_buffer()

def read_lines_until(ser, pattern, timeout=120, collect_all=True):
    """Read serial lines until pattern is found or timeout.
    Returns (matching_line, all_lines)."""
    start = time.time()
    lines = []
    while time.time() - start < timeout:
        try:
            line = ser.readline().decode("utf-8", errors="replace").strip()
        except Exception:
            continue
        if line:
            lines.append(line)
            if pattern in line:
                return line, lines
    return None, lines

def collect_hex_lines(ser, prefix, timeout=10, max_lines=10):
    """Collect lines matching prefix (e.g. [TX_HEX] or [RX_HEX])."""
    start = time.time()
    results = []
    while time.time() - start < timeout and len(results) < max_lines:
        try:
            line = ser.readline().decode("utf-8", errors="replace").strip()
        except Exception:
            continue
        if line and prefix in line:
            hex_data = line.split(prefix)[-1].strip()
            results.append(hex_data)
    return results

def drain_and_collect(ser, timeout=5):
    """Read all available lines for a period, return them."""
    start = time.time()
    lines = []
    while time.time() - start < timeout:
        try:
            line = ser.readline().decode("utf-8", errors="replace").strip()
        except Exception:
            continue
        if line:
            lines.append(line)
    return lines

# ---------------------------------------------------------------------------
# Parse announce packet from raw hex
# ---------------------------------------------------------------------------

def parse_announce(raw_hex):
    """Parse a raw announce packet, return dict of fields or None."""
    raw = bytes.fromhex(raw_hex)
    if len(raw) < 19 + 148:  # min header + min announce payload
        return None

    flags = raw[0]
    hops = raw[1]
    pkt_type = flags & 0x03
    if pkt_type != 0x01:  # Not an announce
        return None

    header_type = (flags >> 6) & 0x01
    if header_type == 0:  # HEADER_1
        dest_hash = raw[2:18]
        context = raw[18]
        payload = raw[19:]
    else:  # HEADER_2
        transport_id = raw[2:18]
        dest_hash = raw[18:34]
        context = raw[34]
        payload = raw[35:]

    if len(payload) < 148:
        return None

    x25519_pub = payload[0:32]
    ed25519_pub = payload[32:64]
    name_hash = payload[64:74]
    random_hash = payload[74:84]
    signature = payload[84:148]
    app_data = payload[148:] if len(payload) > 148 else b""

    # Compute identity hash
    identity_hash = sha256(x25519_pub + ed25519_pub)[:16]

    # Compute expected dest hash
    expected_dest = sha256(name_hash + identity_hash)[:16]

    return {
        "flags": flags,
        "hops": hops,
        "dest_hash": dest_hash,
        "context": context,
        "x25519_pub": x25519_pub,
        "ed25519_pub": ed25519_pub,
        "name_hash": name_hash,
        "random_hash": random_hash,
        "signature": signature,
        "app_data": app_data,
        "identity_hash": identity_hash,
        "expected_dest": expected_dest,
        "raw": raw,
    }

# ---------------------------------------------------------------------------
# Verify announce signature using RNS
# ---------------------------------------------------------------------------

def verify_announce_signature(announce):
    """Use RNS.Identity to verify the announce signature."""
    import RNS

    # Build signed_data: dest_hash + public_key + name_hash + random_hash + app_data
    signed_data = (announce["dest_hash"] +
                   announce["x25519_pub"] + announce["ed25519_pub"] +
                   announce["name_hash"] + announce["random_hash"] +
                   announce["app_data"])

    # Load identity from public keys
    identity = RNS.Identity(create_keys=False)
    identity.load_public_key(announce["x25519_pub"] + announce["ed25519_pub"])

    return identity.validate(announce["signature"], signed_data)

# ---------------------------------------------------------------------------
# Parse data packet from raw hex
# ---------------------------------------------------------------------------

def parse_data_packet(raw_hex):
    """Parse a raw DATA packet."""
    raw = bytes.fromhex(raw_hex)
    if len(raw) < 19:
        return None

    flags = raw[0]
    pkt_type = flags & 0x03
    if pkt_type != 0x00:  # Not DATA
        return None

    dest_hash = raw[2:18]
    context = raw[18]
    payload = raw[19:]

    return {
        "flags": flags,
        "dest_hash": dest_hash,
        "context": context,
        "encrypted_payload": payload,
        "raw": raw,
    }

# ---------------------------------------------------------------------------
# Decrypt data packet using known identity
# ---------------------------------------------------------------------------

def decrypt_data_with_identity(encrypted_payload, receiver_prv_bytes, receiver_id_hash):
    """Decrypt a data packet using the receiver's identity.
    receiver_prv_bytes = x25519_private(32) + ed25519_private(32) from identity file."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey,
    )

    if len(encrypted_payload) < 96:  # 32 eph + 16 iv + 16 ct + 32 hmac
        raise ValueError(f"Payload too short: {len(encrypted_payload)}")

    # Extract ephemeral public key (first 32 bytes)
    eph_pub_bytes = encrypted_payload[:32]
    token_body = encrypted_payload[32:]

    # ECDH
    x25519_prv = X25519PrivateKey.from_private_bytes(receiver_prv_bytes[:32])
    eph_pub = X25519PublicKey.from_public_bytes(eph_pub_bytes)
    shared_key = x25519_prv.exchange(eph_pub)

    # HKDF with identity_hash as salt
    derived = hkdf_sha256(shared_key, receiver_id_hash, b"", 64)
    signing_key = derived[:32]
    encryption_key = derived[32:]

    return token_decrypt(signing_key, encryption_key, token_body)

# ---------------------------------------------------------------------------
# Load identity from ESP32 identity file (128 bytes)
# ---------------------------------------------------------------------------

def load_esp32_identity(path):
    """Load identity from 128-byte file: x25519_prv(32)+x25519_pub(32)+ed25519_prv(32)+ed25519_pub(32)"""
    with open(path, "rb") as f:
        data = f.read()
    if len(data) != 128:
        raise ValueError(f"Expected 128 bytes, got {len(data)}")
    return {
        "x25519_prv": data[0:32],
        "x25519_pub": data[32:64],
        "ed25519_prv": data[64:96],
        "ed25519_pub": data[96:128],
        "identity_hash": sha256(data[32:64] + data[96:128])[:16],
    }

# ---------------------------------------------------------------------------
# Test 2a: Capture and Parse Announce
# ---------------------------------------------------------------------------

def test_2a_announce_capture(ser_a, ser_b):
    """Capture announce from Device A on Device B's serial."""
    print("\n=== Test 2a: Capture and Parse Announce ===")

    # Wait for Device B to receive and print an [RX_HEX] announce
    print("  INFO: Waiting for Device B to receive Device A's announce...")
    print("  INFO: (this may take up to 120s for periodic re-announce)")

    start = time.time()
    announce_hex = None
    while time.time() - start < 180:
        try:
            line = ser_b.readline().decode("utf-8", errors="replace").strip()
        except Exception:
            continue
        if not line:
            continue
        # Print interesting lines for diagnostics
        if any(tag in line for tag in ["[RX_HEX]", "[RX]", "[TX_HEX]", "[TX]", "[AUTO]"]):
            print(f"  DBG B: {line}")

        if "[RX_HEX]" in line:
            hex_data = line.split("[RX_HEX]")[-1].strip()
            # Check if it's an announce (flags & 0x03 == 1)
            try:
                raw = bytes.fromhex(hex_data)
                if len(raw) >= 19 and (raw[0] & 0x03) == 0x01:
                    announce_hex = hex_data
                    print(f"  INFO: Captured announce: {len(raw)} bytes")
                    break
            except ValueError:
                continue

        # Also check Device A output for diagnostics
        try:
            line_a = ser_a.readline().decode("utf-8", errors="replace").strip()
            if line_a and any(tag in line_a for tag in ["[TX_HEX]", "[TX]", "[AUTO]"]):
                print(f"  DBG A: {line_a}")
        except Exception:
            pass

    test("Captured announce packet from Device B serial",
         announce_hex is not None,
         "No [RX_HEX] announce received within timeout")

    if announce_hex is None:
        return None

    # Parse
    announce = parse_announce(announce_hex)
    test("Announce parsed successfully", announce is not None)
    if announce is None:
        return None

    # Verify fields
    test("Dest hash matches known Device A dest",
         announce["dest_hash"] == DEVICE_A_DEST_HASH,
         f"Got={hexdump(announce['dest_hash'])} Expected={hexdump(DEVICE_A_DEST_HASH)}")

    test("Identity hash matches known Device A identity",
         announce["identity_hash"] == DEVICE_A_ID_HASH,
         f"Got={hexdump(announce['identity_hash'])} Expected={hexdump(DEVICE_A_ID_HASH)}")

    test("Expected dest hash matches packet dest_hash",
         announce["expected_dest"] == announce["dest_hash"],
         f"Computed={hexdump(announce['expected_dest'])}")

    test("Name hash matches 'traildrop.waypoint'",
         announce["name_hash"] == NAME_HASH,
         f"Got={hexdump(announce['name_hash'])} Expected={hexdump(NAME_HASH)}")

    test("Flags byte = 0x01 (HEADER_1, BROADCAST, SINGLE, ANNOUNCE)",
         announce["flags"] == 0x01)

    test("Hops = 0", announce["hops"] == 0)
    test("Context = 0x00 (CTX_NONE)", announce["context"] == 0x00)

    # Verify signature using RNS
    sig_valid = verify_announce_signature(announce)
    test("Ed25519 signature validates via RNS", sig_valid)

    # Verify via RNS validate_announce
    import RNS

    class MockPacket:
        pass
    mock = MockPacket()
    mock.packet_type = RNS.Packet.ANNOUNCE
    mock.destination_hash = announce["dest_hash"]
    mock.context_flag = RNS.Packet.FLAG_UNSET
    mock.data = (announce["x25519_pub"] + announce["ed25519_pub"] +
                 announce["name_hash"] + announce["random_hash"] +
                 announce["signature"] + announce["app_data"])
    mock.hops = announce["hops"]
    mock.rssi = None
    mock.snr = None
    mock.receiving_interface = None
    mock.transport_id = None

    rns_valid = RNS.Identity.validate_announce(mock, only_validate_signature=True)
    test("RNS.Identity.validate_announce passes", rns_valid == True)

    return announce


# ---------------------------------------------------------------------------
# Test 2b: Capture and Decrypt Data Packet
# ---------------------------------------------------------------------------

def test_2b_data_capture(ser_a, ser_b, announce):
    """Capture encrypted DATA packet and decrypt it."""
    print("\n=== Test 2b: Capture and Decrypt Data Packet ===")

    if announce is None:
        print("  SKIP: No announce captured, cannot proceed")
        return

    # Wait for auto-send to trigger (30s after peer discovery)
    # Listen on both serial ports for [TX_HEX] and [RX_HEX] data packets
    print("  INFO: Waiting for auto-send (up to 120s)...")

    data_rx_hex = None
    data_tx_hex = None
    sender_port = None  # Which device sent
    start = time.time()

    while time.time() - start < 120:
        # Check Device B
        try:
            line_b = ser_b.readline().decode("utf-8", errors="replace").strip()
            if line_b:
                if any(tag in line_b for tag in ["[RX_HEX]", "[TX_HEX]", "[AUTO]", "[DATA]"]):
                    print(f"  DBG B: {line_b}")
                if "[TX_HEX]" in line_b and data_tx_hex is None:
                    hex_data = line_b.split("[TX_HEX]")[-1].strip()
                    try:
                        raw = bytes.fromhex(hex_data)
                        if len(raw) >= 19 and (raw[0] & 0x03) == 0x00:  # DATA packet
                            data_tx_hex = hex_data
                            sender_port = "B"
                            print(f"  INFO: Captured TX DATA from Device B: {len(raw)} bytes")
                    except ValueError:
                        pass
                if "[RX_HEX]" in line_b and data_rx_hex is None:
                    hex_data = line_b.split("[RX_HEX]")[-1].strip()
                    try:
                        raw = bytes.fromhex(hex_data)
                        if len(raw) >= 19 and (raw[0] & 0x03) == 0x00:  # DATA packet
                            data_rx_hex = hex_data
                            print(f"  INFO: Captured RX DATA on Device B: {len(raw)} bytes")
                    except ValueError:
                        pass
        except Exception:
            pass

        # Check Device A
        try:
            line_a = ser_a.readline().decode("utf-8", errors="replace").strip()
            if line_a:
                if any(tag in line_a for tag in ["[TX_HEX]", "[RX_HEX]", "[AUTO]", "[DATA]"]):
                    print(f"  DBG A: {line_a}")
                if "[TX_HEX]" in line_a and data_tx_hex is None:
                    hex_data = line_a.split("[TX_HEX]")[-1].strip()
                    try:
                        raw = bytes.fromhex(hex_data)
                        if len(raw) >= 19 and (raw[0] & 0x03) == 0x00:
                            data_tx_hex = hex_data
                            sender_port = "A"
                            print(f"  INFO: Captured TX DATA from Device A: {len(raw)} bytes")
                    except ValueError:
                        pass
                if "[RX_HEX]" in line_a and data_rx_hex is None:
                    hex_data = line_a.split("[RX_HEX]")[-1].strip()
                    try:
                        raw = bytes.fromhex(hex_data)
                        if len(raw) >= 19 and (raw[0] & 0x03) == 0x00:
                            data_rx_hex = hex_data
                            print(f"  INFO: Captured RX DATA on Device A: {len(raw)} bytes")
                    except ValueError:
                        pass
        except Exception:
            pass

        # If we got either TX or RX data, that's enough
        if data_tx_hex or data_rx_hex:
            # Give a moment for the other side
            time.sleep(2)
            break

    # Use whichever we captured (TX preferred since it's the sender's raw bytes)
    captured_hex = data_tx_hex or data_rx_hex
    test("Captured DATA packet",
         captured_hex is not None,
         "No [TX_HEX]/[RX_HEX] DATA packet within timeout")

    if captured_hex is None:
        return

    data_pkt = parse_data_packet(captured_hex)
    test("DATA packet parsed", data_pkt is not None)

    if data_pkt is None:
        return

    test("DATA flags byte = 0x00", data_pkt["flags"] == 0x00)

    # Determine who sent and who receives
    # The auto-send sends to "first peer". After Device B receives Device A's announce,
    # Device B's first peer is Device A. So Device B sends to Device A.
    # Similarly, Device A sends to Device B.
    # We need the RECEIVER's private key to decrypt.

    # Try both — we know the expected plaintext
    encrypted = data_pkt["encrypted_payload"]
    print(f"  INFO: Encrypted payload: {len(encrypted)} bytes")
    print(f"  INFO: Dest hash: {hexdump(data_pkt['dest_hash'])}")

    # Determine receiver from dest_hash
    if data_pkt["dest_hash"] == DEVICE_A_DEST_HASH:
        receiver_name = "Device A"
        receiver_id_hash = DEVICE_A_ID_HASH
        print(f"  INFO: Packet addressed to Device A")
    elif data_pkt["dest_hash"] == DEVICE_B_DEST_HASH:
        receiver_name = "Device B"
        receiver_id_hash = DEVICE_B_ID_HASH
        print(f"  INFO: Packet addressed to Device B")
    else:
        test("Dest hash matches known device", False,
             f"Unknown dest: {hexdump(data_pkt['dest_hash'])}")
        return

    test(f"Dest hash matches a known device ({receiver_name})", True)

    # We need the receiver's private key from the SD card.
    # Try to read the identity file via serial command or from a known location.
    # For now, use RNS to decrypt if we have the keys.

    # Attempt to decrypt using RNS
    # We need the receiver's private key. These are on the devices' SD cards.
    # Let's try to read them by having the device dump them, or use a cached copy.

    # First check if we have identity files cached locally
    identity_cache_dir = os.path.join(os.path.dirname(__file__), ".identity_cache")
    os.makedirs(identity_cache_dir, exist_ok=True)

    # Device identity file paths (from device SD at /traildrop/identity.dat)
    device_a_key_path = os.path.join(identity_cache_dir, "device_a_identity.dat")
    device_b_key_path = os.path.join(identity_cache_dir, "device_b_identity.dat")

    if data_pkt["dest_hash"] == DEVICE_A_DEST_HASH:
        key_path = device_a_key_path
    else:
        key_path = device_b_key_path

    if os.path.exists(key_path):
        try:
            identity = load_esp32_identity(key_path)
            # Verify the identity hash matches
            test(f"Cached identity hash matches {receiver_name}",
                 identity["identity_hash"] == receiver_id_hash,
                 f"Got={hexdump(identity['identity_hash'])} Expected={hexdump(receiver_id_hash)}")

            # Decrypt
            plaintext = decrypt_data_with_identity(
                encrypted, identity["x25519_prv"], identity["identity_hash"])
            test("Decrypted plaintext matches expected",
                 plaintext == b"Hello from TrailDrop!",
                 f"Got: {plaintext}")
            return
        except Exception as e:
            test(f"Decrypt with cached key", False, str(e))
    else:
        print(f"  INFO: No cached identity at {key_path}")

    # Alternative: use RNS Identity to decrypt
    # We need the private key. Let's try reading from the announce's public keys
    # and the known identity data.
    # Without the private key, we can only verify the packet structure, not decrypt.

    print("  INFO: Cannot decrypt without receiver private key.")
    print("  INFO: To enable decryption, copy identity files to:")
    print(f"  INFO:   {device_a_key_path}")
    print(f"  INFO:   {device_b_key_path}")
    print("  INFO: (128 bytes each from /traildrop/identity.dat on each device's SD)")

    # Structural verification only
    test("Encrypted payload >= 96 bytes (32+16+16+32 min)",
         len(encrypted) >= 96,
         f"Got {len(encrypted)} bytes")

    # Verify encrypted format structure
    eph_pub = encrypted[:32]
    token_body = encrypted[32:]
    iv = token_body[:16]
    hmac_val = token_body[-32:]
    ct = token_body[16:-32]

    test("Ephemeral public key field is 32 bytes", len(eph_pub) == 32)
    test("Ciphertext is multiple of 16", len(ct) % 16 == 0,
         f"Ciphertext length: {len(ct)}")
    test("Token structure: IV(16) + CT + HMAC(32)", len(token_body) == 16 + len(ct) + 32)


# ---------------------------------------------------------------------------
# Identity key caching from boot output
# ---------------------------------------------------------------------------

def cache_identity_from_boot(boot_lines, device_name, cache_dir):
    """Extract [ID_KEY] hex from boot output and cache to file."""
    for line in boot_lines:
        if "[ID_KEY]" in line:
            hex_key = line.split("[ID_KEY]")[-1].strip()
            try:
                key_bytes = bytes.fromhex(hex_key)
                if len(key_bytes) == 128:
                    cache_path = os.path.join(cache_dir, f"{device_name}_identity.dat")
                    with open(cache_path, "wb") as f:
                        f.write(key_bytes)
                    print(f"  Cached {device_name} identity key ({len(hex_key)} hex chars)")
                    return True
                else:
                    print(f"  WARN: [ID_KEY] for {device_name} has {len(key_bytes)} bytes, expected 128")
            except ValueError as e:
                print(f"  WARN: [ID_KEY] hex parse error for {device_name}: {e}")
    print(f"  WARN: No [ID_KEY] found in {device_name} boot output ({len(boot_lines)} lines)")
    return False


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("Wire Compatibility Test: ESP32 TrailDrop ↔ Python Reticulum")
    print("Part 2: Hardware Capture Tests")
    print("=" * 60)

    # Check serial ports
    for port in [DEVICE_A_PORT, DEVICE_B_PORT]:
        if not os.path.exists(port):
            print(f"ERROR: Serial port {port} not found")
            sys.exit(1)

    # Open serial connections
    print(f"\nOpening serial ports...")
    ser_a = open_serial(DEVICE_A_PORT, timeout=0.5)
    ser_b = open_serial(DEVICE_B_PORT, timeout=0.5)
    print(f"  Device A: {DEVICE_A_PORT}")
    print(f"  Device B: {DEVICE_B_PORT}")

    # Staggered reset: Boot Device B (receiver) first, wait for it to enter
    # the main loop and be ready to receive, then reset Device A (sender).
    # This ensures Device A's announce arrives when Device B is listening.
    # IMPORTANT: Read serial continuously during boot to avoid buffer overflow.
    identity_cache_dir = os.path.join(os.path.dirname(__file__), ".identity_cache")
    os.makedirs(identity_cache_dir, exist_ok=True)

    print("\nResetting Device B (receiver) first...")
    reset_device(ser_b)
    print("Waiting for Device B to boot and enter main loop (25s)...")
    boot_b = drain_and_collect(ser_b, timeout=25)
    print(f"  Device B: {len(boot_b)} lines of boot output")
    b_ready = any("[NET]" in l or "Entering main loop" in l for l in boot_b)
    if not b_ready:
        print("  WARN: Device B may not have network initialized")
    cache_identity_from_boot(boot_b, "device_b", identity_cache_dir)

    print("\nNow resetting Device A (sender)...")
    reset_device(ser_a)
    print("Waiting for Device A to boot (25s)...")
    boot_a = drain_and_collect(ser_a, timeout=25)
    print(f"  Device A: {len(boot_a)} lines of boot output")
    a_ready = any("[NET]" in l or "Entering main loop" in l for l in boot_a)
    if not a_ready:
        print("  WARN: Device A may not have network initialized")
    cache_identity_from_boot(boot_a, "device_a", identity_cache_dir)

    # Run tests
    announce = test_2a_announce_capture(ser_a, ser_b)
    test_2b_data_capture(ser_a, ser_b, announce)

    # Clean up
    ser_a.close()
    ser_b.close()

    # Summary
    global passed, failed
    total = passed + failed
    print("\n" + "=" * 60)
    print(f"Results: {passed}/{total} passed, {failed} failed")
    print("=" * 60)

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
