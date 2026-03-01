#!/usr/bin/env python3
"""
Hardware Wire Compatibility Test: ESP32 TrailDrop ↔ Python Reticulum
Part 2 — Captures raw packets from ESP32 devices over serial, parses and
verifies them against Python Reticulum using actual device keys.

Test flow:
  1. Connect to both devices via serial (threaded capture)
  2. Reset devices via DTR/RTS to trigger fresh boot + announces
  3. Wait for boot completion, then capture announce TX_HEX/RX_HEX
  4. Parse announce: verify dest_hash, identity_hash, Ed25519 signature
  5. Wait for auto-send DATA packet (30s after peer discovery)
  6. Decrypt DATA packet with Python using real device private keys
  7. Verify plaintext = "Hello from TrailDrop!"

Requires: pyserial, cryptography, rns
Runs on rflab-sam.
"""

import hashlib
import hmac as hmac_mod
import os
import sys
import time
import threading
from math import ceil

try:
    import serial
except ImportError:
    print("ERROR: pyserial not installed. Run: pip install pyserial")
    sys.exit(1)

# ===================================================================
# Configuration
# ===================================================================

DEVICE_A_PORT = "/dev/ttyACM1"
DEVICE_B_PORT = "/dev/ttyACM0"
BAUD = 115200
TEST_TIMEOUT = 180  # 3 minutes total

EXPECTED_PLAINTEXT = b"Hello from TrailDrop!"
FULL_NAME = "traildrop.waypoint"

# ===================================================================
# Actual device keys (extracted from ESP32 SD cards)
# ===================================================================

DEVICE_A = {
    "name": "Device A",
    "port": DEVICE_A_PORT,
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
    "identity_hash": "530edfd3154e564a90c41eec5d93f586",
    "dest_hash": "19820e6239feccf4a37b65cd73f7668d",
}

DEVICE_B = {
    "name": "Device B",
    "port": DEVICE_B_PORT,
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
    "identity_hash": "1b22687bfffbe8832a9520b2d31916fd",
    "dest_hash": "ff6b89bede65c0ae89b7957f6bf0b3b8",
}

NAME_HASH = hashlib.sha256(FULL_NAME.encode("utf-8")).digest()[:10]
DEVICES_BY_DEST = {
    DEVICE_A["dest_hash"]: DEVICE_A,
    DEVICE_B["dest_hash"]: DEVICE_B,
}

# ===================================================================
# ESP32 crypto (mirrors src/crypto/)
# ===================================================================


def sha256(data):
    return hashlib.sha256(data).digest()


def hmac_sha256(key, data):
    return hmac_mod.new(key, data, hashlib.sha256).digest()


def hkdf(ikm, salt, info, length):
    if not salt:
        salt = b"\x00" * 32
    prk = hmac_sha256(salt, ikm)
    t = b""
    okm = b""
    for i in range(1, ceil(length / 32) + 1):
        t = hmac_sha256(prk, t + info + bytes([i]))
        okm += t
    return okm[:length]


def pkcs7_unpad(data):
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16:
        raise ValueError(f"Invalid PKCS7 padding: {pad_len}")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Corrupt PKCS7 padding")
    return data[:-pad_len]


def decrypt_payload(receiver, encrypted):
    """Full identity_decrypt: ECDH + HKDF + AES-256-CBC + HMAC verify."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey,
        X25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

    if len(encrypted) < 96:
        raise ValueError(f"Ciphertext too short: {len(encrypted)}")

    eph_pub = encrypted[:32]
    token = encrypted[32:]

    # ECDH
    prv = X25519PrivateKey.from_private_bytes(receiver["x25519_priv"])
    pub = X25519PublicKey.from_public_bytes(eph_pub)
    shared = prv.exchange(pub)

    # HKDF (salt = receiver's identity_hash)
    id_hash = bytes.fromhex(receiver["identity_hash"])
    derived = hkdf(shared, id_hash, b"", 64)
    signing_key = derived[:32]
    encryption_key = derived[32:]

    # HMAC verify
    mac_got = token[-32:]
    mac_exp = hmac_sha256(signing_key, token[:-32])
    if not hmac_mod.compare_digest(mac_got, mac_exp):
        raise ValueError("HMAC verification failed")

    # AES-256-CBC decrypt + PKCS7 unpad
    iv = token[:16]
    ct = token[16:-32]
    dec = Cipher(algorithms.AES(encryption_key), modes.CBC(iv)).decryptor()
    return pkcs7_unpad(dec.update(ct) + dec.finalize())


# ===================================================================
# Threaded serial capture
# ===================================================================


class SerialCapture:
    """Captures serial output in a background thread."""

    def __init__(self, name, port, baud=115200):
        self.name = name
        self.port = port
        self.lines = []
        self.running = True
        self.ser = None
        self._lock = threading.Lock()

        try:
            self.ser = serial.Serial(port, baud, timeout=0.5)
            self.ser.reset_input_buffer()
        except serial.SerialException as e:
            print(f"  ERROR: Cannot open {port}: {e}")
            self.running = False
            return

        self.thread = threading.Thread(target=self._read, daemon=True)
        self.thread.start()

    def _read(self):
        while self.running:
            try:
                raw = self.ser.readline()
                if raw:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        with self._lock:
                            self.lines.append((time.time(), line))
            except Exception:
                if not self.running:
                    break
                time.sleep(0.1)

    def reset(self):
        """ESP32 reset via DTR/RTS toggle."""
        if not self.ser:
            return
        try:
            self.ser.setDTR(False)
            self.ser.setRTS(True)
            time.sleep(0.1)
            self.ser.setRTS(False)
            time.sleep(0.1)
            self.ser.setDTR(True)
        except Exception as e:
            print(f"  WARN: Reset failed for {self.name}: {e}")

    def get_lines(self, prefix=None, after=0):
        """Get all lines (optionally filtered by prefix and after timestamp)."""
        with self._lock:
            if prefix:
                return [(t, l) for t, l in self.lines if l.startswith(prefix) and t > after]
            return [(t, l) for t, l in self.lines if t > after]

    def wait_for(self, prefix, timeout=120, after=0):
        """Block until a line starting with prefix appears. Returns line or None."""
        deadline = time.time() + timeout
        seen = 0
        while time.time() < deadline:
            lines = self.get_lines(prefix, after)
            if len(lines) > seen:
                return lines[seen][1]
            time.sleep(0.3)
        return None

    @property
    def is_open(self):
        return self.ser is not None and self.running

    def stop(self):
        self.running = False
        if self.ser:
            try:
                self.ser.close()
            except Exception:
                pass


# ===================================================================
# Packet parsing
# ===================================================================


def extract_hex(line, prefix):
    """Extract hex data from a tagged line like '[TX_HEX] abcd...'"""
    return line.split(prefix, 1)[-1].strip()


def is_announce(raw):
    """Check if raw bytes are an announce packet."""
    return len(raw) >= 19 + 148 and (raw[0] & 0x03) == 0x01


def is_data(raw):
    """Check if raw bytes are a data packet."""
    return len(raw) >= 19 and (raw[0] & 0x03) == 0x00


def parse_announce(raw):
    """Parse announce packet bytes into field dict."""
    flags = raw[0]
    hops = raw[1]
    header_type = (flags >> 6) & 0x01

    if header_type == 0:
        dest_hash = raw[2:18]
        context = raw[18]
        payload = raw[19:]
    else:
        dest_hash = raw[18:34]
        context = raw[34]
        payload = raw[35:]

    return {
        "flags": flags,
        "hops": hops,
        "dest_hash": dest_hash,
        "context": context,
        "x25519_pub": payload[0:32],
        "ed25519_pub": payload[32:64],
        "name_hash": payload[64:74],
        "random_hash": payload[74:84],
        "signature": payload[84:148],
        "app_data": payload[148:],
        "payload": payload,
        "raw": raw,
    }


def parse_data(raw):
    """Parse data packet bytes into field dict."""
    flags = raw[0]
    header_type = (flags >> 6) & 0x01

    if header_type == 0:
        dest_hash = raw[2:18]
        context = raw[18]
        payload = raw[19:]
    else:
        dest_hash = raw[18:34]
        context = raw[34]
        payload = raw[35:]

    return {
        "flags": flags,
        "dest_hash": dest_hash,
        "context": context,
        "encrypted": payload,
        "raw": raw,
    }


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


def find_packet(capture, prefix, pkt_check, dest_match=None, after=0, timeout=120):
    """Find a TX_HEX or RX_HEX line containing a packet matching criteria."""
    deadline = time.time() + timeout
    seen = 0
    while time.time() < deadline:
        lines = capture.get_lines(prefix, after)
        while seen < len(lines):
            _, line = lines[seen]
            seen += 1
            hex_str = extract_hex(line, prefix)
            try:
                raw = bytes.fromhex(hex_str)
            except ValueError:
                continue
            if not pkt_check(raw):
                continue
            if dest_match:
                # dest_hash at bytes 2:18 for HEADER_1
                pkt_dest = raw[2:18]
                if pkt_dest != dest_match:
                    continue
            return raw
        time.sleep(0.5)
    return None


# ===================================================================
# Test 2a: Capture and Parse Announce
# ===================================================================


def test_2a(cap_a, cap_b, start_time):
    print("\n=== Test 2a: Capture and Parse Announce Packets ===")

    for dev, cap in [(DEVICE_A, cap_a), (DEVICE_B, cap_b)]:
        expected_dest = bytes.fromhex(dev["dest_hash"])
        print(f"\n  --- {dev['name']} announce ---")

        # Find TX_HEX announce from this device
        raw = find_packet(
            cap, "[TX_HEX] ", is_announce, expected_dest, after=start_time, timeout=TEST_TIMEOUT
        )

        if raw is None:
            test(f"{dev['name']}: announce TX_HEX captured", False, "Not found within timeout")
            continue

        test(f"{dev['name']}: announce TX_HEX captured", True)
        ann = parse_announce(raw)
        print(f"        Size: {len(raw)} bytes")

        # Verify dest_hash
        test(
            f"{dev['name']}: dest_hash matches known",
            ann["dest_hash"] == expected_dest,
        )

        # Verify public keys
        test(f"{dev['name']}: x25519_pub matches", ann["x25519_pub"] == dev["x25519_pub"])
        test(f"{dev['name']}: ed25519_pub matches", ann["ed25519_pub"] == dev["ed25519_pub"])

        # Verify identity hash derivation
        computed_id = sha256(ann["x25519_pub"] + ann["ed25519_pub"])[:16]
        expected_id = bytes.fromhex(dev["identity_hash"])
        test(
            f"{dev['name']}: identity hash from announce",
            computed_id == expected_id,
            f"computed {computed_id.hex()}, expected {expected_id.hex()}",
        )

        # Verify dest hash derivation
        computed_dest = sha256(ann["name_hash"] + computed_id)[:16]
        test(
            f"{dev['name']}: dest hash derivable from announce",
            computed_dest == ann["dest_hash"],
        )

        # Verify name_hash
        test(f"{dev['name']}: name_hash = SHA256('{FULL_NAME}')[:10]", ann["name_hash"] == NAME_HASH)

        # Verify flags
        test(f"{dev['name']}: flags = 0x01 (H1/broadcast/single/announce)", ann["flags"] == 0x01)

        # Verify Ed25519 signature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        signed_data = (
            ann["dest_hash"]
            + ann["x25519_pub"]
            + ann["ed25519_pub"]
            + ann["name_hash"]
            + ann["random_hash"]
            + ann["app_data"]
        )
        ed_pub = Ed25519PublicKey.from_public_bytes(ann["ed25519_pub"])
        try:
            ed_pub.verify(ann["signature"], signed_data)
            sig_ok = True
        except Exception:
            sig_ok = False
        test(f"{dev['name']}: Ed25519 signature validates", sig_ok)

        # Validate with RNS
        try:
            import RNS

            mock = type("MockPkt", (), {})()
            mock.packet_type = RNS.Packet.ANNOUNCE
            mock.destination_hash = ann["dest_hash"]
            mock.context_flag = RNS.Packet.FLAG_UNSET
            mock.data = ann["payload"]
            mock.hops = ann["hops"]
            mock.rssi = None
            mock.snr = None
            mock.receiving_interface = None
            mock.transport_id = None

            rns_ok = RNS.Identity.validate_announce(mock, only_validate_signature=True)
            test(f"{dev['name']}: RNS validate_announce passes", rns_ok is True)
        except Exception as e:
            test(f"{dev['name']}: RNS validate_announce passes", False, str(e))

    # Cross-check: Device B should have received Device A's announce
    # (Device A announced after Device B was already in main loop due to staggered boot)
    print("\n  --- Cross-device reception ---")
    sender_dest_a = bytes.fromhex(DEVICE_A["dest_hash"])
    raw = find_packet(
        cap_b, "[RX_HEX] ", is_announce, sender_dest_a, after=start_time, timeout=30
    )
    test(
        f"{DEVICE_B['name']} received {DEVICE_A['name']}'s announce (staggered boot)",
        raw is not None,
    )


# ===================================================================
# Test 2b: Capture and Decrypt Encrypted Data
# ===================================================================


def test_2b(cap_a, cap_b, start_time):
    print("\n=== Test 2b: Capture and Decrypt Data Packet ===")
    print("  Waiting for auto-send DATA packet...")

    # The auto-send fires 30s after peer discovery. Either device may send first.
    # Search for data packets on both captures addressed to either device.
    dest_a = bytes.fromhex(DEVICE_A["dest_hash"])
    dest_b = bytes.fromhex(DEVICE_B["dest_hash"])

    raw = None
    direction = None
    deadline = time.time() + TEST_TIMEOUT

    while time.time() < deadline and raw is None:
        # A sent to B? (TX_HEX on A with dest=B)
        r = find_packet(cap_a, "[TX_HEX] ", is_data, dest_b, after=start_time, timeout=2)
        if r:
            raw, direction = r, "A→B"
            break

        # B sent to A? (TX_HEX on B with dest=A)
        r = find_packet(cap_b, "[TX_HEX] ", is_data, dest_a, after=start_time, timeout=2)
        if r:
            raw, direction = r, "B→A"
            break

        # Also check RX_HEX
        r = find_packet(cap_b, "[RX_HEX] ", is_data, dest_b, after=start_time, timeout=2)
        if r:
            raw, direction = r, "A→B"
            break

        r = find_packet(cap_a, "[RX_HEX] ", is_data, dest_a, after=start_time, timeout=2)
        if r:
            raw, direction = r, "B→A"
            break

        time.sleep(2)

    if raw is None:
        test("DATA packet captured", False, "No DATA packet found within timeout")
        return

    test("DATA packet captured", True)
    pkt = parse_data(raw)
    print(f"        Direction: {direction}, size: {len(raw)} bytes")
    print(f"        dest_hash: {pkt['dest_hash'].hex()}")

    # Identify receiver
    receiver = DEVICES_BY_DEST.get(pkt["dest_hash"].hex())
    if receiver is None:
        test("Dest hash matches known device", False, f"unknown: {pkt['dest_hash'].hex()}")
        return

    test(f"Dest hash matches {receiver['name']}", True)
    test("DATA flags = 0x00 (H1/broadcast/single/data)", pkt["flags"] == 0x00)

    # Verify encrypted payload structure
    enc = pkt["encrypted"]
    test(
        "Encrypted payload >= 96 bytes",
        len(enc) >= 96,
        f"got {len(enc)}",
    )

    eph_pub = enc[:32]
    token = enc[32:]
    iv = token[:16]
    ct = token[16:-32]
    hmac_val = token[-32:]

    test("Ephemeral pub = 32 bytes", len(eph_pub) == 32)
    test("AES ciphertext aligned to 16 bytes", len(ct) % 16 == 0, f"ct len={len(ct)}")
    test("Token = IV(16) + CT + HMAC(32)", len(token) == 16 + len(ct) + 32)

    # Decrypt with Python using receiver's private key
    try:
        plaintext = decrypt_payload(receiver, enc)
        test("Python decryption succeeds", True)
        test(
            f"Plaintext = '{EXPECTED_PLAINTEXT.decode()}'",
            plaintext == EXPECTED_PLAINTEXT,
            f"got '{plaintext.decode('utf-8', errors='replace')}'",
        )
    except Exception as e:
        test("Python decryption succeeds", False, str(e))
        return

    # Also verify firmware decrypted it (check receiver's serial output)
    receiver_cap = cap_a if receiver is DEVICE_A else cap_b
    content_line = receiver_cap.wait_for("[DATA] Content:", timeout=5, after=start_time)
    if content_line:
        fw_text = content_line.split("[DATA] Content: ", 1)[-1]
        test(
            "Firmware decryption matches Python",
            fw_text == EXPECTED_PLAINTEXT.decode(),
            f"firmware: '{fw_text}'",
        )
    else:
        # Firmware might have printed before we started capturing, or output was lost
        test("Firmware decryption output found", False, "No [DATA] Content: line seen")


# ===================================================================
# Main
# ===================================================================


def reset_and_wait(name, port, baud, timeout=45):
    """Reset a device and capture boot output. Returns SerialCapture."""
    # Open serial, reset, then capture
    cap = SerialCapture(name, port, baud)
    if not cap.is_open:
        print(f"  FATAL: Cannot open {port}")
        sys.exit(1)

    start = time.time()
    cap.reset()
    time.sleep(0.5)

    boot = cap.wait_for("[BOOT] === Entering main loop ===", timeout=timeout, after=start)
    if boot:
        print(f"  {name}: booted and ready")
    else:
        print(f"  {name}: no boot marker (may already be running)")
    return cap, start


def main():
    print("=" * 60)
    print("Hardware Wire Compatibility Test: ESP32 TrailDrop ↔ Python RNS")
    print("Part 2: Live Packet Capture and Verification")
    print("=" * 60)

    # Staggered boot: bring up Device B (receiver) first so it's listening
    # when Device A announces. This ensures cross-device discovery.
    print("\nPhase 1: Reset Device B first (will be the listener)...")
    cap_b, start_b = reset_and_wait(DEVICE_B["name"], DEVICE_B_PORT, BAUD)
    print(f"  {DEVICE_B['name']} is now polling radio for incoming packets")

    print("\nPhase 2: Reset Device A (Device B will hear its announce)...")
    cap_a, start_a = reset_and_wait(DEVICE_A["name"], DEVICE_A_PORT, BAUD)
    print(f"  {DEVICE_A['name']} is now in main loop")

    # Use the earlier start time so we capture everything
    start_time = min(start_a, start_b)

    # Brief diagnostic: count captured lines
    a_tx = len(cap_a.get_lines("[TX_HEX] ", start_time))
    b_tx = len(cap_b.get_lines("[TX_HEX] ", start_time))
    b_rx = len(cap_b.get_lines("[RX_HEX] ", start_time))
    print(f"\n  Diagnostic: A has {a_tx} TX_HEX, B has {b_tx} TX_HEX + {b_rx} RX_HEX lines")

    try:
        test_2a(cap_a, cap_b, start_time)
        test_2b(cap_a, cap_b, start_time)
    finally:
        cap_a.stop()
        cap_b.stop()

    print(f"\n{'=' * 60}")
    print(f"Results: {_passed}/{_passed + _failed} passed, {_failed} failed")
    print(f"{'=' * 60}")

    sys.exit(0 if _failed == 0 else 1)


if __name__ == "__main__":
    main()
