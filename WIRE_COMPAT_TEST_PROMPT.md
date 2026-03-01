# Wire Compatibility Test: ESP32 TrailDrop ↔ Python Reticulum

## Goal
Prove that TrailDrop firmware on ESP32 is wire-compatible with Python Reticulum by:
1. **Software test**: Using known keys, verify that bytes encrypted by one side can be decrypted by the other
2. **Hardware test**: Automated — capture raw packets from the ESP32 over serial and decrypt them with Python Reticulum (no physical button presses needed)

## Context
Two T-Deck Plus devices are running TrailDrop firmware and successfully exchanging encrypted messages over LoRa. We need to verify the wire format matches Python Reticulum exactly.

## Device Identities (persisted on SD)

**Device A** (ttyACM1):
- Identity hash: `530edfd3154e564a90c41eec5d93f586`
- Destination hash: `19820e6239feccf4a37b65cd73f7668d`
- Identity file on SD: `/identity.key` (128 bytes: x25519_priv(32) + x25519_pub(32) + ed25519_priv(32) + ed25519_pub(32))

**Device B** (ttyACM0):
- Identity hash: `1b22687bfffbe8832a9520b2d31916fd`
- Destination hash: `ff6b89bede65c0ae89b7957f6bf0b3b8`

**App name**: "traildrop", **Aspects**: "waypoint"
**Destination full name**: "traildrop.waypoint"

## Part 1: Software Wire Compatibility Test

Write a Python script `tests/wire_compat_test.py` that runs on rflab-sam and tests:

### 1a. Identity Hash Computation
- Load a known identity (4 keys × 32 bytes)
- Compute identity_hash = sha256(x25519_pub + ed25519_pub)[:16]
- Compare with Python Reticulum's `RNS.Identity` hash computation
- They must match exactly

### 1b. Destination Hash Computation
- name_hash = sha256("traildrop.waypoint")[:10]
- dest_hash = sha256(name_hash + identity_hash)[:16]
- Compare with Python Reticulum's `RNS.Destination` hash computation
- Must match Device A/B hashes above (verify against known values)

### 1c. Announce Packet Format
- Build an announce packet the way ESP32 does: flags(1) + hops(1) + dest_hash(16) + context(1) + payload
- Payload = public_key(64) + name_hash(10) + random_hash(10) + signature(64) [+ app_data]
- Verify Reticulum's Python code builds the same structure
- Reference: `src/net/announce.cpp` and `RNS/Packet.py`

### 1d. Encryption/Decryption Cross-Test
- Create a known identity in Python (using RNS.Identity)
- Export its keys
- In Python: encrypt "Hello from Python!" using Reticulum's encrypt method
- Verify the encrypted output format: ephemeral_pub(32) + iv(16) + ciphertext + hmac(32)
- Ensure this matches ESP32's `identity_encrypt` format
- Cross-decrypt: encrypt with Python keys → verify ESP32 format can decrypt (byte-level verification)

### 1e. HKDF Derivation Match
- Given: shared_key (from ECDH), salt (identity_hash, 16 bytes)
- ESP32: HKDF-SHA256(shared_key, salt=identity_hash, len=64, info=empty)
- Python: Same HKDF call via Reticulum
- Derived key split: first 32 bytes = signing_key, last 32 bytes = encryption_key
- Verify both sides produce identical derived keys for same inputs

## Part 2: Hardware Wire Compatibility Test (Automated)

Write a Python script `tests/hardware_wire_compat_test.py` that:

### Setup
- Connect to Device A via serial (`/dev/ttyACM1`, 115200 baud)
- Reset device via DTR to trigger fresh boot
- Capture the boot announce packet raw bytes from serial output

### 2a. Capture and Parse Announce
- Wait for `[TX] 176 bytes, type=1` line
- The raw packet is sent over LoRa, but we need the bytes. Option: modify firmware to hex-dump raw TX bytes (or use Device B to receive and hex-dump RX bytes)
- **Better approach**: Connect to Device B (ttyACM0) and capture the raw RX bytes
- Parse the captured announce using Python Reticulum's packet parser
- Verify: dest_hash matches, signature validates, public keys extracted

### 2b. Capture and Parse Encrypted Data
- Wait for periodic announce (5 min) or trigger reboot on both devices
- After both have discovered each other, send a command to trigger 's' key... 
- **Since we can't send keyboard commands via serial**: Add a firmware feature that auto-sends a test message 30 seconds after discovering a peer. This makes the test fully automated.
- Capture the encrypted DATA packet on the receiving device
- Decrypt using Python Reticulum's decrypt with the sender's known keys
- Verify plaintext matches "Hello from TrailDrop!"

### Firmware Changes Needed for Part 2
In `src/main_test.cpp`, add auto-send behavior:
```cpp
// After processing a successful announce (peer discovered):
// Set a flag + timestamp. 30 seconds later, auto-send test message to first peer.
static bool auto_send_pending = false;
static uint32_t auto_send_time = 0;

// In announce RX success handler:
if (!auto_send_pending && peer_count() > 0) {
    auto_send_pending = true;
    auto_send_time = millis() + 30000; // 30 seconds
}

// In main loop:
if (auto_send_pending && millis() >= auto_send_time) {
    auto_send_pending = false;
    // send test message to first peer
}
```

Also add hex dump of raw TX/RX packets for capture:
```cpp
// After radio TX:
Serial.print("[TX_HEX] ");
for (size_t i = 0; i < len; i++) Serial.printf("%02x", buf[i]);
Serial.println();

// After radio RX:
Serial.print("[RX_HEX] ");
for (size_t i = 0; i < len; i++) Serial.printf("%02x", buf[i]);
Serial.println();
```

## Environment
- **rflab**: `ssh rflab-sam` (user cal, Debian 13)
- **Project dir on rflab**: `~/traildrop-firmware`
- **Python Reticulum**: Already installed (`rns` v1.1.3)
- **Firmware source**: This repo (`traildrop-firmware/`)
- **PlatformIO**: Available on rflab for builds
- **Serial ports**: `/dev/ttyACM0` (Device B), `/dev/ttyACM1` (Device A)

## ESP32 Crypto Implementation Reference
- Identity: `src/crypto/identity.cpp` — key generation, encrypt/decrypt, ECDH + HKDF + Token
- Token: `src/crypto/token.cpp` — AES-256-CBC + HMAC-SHA256 encrypt/decrypt
- Hash: `src/crypto/hash.cpp` — SHA-256, HMAC-SHA256, HKDF-SHA256
- Packet: `src/net/packet.cpp` — wire format serialize/deserialize
- Announce: `src/net/announce.cpp` — announce build/process
- Transport: `src/net/transport.cpp` — send/receive loop
- Config: `include/config.h` — constants (RNS_MTU=500, DEST_HASH_SIZE=16, etc.)

## Python Reticulum Reference
- Identity: `RNS/Identity.py` — key management, encrypt/decrypt
- Destination: `RNS/Destination.py` — hash computation
- Packet: `RNS/Packet.py` — wire format
- Use `find /path/to/rns -name "*.py"` to locate installed files

## Acceptance Criteria
1. ✅ Identity hash computed identically in ESP32 and Python for same keys
2. ✅ Destination hash computed identically for same identity + app name
3. ✅ Announce packet structure matches (field order, sizes, signature format)
4. ✅ HKDF derivation produces identical keys on both sides for same inputs
5. ✅ Encryption format matches (ephemeral_pub + iv + ciphertext + hmac layout)
6. ✅ Software cross-test: bytes encrypted by Python decrypt correctly using ESP32's algorithm (verified in Python reimplementing ESP32's decrypt)
7. ✅ Hardware: raw announce captured from ESP32, parsed successfully by Python Reticulum
8. ✅ Hardware: raw encrypted DATA packet captured from ESP32, decrypted by Python
9. All tests produce clear PASS/FAIL output
10. No modifications to frozen layers (`src/crypto/`, `src/hal/`)

## Output
- `tests/wire_compat_test.py` — software compatibility tests
- `tests/hardware_wire_compat_test.py` — hardware capture + verify tests
- Firmware changes in `src/main_test.cpp` only (hex dump + auto-send)
- Test results logged to stdout

## Important Notes
- Do NOT modify files in `src/crypto/` or `src/hal/` — these are frozen
- The HKDF salt for encryption is `identity_hash` (16 bytes), NOT `dest_hash`
- Key order in identity hash: x25519_pub FIRST, ed25519_pub SECOND
- AES-256-CBC uses PKCS7 padding
- Token format: iv(16) + ciphertext(padded) + hmac(32)
- Encrypted format: ephemeral_pub(32) + token
- Read the Python Reticulum source code first before implementing — verify assumptions against actual code, don't trust summaries
