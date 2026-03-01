# Phase 3 Hardware Test Plan

## Goal
Verify the entire Phase 3 network layer works on real T-Deck Plus hardware. Compiling clean ≠ working. This is the gate before Phase 4.

## Prerequisites
- Two T-Deck Plus devices connected to rflab (or one + Python Reticulum on rflab)
- Current firmware: commit `c0028a4` (Phase 3d + all Cal fixes)
- SD cards in both devices (identity persistence)

## Test 1: Single Device Boot + Identity

**Flash device A:**
```bash
cd ~/traildrop-firmware && pio run -e t-deck-plus -t upload && pio device monitor -b 115200
```

**Verify serial output:**
- [ ] All 8 HAL modules: OK (boot health line `PDKTGRSB` — all uppercase)
- [ ] `[BOOT] Health: PDKTGRSB` (or note any failures)
- [ ] `[ID] Identity loaded from SD` (second boot) or `[ID] New identity generated and saved` (first boot)
- [ ] Identity hash printed (16 hex bytes)
- [ ] Destination hash printed (16 hex bytes)
- [ ] `[BOOT] Full network-ready: radio + storage + identity`
- [ ] All 38 tests pass (12 crypto + 11 packet + 2 destination + 9 announce + 4 transport)
- [ ] `[TX] Announce sent` on boot
- [ ] `[NET] Transport initialized, announce sent`
- [ ] No crashes, no watchdog resets

**Identity persistence test:**
- [ ] Note the identity hash from first boot
- [ ] Reset device (power cycle or BOOT button)
- [ ] Verify identity hash is SAME on second boot (`[ID] Identity loaded from SD`)
- [ ] Verify destination hash is SAME

## Test 2: Two Device Discovery

**Flash device B** (same firmware). Ensure device B has a different/empty SD card so it generates its own identity.

**With both devices powered on and serial monitors attached:**

**Expected behavior:**
- [ ] Device A sends periodic announce every 300s (ANNOUNCE_INTERVAL)
- [ ] Device B receives A's announce: `[RX] N bytes, type=1, RSSI=X SNR=Y`
- [ ] Device B validates announce: `[RX] Announce processed successfully`
- [ ] Device A receives B's announce and processes it
- [ ] Both devices show `Peers=1` on LCD network status line

**Verify peer discovery:**
- [ ] Device A's serial shows it received and validated B's announce
- [ ] Device B's serial shows it received and validated A's announce
- [ ] Peer count increments on both devices

**If announces aren't received:**
- Check RSSI/SNR values — are devices in range?
- Check sync word matches (0x12 in config.h)
- Check frequency (915.0 MHz)
- Check that `radio_start_receive()` is called after each TX

## Test 3: Encrypted Data Exchange

Keyboard triggers are built in:
- **Press 's'** — Send encrypted test message ("Hello from TrailDrop!") to first known peer
- **Press 'a'** — Force an immediate announce broadcast

**After both devices have discovered each other (Test 2 passes):**

On Device A, press 's' on the keyboard.

**Expected on Device A serial:**
```
[TEST] Sending to peer ab12cd34...
[TX] N bytes, type=0
[TEST] Message sent successfully
```

**Expected on Device B serial:**
```
[RX] N bytes, type=0, RSSI=-XX.X SNR=X.X
[RX] DATA decrypted: 21 bytes
[DATA] Received 21 bytes (sender unknown)
[DATA] Content: Hello from TrailDrop!
```

**Checklist:**
- [ ] Device A: `[TEST] Message sent successfully`
- [ ] Device B: `[RX] DATA decrypted: 21 bytes`
- [ ] Device B: `[DATA] Content: Hello from TrailDrop!`
- [ ] Content matches exactly
- [ ] Press 's' on Device B → Device A receives and decrypts the same way
- [ ] Press 'a' on either device → forces an immediate announce

## Test 4: Wire Compatibility with Python Reticulum

**On rflab (has Python + pip):**
```bash
pip install rns
```

**Test A — Announce interop:**
- Run Python Reticulum instance on rflab with a serial or UDP interface
- T-Deck sends announce over LoRa
- Python RNS receives and validates the announce
- If validation passes: our announce format is wire-compatible

**Test B — Encrypt/decrypt interop:**
- Generate a known identity in Python RNS
- Encrypt a message using Python `Identity.encrypt()`
- Transfer ciphertext to ESP32 (serial or hardcode)
- ESP32 decrypts with `crypto::identity_decrypt()`
- Compare plaintext

**Test C — Packet hash interop:**
- Construct the same packet in both Python and C
- Compare packet hashes — must be identical

This is the definitive test. If packet hashes, announces, and encryption all interoperate, TrailDrop speaks Reticulum.

## What to Report

For each test, capture:
1. Full serial output (both devices if applicable)
2. RSSI/SNR values for radio tests
3. Any test failures with exact output
4. Build size confirmation (should match: 8.8% RAM, 14.2% flash)

## Known Limitations (not bugs)
- Sender identity not available in DATA callback (H1 limitation, documented)
- No ratchet support (context_flag=1 announces will be rejected — fail-safe)
- No PROOF packets sent/processed yet
- No LINK support
- Single-hop only (no transport/routing)

These are all by design for Phase 3. Phase 4+ addresses them as needed.
