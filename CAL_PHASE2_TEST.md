# Phase 2 Crypto — Hardware Verification Instructions for Cal

## What Changed

Phase 2 restructured the crypto layer to match Reticulum's actual identity/encryption model. New files:

- `src/crypto/token.h` / `token.cpp` — Token layer (AES-256-CBC + HMAC-SHA256 authenticated encryption)
- `src/crypto/hash.cpp` — Added HKDF-SHA256 wrapper
- `src/crypto/identity.cpp` — Restructured: correct key ordering, identity hash, destination hash, `identity_encrypt()`/`identity_decrypt()` implementing full Reticulum flow
- `src/main_test.cpp` — 12 crypto self-tests

## Step 1: Pull and Flash

```bash
cd traildrop-firmware
git pull origin main
pio run -e t-deck-plus          # should compile clean (~8s)
pio run -e t-deck-plus -t upload  # flash to T-Deck Plus
```

Expected compile output: ~6.7% RAM, ~13.9% flash. If it doesn't compile, stop and report.

## Step 2: Monitor Serial Output

```bash
pio device monitor -b 115200
```

You should see the Phase 1 HAL tests run first (all 8 modules), then:

```
[CRYPTO] Running Phase 2 crypto tests...
[CRYPTO] SHA-256          PASS
[CRYPTO] HMAC-SHA256      PASS
[CRYPTO] AES-256-CBC      PASS
[CRYPTO] HKDF-SHA256      PASS
[CRYPTO] Token Round      PASS
[CRYPTO] Token HMAC       PASS
[CRYPTO] Identity S/L     PASS
[CRYPTO] Identity Hash    PASS
[CRYPTO] Dest Hash        PASS
[CRYPTO] Encrypt/Decrypt  PASS
[CRYPTO] Cross-ID Fail    PASS
[CRYPTO] Ed25519 Sign     PASS
[CRYPTO] === ALL TESTS PASSED ===
```

The T-Deck Plus display should also show each test result (green = PASS, red = FAIL).

**NOTE:** Crypto tests require SD card (`ok_sd` gate). If SD init fails, you'll see "Crypto: SKIP (no SD)" — the identity save/load test needs SD storage. Make sure the SD card is inserted.

## What Each Test Verifies

| Test | What it checks |
|------|---------------|
| SHA-256 | Basic hash against known vector |
| HMAC-SHA256 | Keyed hash against known vector |
| AES-256-CBC | Encrypt/decrypt round-trip |
| HKDF-SHA256 | RFC 5869 Test Case 1 (known input → known output) |
| Token Round | Token encrypt → decrypt, plaintext matches |
| Token HMAC | Corrupt one byte of token → decrypt fails (authentication works) |
| Identity S/L | Generate identity → save to SD → load → keys match |
| Identity Hash | Verify hash = truncated_sha256(x25519_pub + ed25519_pub) — key order critical |
| Dest Hash | Two-step: sha256(name)[0:10] + identity.hash → sha256 → [0:16] |
| Encrypt/Decrypt | Alice encrypts for Bob, Bob decrypts — full Reticulum flow |
| Cross-ID Fail | Alice encrypts for Bob, Carol tries to decrypt → fails |
| Ed25519 Sign | Sign message → verify → tamper → verify fails |

## What to Report

1. Did all 12 tests pass? If any failed, which ones and what was the serial output?
2. Did any HAL modules that passed before now fail? (Phase 2 shouldn't touch HAL, but checking)
3. RAM/flash usage from compile output
4. Any warnings during compile?

## Known Open Items (Not Part of This Test)

These are from your firmware review and are still unfixed:
- **SPI bus mutex (blocker #3)** — radio/display/SD can collide under concurrent access
- **`setup()` ignoring init return values (#5)** — if a peripheral fails, we don't act on it

These are next after Phase 2 is hardware-verified.

## After Hardware Verification: Wire-Compatibility Test

Once the self-tests pass on hardware, the next step is confirming our crypto output matches Python Reticulum. Here's a test we can run:

```python
# On a machine with RNS installed:
import RNS

# Generate a known identity
id_a = RNS.Identity()

# Export the raw keys
pub_key = id_a.pub_bytes + id_a.sig_pub_bytes  # 64 bytes
prv_key = id_a.prv_bytes + id_a.sig_prv_bytes  # 64 bytes

# Print as hex for loading into ESP32
print("Public key:", pub_key.hex())
print("Private key:", prv_key.hex())
print("Identity hash:", id_a.hash.hex())

# Encrypt a known message
plaintext = b"TrailDrop wire-compat test"
ciphertext = id_a.encrypt(plaintext)
print("Ciphertext:", ciphertext.hex())
print("Plaintext len:", len(plaintext))
print("Ciphertext len:", len(ciphertext))
```

Then on ESP32: load the same private key, call `identity_decrypt()` on the ciphertext. If we get back "TrailDrop wire-compat test", we're wire-compatible.

We can also go the other direction: encrypt on ESP32 with a known key, decrypt in Python.

This doesn't need to happen on-device first — can be done with the ESP32 connected via serial, feeding it hex and reading output.
