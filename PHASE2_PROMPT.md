# Phase 2 Crypto Restructure — Sub-Agent Prompt

## Context

TrailDrop is a backcountry waypoint sharing device running on a LilyGO T-Deck Plus (ESP32-S3). It communicates over Reticulum, an encrypted mesh networking stack. Phase 1 (HAL bringup) is hardware-verified. Phase 2 is the crypto layer.

**Current state:** Low-level crypto primitives exist in `src/crypto/` (AES-256-CBC, X25519, Ed25519, SHA-256, HMAC-SHA256) using the `rweather/Crypto` Arduino library. They compile and pass basic self-tests. But the API doesn't match Reticulum's actual identity/encryption model, so nothing we build on top will be wire-compatible with Python Reticulum nodes.

**Your job:** Restructure `src/crypto/` to match Reticulum's actual crypto architecture. Keep `framework = arduino` and `rweather/Crypto` — it has everything we need including `HKDF<SHA256>`.

## Reticulum's Crypto Architecture (from source)

Read these carefully. This is the spec you're implementing against.

### Identity Model (RNS/Identity.py)

A Reticulum Identity has **four keys** — two independent keypairs:
- `prv` / `pub` — X25519 keypair (for encryption/ECDH)
- `sig_prv` / `sig_pub` — Ed25519 keypair (for signing)

**Public key** = `pub_bytes(32) + sig_pub_bytes(32)` = 64 bytes (encryption key FIRST)
**Private key** = `prv_bytes(32) + sig_prv_bytes(32)` = 64 bytes
**Identity hash** = `truncated_sha256(public_key)` = first 16 bytes of SHA-256 of the 64-byte public key

The identity hash is stored on the struct and used as HKDF salt during encryption.

### Destination Hash (RNS/Destination.py)

Destination hash is a TWO-STEP process, separate from identity hash:
1. `name_hash = sha256("app_name.aspect1.aspect2")` truncated to first 10 bytes (NAME_HASH_LENGTH = 80 bits)
2. `destination_hash = truncated_sha256(name_hash + identity_hash)` → first 16 bytes

### Encryption Flow (Identity.encrypt)

```
1. Generate ephemeral X25519 keypair
2. shared_key = ECDH(ephemeral_private, destination_public_x25519)
3. derived_key = HKDF-SHA256(
       length=64,
       derive_from=shared_key,
       salt=identity_hash,    # 16-byte truncated hash of target's public key
       context=None            # Reticulum passes no context/info
   )
4. Split derived_key: signing_key = first 32 bytes, encryption_key = last 32 bytes
5. Token encrypt:
   a. iv = random 16 bytes
   b. ciphertext = AES-256-CBC(encryption_key, iv, PKCS7_pad(plaintext))
   c. hmac = HMAC-SHA256(signing_key, iv + ciphertext)
   d. token = iv(16) + ciphertext + hmac(32)
6. Output: ephemeral_pub(32) + token
```

Fixed overhead: 32 (ephemeral pub) + 16 (IV) + 32 (HMAC) = 80 bytes. Plus PKCS7 padding (1-16 bytes). Total: 81-96 bytes overhead.

### Decryption Flow (Identity.decrypt)

```
1. Extract ephemeral_pub = first 32 bytes of ciphertext_token
2. remaining = rest of ciphertext_token
3. shared_key = ECDH(own_x25519_private, ephemeral_pub)
4. derived_key = HKDF-SHA256(length=64, derive_from=shared_key, salt=own_identity_hash, context=None)
5. Split: signing_key = first 32, encryption_key = last 32
6. Verify HMAC-SHA256(signing_key, iv + ciphertext_without_hmac) == last 32 bytes
7. If valid: plaintext = PKCS7_unpad(AES-256-CBC_decrypt(encryption_key, iv, ciphertext))
```

### HKDF (RNS/Cryptography/HKDF.py)

Standard RFC 5869 HKDF. `rweather/Crypto` provides `HKDF<SHA256>` with this API:
- `setKey(key, keyLen, salt, saltLen)` — HKDF-Extract: derives PRK from key material + salt
- `extract(out, outLen, info, infoLen)` — HKDF-Expand: produces output key material (NOTE: the library names the expand step "extract" — confusing but correct)
- There's also a one-shot function: `hkdf<SHA256>(out, outLen, key, keyLen, salt, saltLen, info, infoLen)`

When `info` is NULL/nullptr with `infoLen=0`, the library skips the info step (equivalent to Reticulum's `context=None`).

Reticulum calls it with: length=64, salt=identity_hash(16 bytes), context=None (pass `nullptr, 0`).

**Reference implementation:**
```cpp
// One-shot version (preferred):
uint8_t derived[64];
hkdf<SHA256>(derived, 64, shared_key, 32, identity_hash, 16, nullptr, 0);

// Two-step version:
HKDF<SHA256> hkdf_ctx;
hkdf_ctx.setKey(shared_key, 32, identity_hash, 16);  // Extract
hkdf_ctx.extract(derived, 64, nullptr, 0);             // Expand
```

### Signing

- `sign(message)` = Ed25519 sign with `sig_prv`
- `validate(signature, message)` = Ed25519 verify with `sig_pub`

## What to Build

### 1. Restructure Identity struct and functions

```cpp
struct Identity {
    uint8_t x25519_public[32];
    uint8_t x25519_private[32];
    uint8_t ed25519_public[32];
    uint8_t ed25519_private[32];
    uint8_t hash[16];           // truncated_sha256(x25519_public + ed25519_public)
    bool valid = false;
};
```

- `identity_generate()` must compute and store `hash` using this exact procedure:
  ```cpp
  // Key order is CRITICAL — X25519 first, Ed25519 second (matches Reticulum)
  uint8_t pub_concat[64];
  memcpy(pub_concat, id.x25519_public, 32);       // encryption key FIRST
  memcpy(pub_concat + 32, id.ed25519_public, 32);  // signing key SECOND
  uint8_t full_hash[32];
  sha256(pub_concat, 64, full_hash);
  memcpy(id.hash, full_hash, 16);  // Truncate to first 16 bytes
  ```
- `identity_load()` must recompute hash on load using the same procedure
- Add `identity_get_public_key(id, out[64])` — writes `x25519_pub + ed25519_pub`
- Add `identity_get_private_key(id, out[64])` — writes `x25519_prv + ed25519_prv`
- Fix or create `identity_destination_hash()` with this signature:
  ```cpp
  // Computes Reticulum-compatible destination hash (two-step process)
  // full_name example: "traildrop.waypoint" (app_name.aspect, dot-separated)
  void identity_destination_hash(const char* full_name, const Identity& id, uint8_t out[16]);
  ```
  Implementation:
  1. `name_hash = sha256(full_name)[0:10]` — truncate to first 10 bytes
  2. Concatenate: `name_hash(10) + identity.hash(16)` = 26 bytes
  3. `dest_hash = sha256(concatenated)[0:16]` — truncate to first 16 bytes

### 2. Build Token class (src/crypto/token.h, token.cpp)

Modified Fernet, matching RNS/Cryptography/Token.py:

```cpp
namespace crypto {
    struct Token {
        uint8_t signing_key[32];
        uint8_t encryption_key[32];
    };

    // Split derived_key: signing_key = first 32 bytes, encryption_key = last 32 bytes
    // Implementation MUST be:
    //   memcpy(t.signing_key, derived_key, 32);
    //   memcpy(t.encryption_key, derived_key + 32, 32);
    void token_init(Token& t, const uint8_t derived_key[64]);
    // encrypt: returns iv(16) + ciphertext + hmac(32). Returns total length via out_len.
    bool token_encrypt(const Token& t, const uint8_t* plaintext, size_t len,
                       uint8_t* out, size_t* out_len);
    // decrypt: verifies HMAC first, then decrypts. Returns plaintext length via out_len.
    bool token_decrypt(const Token& t, const uint8_t* token_data, size_t token_len,
                       uint8_t* out, size_t* out_len);
}
```

TOKEN_OVERHEAD = 48 bytes (16 IV + 32 HMAC, not counting padding).

### 3. Build encrypt_for_identity / decrypt_for_identity (src/crypto/identity.h)

```cpp
// Encrypts plaintext for a target identity. Caller provides output buffer.
// Output: ephemeral_pub(32) + iv(16) + ciphertext + hmac(32)
// out must be at least 80 + plaintext_len + 16 bytes
// (ephemeral_pub(32) + IV(16) + ciphertext + HMAC(32) + max_padding(16))
bool identity_encrypt(const Identity& target, const uint8_t* plaintext, size_t len,
                      uint8_t* out, size_t* out_len);

// Decrypts ciphertext_token using own private key.
// Input: ephemeral_pub(32) + iv(16) + ciphertext + hmac(32)
bool identity_decrypt(const Identity& self, const uint8_t* ciphertext_token, size_t len,
                      uint8_t* out, size_t* out_len);
```

### 4. Add HKDF wrapper (src/crypto/hash.h)

```cpp
// HKDF-SHA256: derive output key of given length from input key material
void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len);
```

Use `#include <HKDF.h>` from rweather/Crypto. Template: `HKDF<SHA256>`.

### 5. Remove from public API

- Remove `identity_derive_shared_key()` from `identity.h` if it exists (Phase 1 artifact) — raw shared secrets must never be exposed in the public API. The only public encryption functions should be `identity_encrypt()` and `identity_decrypt()`.
- Keep `aes256_cbc_encrypt/decrypt` in encrypt.h but they become internal (Token uses them)
- Keep raw `sha256()` and `hmac_sha256()` — still useful for hashing

### 6. Update tests in main_test.cpp

Replace the Phase 2 crypto tests with:

1. **HKDF test** — use RFC 5869 Test Case 1:
   ```
   IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
   salt = 0x000102030405060708090a0b0c (13 bytes)
   info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
   L    = 42
   OKM  = 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
   ```
2. **Token round-trip** — encrypt then decrypt with known key, verify plaintext matches
3. **Token HMAC rejection** — corrupt one byte of token, verify decrypt fails
4. **Identity encrypt/decrypt round-trip** — generate Alice and Bob, Alice encrypts for Bob, Bob decrypts
5. **Cross-identity failure** — Alice encrypts for Bob, Carol can't decrypt
6. **Identity hash correctness** — verify key order: `sha256(x25519_pub + ed25519_pub)[0:16]`
7. **Destination hash** — verify two-step: `sha256(sha256("app.aspect")[0:10] + identity_hash)[0:16]`
8. **Sign/verify** — existing tests are fine, keep them

### 7. Update config.h

Add:
```cpp
#define NAME_HASH_LENGTH    10    // Truncated name hash (80 bits / 8)
#define TOKEN_OVERHEAD      48    // IV(16) + HMAC(32)
#define DERIVED_KEY_LENGTH  64    // HKDF output for Token (signing + encryption)
```

## Constraints

- **DO NOT modify any file in `src/hal/`** — Phase 1 is hardware-verified, don't touch it
- **DO NOT change `platformio.ini`** except to keep existing lib_deps (rweather/Crypto already has HKDF)
- **DO NOT add libsodium or change the framework** — rweather/Crypto is sufficient
- **Keep `framework = arduino`**
- Must compile clean with `pio run -e t-deck-plus`
- Test with `pio run -e t-deck-plus` (compile only — we'll flash separately)

## Acceptance Criteria

The work is NOT done until ALL of these are true:

1. ✅ `Identity.hash` is computed as `truncated_sha256(x25519_pub + ed25519_pub)` — key order matches Reticulum
2. ✅ Destination hash uses two-step process (name_hash + identity_hash)
3. ✅ HKDF-SHA256 is implemented and passes RFC 5869 test vector
4. ✅ Token encrypt/decrypt exists with HMAC authentication (encrypt-then-MAC)
5. ✅ `identity_encrypt()` implements full flow: ephemeral ECDH → HKDF(salt=target.hash, len=64) → Token
6. ✅ `identity_decrypt()` implements full flow: extract ephemeral pub → ECDH → HKDF → Token decrypt
7. ✅ `identity_derive_shared_key()` removed from public API
8. ✅ All tests pass in main_test.cpp (compile verification)
9. ✅ `pio run -e t-deck-plus` compiles clean with no errors or warnings
10. ✅ Committed and pushed to `deanssamclaw/traildrop-firmware`
11. ✅ Output must be wire-compatible with Python Reticulum — same inputs must produce same outputs. Key ordering, HKDF parameters, Token format must match exactly.

If any criterion is not met, the work is incomplete. Do not declare done.

When completely finished, run:
`openclaw system event --text "Done: Phase 2 crypto restructured to match Reticulum identity model" --mode now`
