# Phase 2 Prompt Review — Issues Found

Reviewed against Reticulum source (Identity.py, Token.py, HKDF.py, Destination.py)

## Issues

### 1. **BLOCKER:** HKDF rweather/Crypto API mismatch
**Location:** Section 4 "Add HKDF wrapper"

**Problem:** The prompt says to use `rweather/Crypto`'s `HKDF<SHA256>` but describes the API incorrectly. It says:
> `setKey(derive_from, derive_from_len, salt, salt_len)` — extract step  
> `extract(out, length, info, info_len)` — expand step

This is confusing. Standard HKDF terminology:
- `HKDF-Extract(salt, IKM) -> PRK`
- `HKDF-Expand(PRK, info, L) -> OKM`

The rweather library likely has:
- `setKey()` for Extract
- `expand()` (NOT `extract()`) for Expand

**Impact:** A sub-agent following this literally will call the wrong methods and produce invalid keys, breaking wire compatibility.

**Fix:** Verify the actual rweather/Crypto HKDF API and update the prompt with correct method names. Or provide a complete reference implementation example:
```cpp
HKDF<SHA256> hkdf;
hkdf.setKey(ikm, ikm_len, salt, salt_len);  // Extract phase
hkdf.expand(out, out_len, info, info_len);   // Expand phase (NOT "extract")
```

---

### 2. **IMPORTANT:** Missing Identity.hash computation instructions
**Location:** Section 1 "Restructure Identity struct"

**Problem:** The prompt says:
> `identity_generate()` must compute and store `hash`  
> `identity_load()` / `identity_save()` must recompute hash on load

But it never explicitly says **how** to compute the hash in the implementation instructions. The formula is mentioned earlier in the "Reticulum's Crypto Architecture" section, but not in "What to Build."

**Impact:** A sub-agent might miss the key ordering (X25519 pub FIRST, then Ed25519 pub) and compute `sha256(ed25519_pub + x25519_pub)` instead, breaking all destination routing.

**Fix:** Add explicit instruction:
```cpp
// In identity_generate() and identity_load():
uint8_t pub_key_concat[64];
memcpy(pub_key_concat, x25519_public, 32);
memcpy(pub_key_concat + 32, ed25519_public, 32);
sha256(pub_key_concat, 64, hash_full);
memcpy(identity.hash, hash_full, 16);  // Truncate to 16 bytes
```

---

### 3. **IMPORTANT:** HKDF context=None handling unclear
**Location:** Section 4 "Add HKDF wrapper" and encryption flow

**Problem:** The prompt says HKDF is called with `context=None`, and the wrapper signature has:
```cpp
const uint8_t* info, size_t info_len
```

In C++, there is no "None." The prompt must specify:
- Pass `info=nullptr, info_len=0`?
- Pass `info=<anything>, info_len=0`?
- Does the wrapper need to handle `info==nullptr` specially?

**Impact:** Sub-agent guesses wrong, HKDF fails or crashes, or produces wrong keys.

**Fix:** Clarify in the HKDF wrapper spec:
```cpp
// When context is None (Reticulum standard), caller passes:
hkdf_sha256(shared_key, 32, identity_hash, 16, nullptr, 0, out, 64);
// OR: info_len=0 is sufficient; info pointer is ignored if info_len==0
```

---

### 4. **IMPORTANT:** Acceptance criterion assumes prior knowledge
**Location:** Acceptance Criteria #7

**Problem:** Says:
> ✅ `identity_derive_shared_key()` removed from public API

But nowhere does the prompt say this function currently exists or what it does. A sub-agent working from scratch won't know to remove it.

**Impact:** Sub-agent meets all stated criteria but leaves a dangerous public API that leaks raw shared secrets.

**Fix:** Either:
1. Add to "What to Build": "Remove `identity_derive_shared_key()` from `identity.h` if present (Phase 1 artifact)"
2. Or change criterion: "Shared ECDH keys are never exposed in public API (encrypt/decrypt are the only public methods)"

---

### 5. **IMPORTANT:** Token key-splitting not explicit in Token section
**Location:** Section 2 "Build Token class"

**Problem:** The Token struct and init function are defined:
```cpp
struct Token {
    uint8_t signing_key[32];
    uint8_t encryption_key[32];
};
void token_init(Token& t, const uint8_t derived_key[64]);
```

But **how** to split the 64-byte key isn't stated here. It's only mentioned in the encryption flow description ("signing_key = first 32 bytes, encryption_key = last 32 bytes").

**Impact:** Sub-agent implements `token_init()` with reversed key order (encryption first, signing second), breaking HMAC verification.

**Fix:** Add to Token section:
```cpp
void token_init(Token& t, const uint8_t derived_key[64]) {
    // Split: signing_key = derived_key[0:32], encryption_key = derived_key[32:64]
    memcpy(t.signing_key, derived_key, 32);
    memcpy(t.encryption_key, derived_key + 32, 32);
}
```

---

### 6. **IMPORTANT:** Destination hash function name assumed
**Location:** Section 1 "Restructure Identity struct"

**Problem:** Says:
> Fix `identity_destination_hash()` to use the two-step process

But the prompt never says this function exists or what its signature is. A sub-agent might:
- Create a function with the wrong signature
- Create it in the wrong file
- Not create it at all if they don't find it in existing code

**Impact:** Missing or wrong destination hash function → can't communicate with destinations.

**Fix:** Provide explicit signature:
```cpp
// Add to identity.h:
void identity_destination_hash(const char* app_name, const char* aspects[], 
                                size_t aspect_count, const Identity& id, 
                                uint8_t out[16]);
// Computes: sha256(sha256(app_name.aspect1.aspect2)[0:10] + identity.hash)[0:16]
```

---

### 7. **MINOR:** Overhead arithmetic error
**Location:** Encryption Flow description

**Problem:** Says:
> Total overhead: 32 (ephemeral pub) + 16 (IV) + padding + 32 (HMAC) = 48 + 32 = 80 bytes + padding

The math `48 + 32 = 80` is correct, but then saying `= 80 bytes + padding` is contradictory. It should be:
`32 + 16 + 32 = 80` (fixed overhead) `+ padding` (variable 1-16)

**Impact:** Confusion, but doesn't break implementation if they read the buffer sizing correctly.

**Fix:** Rewrite as:
> Total overhead: 32 (ephemeral) + TOKEN_OVERHEAD(48) + padding = 80 + padding (1-16 bytes)

---

### 8. **MINOR:** Missing RFC 5869 test vector
**Location:** Section 6 "Update tests" — HKDF test

**Problem:** Says to use "RFC 5869 Test Case 1" but doesn't provide values.

**Impact:** Sub-agent has to look it up (easy but extra step).

**Fix:** Include in prompt:
```
RFC 5869 Test Case 1 (SHA-256):
IKM  = 0x0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b (22 bytes)
salt = 0x000102030405060708090a0b0c (13 bytes)
info = 0xf0f1f2f3f4f5f6f7f8f9 (10 bytes)
L    = 42
Expected OKM = 0x3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865
```

---

### 9. **MINOR:** Buffer size comment grouping
**Location:** Section 3 "identity_encrypt signature"

**Problem:** Comment says:
> out must be at least 32 + 48 + plaintext_len + 16 (max padding) bytes

The grouping `32 + 48` obscures structure. Clearer:
> out must be at least 80 + plaintext_len + 16 bytes  
> (ephemeral_pub(32) + IV(16) + ciphertext + HMAC(32) + max_padding(16))

**Impact:** None (math is correct), just clarity.

**Fix:** Rewrite comment for clarity.

---

### 10. **CORRECTNESS CHECK:** All crypto flows verified ✓

I cross-checked every claim against source:
- ✅ Key ordering (X25519 first, Ed25519 second): CORRECT
- ✅ Identity hash = truncated SHA-256 of 64-byte public key: CORRECT
- ✅ Destination hash two-step (name_hash 10 bytes, then + identity.hash): CORRECT
- ✅ HKDF parameters (length=64, salt=identity.hash, context=None): CORRECT
- ✅ Key splitting (signing first 32, encryption last 32): CORRECT
- ✅ Token format (IV + ciphertext + HMAC): CORRECT
- ✅ Encrypt output (ephemeral_pub + token): CORRECT
- ✅ TOKEN_OVERHEAD = 48: CORRECT
- ✅ NAME_HASH_LENGTH = 10: CORRECT
- ✅ DERIVED_KEY_LENGTH = 64: CORRECT

**No contradictions found in crypto math.**

---

## Acceptance Criteria Gaps

Could a sub-agent meet all 10 criteria and still produce broken code?

**YES — Example scenario:**

1. Sub-agent reverses signing/encryption keys in `token_init()` (issue #5)
2. Sub-agent uses wrong HKDF method names (issue #1)
3. Sub-agent computes identity.hash with swapped key order (issue #2)
4. All 10 criteria are technically "met":
   - ✅ Identity.hash is computed (just wrong order)
   - ✅ HKDF implemented (just wrong API calls)
   - ✅ Token exists (just wrong key split)
   - ✅ Code compiles
   - ✅ Tests might even pass if test vectors are also wrong

**Result:** Firmware boots, encrypts data, but is 100% wire-incompatible with Python Reticulum.

**Missing implicit requirements:**
- "Wire-compatible with Reticulum" should be explicit criterion #11
- "Cross-verified against a Python Reticulum node" (integration test)
- "Test vectors must match Python RNS output for same inputs"

---

## Verdict

The prompt has **4 BLOCKER/IMPORTANT issues** that would cause wrong output:
1. HKDF API mismatch (#1)
2. Missing identity hash computation details (#2)
3. Unclear HKDF context=None handling (#3)
4. Token key-split order not explicit (#5)

The prompt has **2 IMPORTANT ambiguities** that assume prior knowledge:
5. Acceptance criterion #7 (remove derive_shared_key) (#4)
6. Destination hash function signature (#6)

And **3 MINOR clarity issues** (#7, #8, #9).

**Recommendation:** Fix the 6 IMPORTANT/BLOCKER issues before spawning a sub-agent. The crypto flows are correct, but the implementation guidance has critical gaps.
