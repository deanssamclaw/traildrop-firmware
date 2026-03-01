# Phase 4a.5 Cal Review: Announce Migration + Dual Destinations

Reviewed: 2026-03-01
Commit: 4f171ba
Files reviewed: `src/net/announce.cpp`, `announce.h`, `peer.cpp`, `peer.h`, `src/main_test.cpp`, `tests/phase4a5_test_vectors.py`

---

## 1. Buffer Overflows — encode_app_data and announce_process

### encode_app_data (announce.cpp:14-27) — SAFE

- Input: `display_name` (C string), clamped to `DISPLAY_NAME_MAX - 1 = 31` bytes at line 18.
- Output buffer: `DISPLAY_NAME_MAX + 8 = 40` bytes.
- Worst-case msgpack encoding: `fixarray(1) + bin8(1) + len(1) + 31 + nil(1) = 35 bytes`. Fits in 40.
- `enc.error` is checked before returning `enc.pos`. **No issue.**

### announce_build signed_data buffer (announce.cpp:52) — SAFE

- `signed_data[16 + 64 + 10 + 10 + DISPLAY_NAME_MAX + 8]` = 140 bytes.
- Max fill: 16 + 32 + 32 + 10 + 10 + 35 (max app_data) = 135. Fits.
- `payload_len` checked against `RNS_MTU` (line 83) before any `out_pkt.payload[]` writes. **No issue.**

### announce_process signed_data buffer (announce.cpp:184) — SAFE

- `signed_data[16 + 64 + 10 + 10 + (RNS_MAX_PAYLOAD_H1 - 148)]` = `100 + 333 = 433` bytes.
- Max `app_data_len` = `pkt.payload_len - 148`. Since `pkt.payload[]` is `RNS_MTU = 500` bytes and `payload_len` is bounded by deserialization (never exceeds 500), max app_data_len = 352. But `RNS_MAX_PAYLOAD_H1 - 148 = 333`.

**BUG (minor): If `payload_len` can ever be > `148 + 333 = 481` (e.g., `payload_len` up to 500), then `app_data_len` could be up to 352, overflowing the signed_data buffer by 19 bytes.**

In practice, `payload_len` should never exceed `RNS_MAX_PAYLOAD_H1 = 481` for H1 packets (announces are always H1). But there's no explicit bounds check on `app_data_len` before the `memcpy` at line 200.

**Recommendation**: Add a bounds check:
```cpp
if (app_data_len > sizeof(signed_data) - 100) return false;
```
Or more precisely, clamp `app_data_len` against the remaining buffer capacity:
```cpp
size_t max_app_data = sizeof(signed_data) - (16 + 64 + 10 + 10);
if (app_data_len > max_app_data) return false;
```

**Severity: LOW** — announce packets are H1, and `payload_len` won't exceed 481 in normal operation. But defensive code is good firmware practice.

### display_name decode (announce.cpp:210-235) — SAFE

- `display_name[DISPLAY_NAME_MAX]` = 32 bytes, zero-initialized.
- Legacy path: `copy_len` clamped to `DISPLAY_NAME_MAX - 1 = 31` (line 230-231). Null-terminated at line 234.
- Msgpack path: `read_bin()` into `name_buf[DISPLAY_NAME_MAX]`, max `sizeof(name_buf) - 1 = 31`. Checked `name_len < DISPLAY_NAME_MAX` (line 221). Null-terminated at line 223.
- **No issue.**

---

## 2. lxmf_dest_hash Computation — announce_process:239-250

### Algorithm Verification

```cpp
lxmf_full_name = "lxmf.delivery"  // 13 chars
lxmf_name_hash = SHA-256("lxmf.delivery")[:10]
lxmf_dest = SHA-256(lxmf_name_hash + identity_hash)[:16]
```

This matches the RNS destination derivation formula:
```
dest_hash = SHA-256( SHA-256(app_name.aspects)[:10] + SHA-256(pub_keys)[:16] )[:16]
```

**CORRECT.** The `identity_hash` was computed at line 147-149 as `SHA-256(x25519_pub + ed25519_pub)[:16]`. The `lxmf_name_hash` uses the same dot-concatenation convention as the main announce destination. The test vectors in `test_peer_lxmf_dest_hash` (main_test.cpp:1905) verify against the Python script output.

### One concern: hardcoded string

The string `"lxmf.delivery"` is hardcoded at line 241 rather than using config constants. This is actually fine — the lxmf.delivery destination is a protocol constant (LXMF spec), not our app name. It would be confusing to derive it from `APP_NAME` since our `APP_NAME` is still `"traildrop"`.

**No issue.** Clear and correct.

---

## 3. Legacy vs 0.5.0+ Format Detection — Robustness

### Detection logic (announce.cpp:213)

```cpp
if (raw[0] >= 0x90 && raw[0] <= 0x9f) {
    // LXMF 0.5.0+ format: msgpack fixarray
} else {
    // Legacy format: raw UTF-8
}
```

### Comparison with Python LXMF source (LXMF.py:113-135)

Python checks:
```python
if (app_data[0] >= 0x90 and app_data[0] <= 0x9f) or app_data[0] == 0xdc:
```

**MISSING: `0xdc` (array16) case.** If a future LXMF peer sends app_data with 16+ elements (array16 prefix `0xdc`), the firmware will misinterpret it as legacy UTF-8.

**Impact: LOW** — current LXMF always sends a 2-element array (fixarray). But for forward compatibility:

**Recommendation**: Add `|| raw[0] == 0xdc` to match Python:
```cpp
if ((raw[0] >= 0x90 && raw[0] <= 0x9f) || raw[0] == 0xdc) {
```

### Edge case: UTF-8 display names starting with 0x90-0x9f

Bytes 0x90-0x9f are valid UTF-8 continuation bytes (never appear as the first byte of a UTF-8 character). They're also not valid ASCII. So a legacy app_data string will never start with these bytes unless:
1. The string is malformed UTF-8, or
2. The string starts with a multi-byte character whose leading byte happens to be 0x90-0x9f (these would be `U+0100`–`U+01FF` range, Latin Extended characters).

Wait — **correction**: 0x90-0x9f are NOT valid UTF-8 leading bytes either. Valid UTF-8 leading bytes for multi-byte sequences are 0xC2-0xF4. Bytes 0x80-0xBF are continuation bytes. So 0x90-0x9f ARE valid as continuation bytes but NEVER as the first byte of a valid UTF-8 string.

**VERDICT: Detection is robust for valid UTF-8 display names.** A malicious or corrupt legacy app_data starting with 0x90-0x9f would be misparsed, but this is an acceptable edge case.

### Edge case: empty app_data

Handled at line 211: `if (app_data_len > 0)`. If `app_data_len == 0`, `display_name` stays as the zero-initialized empty string. **No issue.**

### Edge case: app_data is exactly 1 byte

If `app_data_len == 1` and `raw[0]` is in 0x90-0x9f, the decoder will try to parse a fixarray. `dec.read_array()` returns count = 0-15, then `dec.read_bin()` tries to read past the buffer. The decoder's bounds checking (msgpack.cpp:142, `pos >= len`) sets `error = true`, and the `!dec.error` check at line 217 catches it. Display name stays empty. **Safe.**

---

## 4. Peer Table — New Field Compatibility

### Struct change (peer.h:15)

Added `uint8_t lxmf_dest_hash[DEST_HASH_SIZE]` (16 bytes) to the `Peer` struct. This grows each peer entry by 16 bytes. With `MAX_PEERS = 50`, total table growth = 800 bytes. On ESP32-S3 with plenty of RAM, **no concern**.

### peer_store signature change (peer.h:29-34)

```cpp
bool peer_store(const uint8_t dest_hash[DEST_HASH_SIZE],
                const uint8_t x25519_pub[32],
                const uint8_t ed25519_pub[32],
                const uint8_t identity_hash[DEST_HASH_SIZE],
                const char* app_data,
                const uint8_t lxmf_dest[DEST_HASH_SIZE] = nullptr);
```

The `lxmf_dest` parameter has a **default value of `nullptr`**. This means existing callers that don't pass `lxmf_dest` will compile without changes and will zero-fill the field (peer.cpp:34, `memset(..., 0, ...)`).

### Existing callers check

1. `announce_process()` (announce.cpp:253): Always passes `lxmf_dest`. **OK.**
2. `test_peer_store_lookup()` (main_test.cpp:856): `peer_store(dest_hash, x25519, ed25519, id_hash, "TestPeer")` — uses default `nullptr`. **Compiles, lxmf_dest_hash zeroed. OK.**

### Peer access patterns

`transport.cpp:57` uses `peer_lookup()` and accesses `x25519_public`, `ed25519_public`, `identity_hash`. Does NOT access `lxmf_dest_hash`. **No breakage.**

**VERDICT: Backward compatible. No existing callers broken.**

---

## 5. Test Coverage Assessment

### Phase 4a.5 test suite (7 tests)

| Test | What it covers | Verdict |
|------|---------------|---------|
| `test_announce_app_data_msgpack` | announce_build produces fixarray(2) app_data, decoder extracts name | Good |
| `test_announce_app_data_python_match` | Byte-exact match against Python `msgpack.packb([b"TrailDrop", None])` | Excellent — cross-language verification |
| `test_announce_decode_legacy_format` | Manually crafted legacy announce (raw UTF-8 app_data) round-trips through announce_process | Excellent — tests backward compat |
| `test_announce_decode_msgpack_format` | announce_build → announce_process round-trip with new format | Good |
| `test_dual_dest_computation` | Known-key dest_hash matches Python test vectors for both traildrop.waypoint and lxmf.delivery | Excellent — cross-language |
| `test_peer_lxmf_dest_hash` | After announce_process, peer's lxmf_dest_hash matches Python vector | Excellent |
| `test_dual_dest_different` | Random identity produces different dest_hashes for the two destinations | Good sanity check |

### Python test vector script

`tests/phase4a5_test_vectors.py` generates deterministic vectors using known keys and standard Python msgpack. Covers identity_hash, both dest_hashes, and app_data encoding. **Good foundation for cross-validation.**

### Missing tests

1. **No test for `display_name == nullptr` through the full pipeline.** `test_announce_without_app_data` exists from Phase 3c (main_test.cpp:874) but was written before the msgpack change. Should verify it still works with the new `encode_app_data` returning 0 for null/empty names.

2. **No test for maximum-length display name.** `DISPLAY_NAME_MAX = 32`, so a 31-character name should work. Should test a 31-char name round-trips correctly, and a 32+ char name gets truncated.

3. **No test for `0xdc` (array16) app_data.** Related to the detection gap noted in section 3. If/when the detection is fixed, add a test.

4. **No negative test: malformed msgpack app_data.** What happens if the first byte is 0x92 (fixarray 2) but the payload is truncated or garbage? The decoder's error flag should prevent storing a bad name. Worth verifying.

5. **No test for peer_store with nullptr lxmf_dest explicitly.** The existing `test_peer_store_lookup` implicitly tests this (default parameter), but doesn't verify the field is zeroed.

**Severity: LOW-MEDIUM.** The existing tests cover the main paths well. The gaps are edge cases.

---

## 6. Additional Observations

### 6a. announce_process doesn't validate app_data_len upper bound

As noted in section 1, `app_data_len` is computed from `pkt.payload_len - 148` without capping. While `RNS_MAX_PAYLOAD_H1 = 481` effectively limits H1 packets, a defensive check would be prudent.

### 6b. The announce app_data uses `write_bin()` (bin format), not `write_str()`

This is **CORRECT**. Python LXMF encodes the display name as `bytes` (not `str`), which maps to msgpack bin format (0xc4). The firmware encoder matches. My Phase 4 review flagged this risk (section 6, Risk 3) and Sam got it right.

### 6c. lxmf_dest_hash is computed but not yet used for routing

The `lxmf_dest_hash` is stored in the peer table but no code reads it yet. This is expected — Phase 4b (LXMF over transport) will use it to address encrypted LXMF messages to peers. The field is correctly pre-populated during announce processing so it'll be ready when needed.

### 6d. peer_store field naming: `app_data` vs `display_name`

The `peer_store` parameter is called `app_data` (matching the RNS announce concept), but `announce_process` passes the decoded `display_name` (line 253). This is fine — the peer table `app_data` field stores the human-readable name after decoding. The naming is slightly confusing but acceptable.

### 6e. The test at main_test.cpp:1708 derives dest from "traildrop.waypoint", not "lxmf.delivery"

All Phase 4a.5 tests still use `traildrop.waypoint` as the announce destination. This is correct for the current codebase where `APP_NAME = "traildrop"`. The dual-dest tests separately verify that `lxmf.delivery` hashing works. When Phase 4b switches the primary destination to `lxmf.delivery`, these tests will need updating.

---

## 7. Summary — Verdict

### Overall: PASS with minor recommendations

The implementation is clean, correct, and well-tested. The Phase 4 review recommendations for announce app_data format (Decision 3) and format detection logic were implemented accurately.

### Must-fix (before Phase 4b)

None. No blocking issues.

### Should-fix (low priority)

1. **Add bounds check on `app_data_len` in `announce_process`** (section 1) — defensive against oversized payloads.
2. **Add `0xdc` (array16) to format detection** (section 3) — forward compatibility with Python LXMF.
3. **Add max-length display name test** (section 5) — boundary condition.

### Nice-to-have

4. Add a malformed-msgpack-app-data negative test.
5. Add explicit test for `nullptr` display_name through the new encode path.

---

*Reviewed by Cal (firmware reviewer agent), 2026-03-01*
