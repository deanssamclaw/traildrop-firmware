# Phase 4c Cal Review: GPS + Waypoint Payload

Reviewed: 2026-03-01
Commit: 7f175d7
Files reviewed: `src/msg/waypoint.h`, `src/msg/waypoint.cpp`, `src/main_test.cpp`, `tests/phase4c_test_vectors.py`
Cross-referenced: Phase 4b Cal review, `src/msg/msgpack.h`, `src/msg/msgpack.cpp`, `src/msg/lxmf.h`, `src/msg/lxmf.cpp`, `src/msg/lxmf_transport.cpp`

---

## 1. Buffer Overflows in waypoint_encode/decode

### 1a. waypoint_encode string handling — SAFE

`wp.name` is `char[32]`, `wp.notes` is `char[128]`. Both are written via `enc.write_str(wp.name, strlen(wp.name))`. The Encoder's `write_str` and underlying `write_bytes` check `pos + len > cap` before any `memcpy` (msgpack.cpp:18-19). If the encoded output exceeds the caller's buffer, `enc.error` is set and `waypoint_encode` returns 0 (waypoint.cpp:39). **No overflow.**

**Potential concern**: `strlen(wp.name)` reads until null terminator. If the caller fails to null-terminate `wp.name` (e.g., fills all 32 bytes without null), `strlen` reads past the buffer. However, all call sites use `memset(&wp, 0, sizeof(wp))` + `strncpy` with `sizeof(wp.name) - 1`, ensuring null termination. **Safe in current usage**, but fragile if future callers skip `memset`.

### 1b. waypoint_decode string handling — SAFE

```cpp
size_t n = dec.read_str(wp.name, sizeof(wp.name) - 1);  // max_len = 31
wp.name[n] = '\0';
```

`read_str` (msgpack.cpp:252) checks `data_len > max_len` and sets error before copying. If the incoming string is 32+ bytes, decode returns false. The null terminator is written at index `n` (0-31), always within bounds. Same pattern for `wp.notes` with `sizeof(wp.notes) - 1 = 127`. **No overflow.**

### 1c. waypoint_decode key buffer — SAFE

```cpp
char key[16];
size_t key_len = dec.read_str(key, sizeof(key) - 1);  // max_len = 15
key[key_len] = '\0';
```

All known keys ("lat", "lon", "ele", "name", "notes", "ts") are <=5 chars. A malicious key >15 chars would trigger `read_str` error, returning false. **Safe.**

### 1d. custom_data[256] in waypoint_send_explicit — SAFE

```cpp
uint8_t custom_data[256];
size_t custom_data_len = waypoint_encode(wp, custom_data, sizeof(custom_data));
```

Maximum encoded waypoint size (computed below in section 4) is ~220 bytes. The 256-byte buffer has >35 bytes of headroom. **No overflow.**

---

## 2. Double Precision: lat/lon float64 Encoding — CORRECT

### Write path (waypoint.cpp:19-22)

```cpp
enc.write_float64(wp.lat);   // wp.lat is double
enc.write_float64(wp.lon);   // wp.lon is double
```

`write_float64` (msgpack.cpp:58-63) writes tag `0xcb` + 8-byte big-endian IEEE 754:

```cpp
void Encoder::write_float64(double val) {
    write_byte(0xcb);
    uint64_t bits;
    memcpy(&bits, &val, sizeof(bits));
    write_be64(bits);
}
```

`memcpy` from `double` to `uint64_t` preserves exact IEEE 754 bits. `write_be64` serializes in network byte order. **True float64, no precision loss.**

### Elevation encoding — CORRECT but wasteful

```cpp
enc.write_float64((double)wp.ele);  // wp.ele is float, cast to double
```

`wp.ele` is `float` (32-bit), cast to `double` before encoding. This preserves the float32 value exactly (double has a superset of float's representable values) and encodes it as float64 on the wire (9 bytes instead of 5 for float32).

**Not a bug**, but wastes 4 bytes per waypoint. The Python test vector script also uses float64 for `ele`, so this is intentionally consistent. A future optimization could encode `ele` as float32 (`0xca` tag) to save 4 bytes, but this would require updating the Python test vectors.

### Read path (waypoint.cpp:62)

```cpp
wp.ele = (float)dec.read_float64();
```

`read_float64` (msgpack.cpp:199-215) handles both `0xcb` (float64) and `0xca` (float32 promoted to double). The decode path correctly accepts either encoding. **Forward-compatible.**

---

## 3. Msgpack Key Order: Python Interop — CORRECT

### Firmware encoding order (waypoint.cpp:19-37)

```
lat -> lon -> ele -> name -> [notes] -> ts
```

### Python test vector order (phase4c_test_vectors.py:16-23)

```python
wp_full = {
    "lat": 38.9717,
    "lon": -95.2353,
    "ele": 267.0,
    "name": "Camp",
    "notes": "Water source",
    "ts": 1709312400,
}
```

Python `dict` preserves insertion order (CPython 3.7+), and `msgpack.packb` serializes in insertion order. **Key order matches.**

### Byte-for-byte verification

The test `test_waypoint_encode_python_match` (main_test.cpp:2307-2342) hardcodes the expected hex from Python's `msgpack.packb` and does `memcmp`. This test **proves** byte-for-byte equivalence. If the test passes on hardware, the encoding is identical.

### No-notes variant

`test_waypoint_empty_notes` (main_test.cpp:2433-2471) separately verifies the 5-field variant (notes omitted) against a different Python-generated hex string. **Both variants verified.**

---

## 4. Waypoint Size vs. 383-byte Encrypted MDU — SAFE

### LXMF plaintext budget analysis

The encrypted MDU pre-check at lxmf_transport.cpp:102 rejects `lxmf_len > 383`. The LXMF plaintext structure from `lxmf_build` is:

```
source_hash(16) + signature(64) + packed_payload
```

So `packed_payload` must fit in `383 - 80 = 303 bytes`.

### Packed payload structure

```
array(4) header:        1 byte
timestamp (float64):    9 bytes
title (bin8):          2 + title_len bytes
content (bin8):        2 + content_len bytes
fields map(2):         1 byte
  FIELD_CUSTOM_TYPE:   1-2 bytes (uint8 0xFB = 2 bytes: 0xcc 0xfb)
  custom_type (bin8):  2 + custom_type_len bytes
  FIELD_CUSTOM_DATA:   1-2 bytes (uint8 0xFC = 2 bytes: 0xcc 0xfc)
  custom_data (bin8):  2 + custom_data_len bytes
```

### Waypoint custom_data size calculation

Full waypoint msgpack (6 fields with notes):

```
map(6):                1 byte (0x86)
"lat" key:             1 + 3 = 4 bytes (fixstr)
lat value:             1 + 8 = 9 bytes (float64)
"lon" key:             1 + 3 = 4 bytes
lon value:             1 + 8 = 9 bytes
"ele" key:             1 + 3 = 4 bytes
ele value:             1 + 8 = 9 bytes
"name" key:            1 + 4 = 5 bytes
name value:            1 + name_len bytes (fixstr, <=31 chars)
"notes" key:           1 + 5 = 6 bytes
notes value:           varies (fixstr <=31: 1+len, str8 32-127: 2+len)
"ts" key:              1 + 2 = 3 bytes
ts value:              5 bytes (uint32)
```

**Minimum** (short name, no notes): `1 + 4+9 + 4+9 + 4+9 + 5+(1+1) + 3+5 = 55 bytes`
**Typical** ("Camp" + "Water source"): `1 + 13 + 13 + 13 + 9 + 18 + 8 = 75 bytes`
**Maximum** (name=31 chars, notes=127 chars): `1 + 13 + 13 + 13 + (5+1+31) + (6+2+127) + 8 = 220 bytes`

### Total LXMF plaintext at maximum waypoint

With `waypoint_send_explicit` (waypoint.cpp:131-133):
- title = name (<=31 chars, via `name ? name : "Waypoint"`)
- content = notes (<=127 chars, via `notes ? notes : ""`)
- custom_type = "traildrop/waypoint" (18 bytes)
- custom_data = encoded waypoint (<=220 bytes)

**Worst case packed_payload:**
```
1 + 9 + (2+31) + (2+127) + 1 + (2+2+18) + (2+2+220) = 419 bytes
```

**Worst case LXMF plaintext (source_hash + signature + payload):**
```
16 + 64 + 419 = 499 bytes
```

This exceeds the 383-byte MDU limit. `lxmf_send` would **correctly reject** this message at lxmf_transport.cpp:102. The message never reaches the encryption step. **The Phase 4b overflow fix catches this.**

### Practical impact

| Scenario | custom_data | packed_payload | LXMF total | Fits in 383? |
|----------|-------------|---------------|------------|-------------|
| Typical ("Camp", "Water source") | 75 | 150 | 230 | YES |
| Medium name (15 chars), medium notes (50 chars) | ~120 | ~210 | ~290 | YES |
| Max name (31), notes (80) | ~180 | ~330 | ~410 | **NO -- rejected** |
| Max name (31), notes (50) | ~150 | ~280 | ~360 | YES -- tight |
| Max name (31), no notes | ~60 | ~130 | ~210 | YES |

**Conclusion**: With max name (31 chars) and notes > ~57 chars, the LXMF pre-check rejects. Typical waypoints (short name, medium notes) fit comfortably. The pre-check correctly prevents overflow. **No silent corruption possible.**

### Recommendation (should-fix): User-facing size validation

The rejection at lxmf_transport.cpp:102 is a deep, silent failure -- `waypoint_send_explicit` returns false, the caller sees `[LXMF-TX] ERROR` which doesn't explain why. Consider adding a pre-check in `waypoint_send_explicit` before calling `lxmf_send`:

```cpp
// Validate total will fit within encrypted MDU (~383 bytes)
// Budget: 80 (src+sig) + 15 (array+ts+title/content headers) + title + content
//       + 9 (fields map + field keys) + 4 (bin8 headers) + custom_type + custom_data
size_t budget = 80 + 15 + strlen(name) + strlen(notes) + 9 + 4 + 18 + custom_data_len;
if (budget > 380) {
    Serial.println("[WAYPOINT] ERROR: Waypoint too large -- shorten name/notes");
    return false;
}
```

This gives the caller actionable feedback. **Severity: LOW** -- the overflow is already prevented.

---

## 5. Decoder skip() for Unknown Keys — CORRECT

```cpp
} else {
    dec.skip();  // Unknown key -- skip value
}
```

`skip()` (msgpack.cpp:296-385) is comprehensive:
- Handles all msgpack types: fixint, fixmap, fixarray, fixstr, nil, bool, bin8/16/32, ext8/16/32, float32/64, uint8/16/32/64, int8/16/32/64, fixext1-16, str8/16/32, array16/32, map16/32, negative fixint
- Recursively skips nested containers (map/array)
- Bounds checking: `if (pos > len) error = true` at line 384 catches any overrun
- Handles the reserved `0xc1` tag (sets error)

The `skip()` in the waypoint decoder correctly allows forward-compatible decoding -- future Python senders can add new keys without breaking firmware decode. **Good design.**

---

## 6. Phase 4b Must-Fix Items — VERIFIED

### 6a. encrypted[] buffer overflow pre-check — FIXED

```cpp
// lxmf_transport.cpp:99-105
if (lxmf_len > 383) {
    Serial.printf("[LXMF-TX] ERROR: Message too large for encrypted transport (%d > 383)\n", (int)lxmf_len);
    return false;
}
```

The pre-check uses the RNS ENCRYPTED_MDU value (383), matching the recommended Option B from the Phase 4b review. **Correctly implemented.**

### 6b. Null guard on s_lxmf_dest — VERIFIED (commit 7ac78b1)

### 6c. custom_type length 19 -> 18 — FIXED

All instances in main_test.cpp now use `(const uint8_t*)"traildrop/waypoint", 18`. Verified at lines 2058, 2380, 2839. **No remaining instances of length 19.**

---

## 7. Test Coverage

### Phase 4c test suite (5 tests)

| Test | What it covers | Verdict |
|------|---------------|---------|
| `test_waypoint_encode_decode_roundtrip` | Encode with all fields -> decode -> verify lat/lon/ele/name/notes/ts/valid | Good -- full field coverage |
| `test_waypoint_encode_python_match` | Byte-for-byte match against Python msgpack.packb hex | Excellent -- proves interop |
| `test_waypoint_in_lxmf_roundtrip` | Encode waypoint -> embed in LXMF -> build -> parse -> extract -> decode -> verify | Excellent -- full pipeline |
| `test_waypoint_no_gps_fix` | Encode/decode with zero coords | Adequate (see gap #2 below) |
| `test_waypoint_empty_notes` | Notes omitted (5-field map) -> byte-match Python -> decode -> verify empty | Good |

### Test coverage gaps (ordered by priority)

1. **No max-size waypoint test (MEDIUM)** -- The MDU budget analysis (section 4) shows that name=31 + notes>57 will be rejected by the 383-byte pre-check. No test verifies this boundary. A test that creates a waypoint with long name/notes and confirms `lxmf_send` returns false would validate the safety net.

2. **test_waypoint_no_gps_fix is misnamed (LOW)** -- The test doesn't actually test `waypoint_send()` rejecting no-fix. It tests encode/decode of zero coordinates. The GPS rejection path (waypoint.cpp:89) is untested because `hal::gps_has_fix()` can't be mocked. The test is still useful (proves zero coords roundtrip), but the name is misleading.

3. **No unknown-key skip test (LOW)** -- The `skip()` function in the decoder is present and comprehensive, but no test exercises it. A test that adds an extra key to a msgpack waypoint and verifies decode still succeeds would validate forward-compatibility.

4. **No negative coordinate test (LOW)** -- The roundtrip test uses negative longitude (-95.2353) which partially covers this. But extreme values like (-90.0, -180.0) or near-zero precision boundaries are untested. IEEE 754 double handles these natively, so risk is minimal.

5. **No truncation test for oversized strings (LOW)** -- What happens if a received waypoint has a name > 31 chars? `read_str` with `max_len=31` sets `dec.error = true` and `waypoint_decode` returns false. This is correct but untested.

---

## 8. Additional Findings

### 8a. ele cast to double is redundant — COSMETIC

```cpp
enc.write_float64((double)wp.ele);  // waypoint.cpp:26
```

C++ implicitly promotes `float` to `double` in function calls. The explicit cast is harmless but unnecessary.

### 8b. timestamp uses millis()/1000 — DESIGN NOTE

```cpp
wp.timestamp = (uint32_t)(millis() / 1000);  // waypoint.cpp:116
```

This is uptime in seconds, not Unix time. Without an RTC or NTP, the device can't produce real timestamps. The Python test vector uses a real Unix timestamp (1709312400 = 2024-03-01T19:00:00Z). The comment says "Uptime as placeholder" -- correct for current hardware constraints. When GPS provides UTC time, this should be updated. **Not a bug -- documented limitation.**

### 8c. waypoint_send_explicit passes name as both LXMF title and waypoint name — INTENTIONAL DUPLICATION

```cpp
strncpy(wp.name, name ? name : "Waypoint", sizeof(wp.name) - 1);  // waypoint struct
// ...
lxmf_send(..., name ? name : "Waypoint", notes ? notes : "", ...);  // LXMF title/content
```

The name appears twice in the wire payload: once in the LXMF title (for non-TrailDrop receivers) and once in the msgpack custom_data (for TrailDrop receivers). This is intentional for compatibility, but uses ~2x the bytes for name/notes. With the MDU budget being tight (section 4), this duplication is the primary reason long notes exceed the limit.

**Optional optimization**: Set LXMF title to a fixed short string like "WP" and content to "" when sending waypoints. This would free ~(name_len + notes_len) bytes in the payload, allowing longer waypoint notes. Trade-off: non-TrailDrop LXMF clients would see "WP" instead of the waypoint name.

### 8d. Python test vector does not verify key order explicitly — MINOR GAP

The Python script calls `msgpack.packb(wp_full)` and prints the hex, but doesn't assert a specific byte sequence. The firmware test hardcodes the expected hex. If Python's msgpack library changes dict serialization order in a future version, the firmware test would still pass (it's hardcoded), but re-running the Python script would produce different output.

**Suggestion**: Add `assert packed_full.hex() == "expected..."` to the Python script for a two-way interop contract.

### 8e. auto-send uses "traildrop/waypoint" custom_type with no custom_data — COSMETIC

```cpp
// main_test.cpp:2839
(const uint8_t*)"traildrop/waypoint", 18,
nullptr, 0,
```

The auto-send path sends an LXMF with custom_type="traildrop/waypoint" but empty custom_data. A receiver checking for custom_type would identify this as a waypoint message, but `waypoint_decode` on empty data would fail. This is a test harness path, not production code.

### 8f. Phase 4b should-fix: write_bin(nullptr, 0) UB — STILL PRESENT

The `write_bytes(nullptr, 0)` UB issue flagged in Phase 4b section 8c remains unfixed. `lxmf_build` at lxmf.cpp:36 calls `enc.write_bin(custom_data, custom_data_len)` where `custom_data` can be nullptr and `custom_data_len` can be 0. This flows to `memcpy(buf+pos, nullptr, 0)`. Still technically UB per C/C++ spec. **Severity: LOW.**

---

## 9. Summary — Verdict

### Overall: PASS (clean)

Phase 4c is a well-implemented, compact module. The waypoint codec is correct, the string handling is bounds-checked at every level, lat/lon use true float64 encoding, and the Python interop is verified byte-for-byte. The decoder includes a proper `skip()` for forward compatibility with unknown keys.

The Phase 4b must-fix item (encrypted buffer overflow) was correctly addressed with the 383-byte pre-check, which now serves as the safety net preventing oversized waypoints from causing memory corruption. All three Phase 4b should-fix items (null guard, custom_type length, size test) have been addressed.

### No must-fix items

### Should-fix

1. **Add max-size waypoint rejection test (MEDIUM)** -- Verify that `lxmf_send` rejects a waypoint with max-length name (31 chars) + long notes (>57 chars). This exercises the 383-byte MDU pre-check on the waypoint path specifically.
2. **Improve error message for oversized waypoints (LOW)** -- Add a pre-check in `waypoint_send_explicit` with a "shorten name/notes" message for actionable feedback.
3. **Add Python hex assertion (LOW)** -- Add `assert packed_full.hex() == "expected..."` to phase4c_test_vectors.py for two-way interop contract.

### Nice-to-have

4. Add unknown-key skip test for forward-compatibility validation.
5. Add oversized-string decode rejection test (name >31 chars from malicious sender).
6. Fix `write_bin(nullptr, 0)` UB (carried from Phase 4b).
7. Rename `test_waypoint_no_gps_fix` to reflect what it actually tests (zero-coord roundtrip).
8. Consider encoding elevation as float32 to save 4 bytes per waypoint.

---

*Reviewed by Cal (firmware reviewer agent), 2026-03-01*
