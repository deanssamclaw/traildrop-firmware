# Phase 4 Cal Review: LXMF Message Layer

Reviewed: 2026-03-01
Source verified: Python LXMF source on rflab-sam (`/usr/local/lib/python3.13/dist-packages/LXMF/`)
Firmware codebase: all of `src/net/`, `src/crypto/`, `include/config.h`, `src/hal/gps.h`

---

## 1. Wire Format Verification

### VERDICT: Sam's analysis is CORRECT with caveats

**Packed message structure** — CONFIRMED (LXMessage.py:387-391)
```
dest_hash(16) + source_hash(16) + signature(64) + msgpack(payload)
```

**Payload array** — CONFIRMED (LXMessage.py:367)
```python
self.payload = [self.timestamp, self.title, self.content, self.fields]
```

**Hash computation** — CONFIRMED (LXMessage.py:369-373)
```python
hashed_part = dest_hash + source_hash + msgpack.packb(payload)
message_hash = SHA256(hashed_part)  # RNS.Identity.full_hash
```

**Signature** — CONFIRMED (LXMessage.py:380-383)
```python
signed_part = hashed_part + message_hash
signature = source_destination.sign(signed_part)  # Ed25519
```

**Opportunistic delivery** — CONFIRMED (LXMessage.py:629)
```python
# Packet data EXCLUDES dest_hash (inferred from RNS packet header):
return RNS.Packet(delivery_dest, self.packed[DESTINATION_LENGTH:])
# So encrypted plaintext = source_hash(16) + sig(64) + packed_payload
```

**Receive-side reconstruction** — CONFIRMED (LXMRouter.py:1822-1824)
```python
lxmf_data  = b""
lxmf_data += packet.destination.hash  # prepend dest_hash
lxmf_data += data                     # source_hash + sig + packed_payload
```

### Constants verified against Python runtime:
| Constant | Value | Source |
|---|---|---|
| DESTINATION_LENGTH | 16 bytes | TRUNCATED_HASHLENGTH(128)//8 |
| SIGNATURE_LENGTH | 64 bytes | SIGLENGTH(512)//8 |
| TIMESTAMP_SIZE | 8 bytes | LXMessage.py:60 |
| STRUCT_OVERHEAD | 8 bytes | LXMessage.py:61 |
| LXMF_OVERHEAD | 112 bytes | 2*16 + 64 + 8 + 8 |
| ENCRYPTED_PACKET_MAX_CONTENT | 295 bytes | LXMessage.py:78 |
| RNS.Packet.ENCRYPTED_MDU | 383 bytes | Runtime verified |

---

## 2. Size Computation — Sam's Numbers Are Off

Sam computed:
```
RNS_MTU = 500
H1 packet: Max payload = 500 - 19 = 481 bytes
Encryption overhead: ~96 bytes
Max plaintext: ~385 bytes
```

**WRONG.** The actual RNS computation (Reticulum.py:154):
```python
MDU = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE = 500 - 35 - 1 = 464
```

RNS uses HEADER_MAXSIZE (35 bytes for H2), not HEADER_MINSIZE (19 bytes for H1), plus 1 byte for IFAC (interface authentication tag). This is conservative by design.

**Encryption MDU** (Packet.py:106):
```python
ENCRYPTED_MDU = floor((464 - 48 - 32) / 16) * 16 - 1
             = floor(384 / 16) * 16 - 1
             = 384 - 1 = 383
```

Where:
- 48 = TOKEN_OVERHEAD (IV 16 + HMAC 32)
- 32 = ephemeral X25519 public key (KEYSIZE//16 = 512//16)
- 16 = AES128_BLOCKSIZE
- -1 = minimum PKCS7 padding byte

**LXMF max content** (LXMessage.py:67-78):
```python
ENCRYPTED_PACKET_MDU = ENCRYPTED_MDU + TIMESTAMP_SIZE = 383 + 8 = 391
ENCRYPTED_PACKET_MAX_CONTENT = 391 - 112 + 16 = 295
```

**Note on the +TIMESTAMP_SIZE**: This looks like a sizing bug in LXMF that inflates the limit by 8 bytes. Actual max content for an encrypted opportunistic packet should be ~287 bytes. Messages with content 288-295 bytes would pass the LXMF check but fail at the RNS packet layer. **This does NOT affect us** — our waypoints are ~80 bytes, well within any limit.

**For the firmware**: Use 295 as the constant to match Python LXMF behavior. Our waypoints won't come close.

### Firmware header discrepancy (minor)

The firmware defines `RNS_MAX_PAYLOAD_H1 = 481` (config.h:102), which doesn't account for:
- IFAC_MIN_SIZE (1 byte) — typically unused on raw LoRa
- H2 header size (RNS uses HEADER_MAXSIZE for conservative MDU)

This is fine for ESP32→ESP32 but should be documented. For LXMF interop, always use the LXMF content limits, not raw payload limits.

---

## 3. CRITICAL: Stamp Handling on Receive

**Sam's doc does not mention this.** The payload array can have 5 elements when a stamp is included (LXMessage.py:376-378):
```python
if not self.defer_stamp:
    self.stamp = self.get_stamp()
    if self.stamp != None: self.payload.append(self.stamp)
```

On receive, unpack_from_bytes (LXMessage.py:742-745) STRIPS the stamp and RE-PACKS:
```python
if len(unpacked_payload) > 4:
    stamp = unpacked_payload[4]
    unpacked_payload = unpacked_payload[:4]
    packed_payload = msgpack.packb(unpacked_payload)  # RE-PACK without stamp
```

The hash is then computed from the RE-PACKED 4-element payload. This means:

1. **We must handle 5-element payloads** when receiving from Sideband/NomadNet
2. **The hash is ALWAYS over the 4-element payload** (not including stamp)
3. **Re-packing must produce identical bytes** — our msgpack encoder must use canonical (most compact) encoding to match Python's umsgpack

**For ESP32→ESP32 (no stamps)**: Not an issue. Payload is always 4 elements.
**For Python→ESP32 interop**: Must strip element [4] and re-pack before hash verification.

**Implementation note**: Rather than re-packing, we can slice the raw bytes. If we know where element [4] starts in the msgpack stream, we can rewrite just the array header (fixarray 0x94→0x94, or if stamps change the encoding, adjust). But the simplest correct approach is: unpack, truncate to 4 elements, re-pack, hash.

---

## 4. Sub-Phase Breakdown Review

### Phase 4a: msgpack + LXMF message format — CORRECT, needs additions

The scope is right: implement msgpack, build/parse LXMF messages, test with Python vectors.

**Missing from 4a:**
1. **Destination change**: Must switch from `traildrop.waypoint` to `lxmf.delivery` (see design decision #2 below). This changes `destination_derive()` calls throughout the codebase.
2. **Announce app_data format change**: Must switch from raw bytes to msgpack array `[display_name_bytes, stamp_cost_or_nil]` (see design decision #3 below).
3. **Stamp stripping logic**: Even for 4a tests, the receive path must handle 5-element payloads.

**Acceptance criteria adjustment**: In addition to "Python can unpack_from_bytes() it", add: "Python Sideband can send a stamped LXMF message and ESP32 correctly verifies its signature."

### Phase 4b: LXMF over transport — CORRECT

Good scope. The integration with `transport_send_data()` and `transport_poll()` dispatch is straightforward. The key addition is that received DATA packets now carry sender identity (via LXMF source_hash), solving the `nullptr` sender problem in `data_callback_t`.

**One concern**: `transport_init()` currently takes a single `Destination`. If we change the app_name to "lxmf" with aspect "delivery", the destination hash changes. All existing peer tables and test scripts break. Plan for this.

**Suggestion**: Do the destination change in 4a, not 4b. That way 4a tests validate the new destination hashing, and 4b can focus purely on transport integration.

### Phase 4c: Waypoint payload + GPS — CORRECT

Good scope. GPS UART is initialized (hal/gps.h, TinyGPSPlus). The `gps_poll()`, `gps_latitude()`, `gps_longitude()`, `gps_altitude()` functions are already implemented.

**One addition**: Need GPS time for LXMF timestamps. If GPS has fix, use UTC from `TinyGPSPlus::time` and `::date`. If no fix, use millis()-based monotonic time (less useful but at least increases). Flag no-GPS-time messages so peers know the timestamp is unreliable.

### Phase 4d: Display UI — CORRECT, can defer

Low priority relative to 4a-4c. Can be Phase 5.

### Recommended order: 4a → 4b → 4c → 4d (unchanged)

The order is correct. 4a is the critical-path blocker. I'd suggest folding the destination/announce changes into 4a so that 4b has clean integration.

---

## 5. Design Decisions

### Decision 1: msgpack library

**Recommendation: Use mpack (https://github.com/ludocode/mpack)**

Rationale:
- Our structures are simple (small arrays, small maps, float64, binary, nil), BUT the decoder must handle the full msgpack spec because Python's umsgpack uses compact encodings (fixint, fixstr, fixarray, fixmap, bin8, float64, nil, etc.)
- Manual encoding is OK for the ENCODE side (we control the output format)
- Manual DECODING is dangerous — msgpack has many type codes (fixint 0x00-0x7f, fixmap 0x80-0x8f, fixarray 0x90-0x9f, fixstr 0xa0-0xbf, nil/bool/float/int/str/bin/array/map variants 0xc0-0xdf, negative fixint 0xe0-0xff). Missing ANY of these means a Python-sent message is silently misparsed.
- mpack is ~40KB compiled, streaming, well-tested, and handles all of this correctly
- Alternative: CMP library (https://github.com/camgunz/cmp) — also good, slightly smaller

**If flash space is a concern**: Hand-roll the encoder (we only need fixarray, float64, bin8, fixmap, fixint, nil — about 150 lines of C). Use mpack/CMP for the decoder only. But honestly, 40KB is nothing on ESP32-S3 (16MB flash).

**PlatformIO integration**: Add to platformio.ini `lib_deps`:
```
ludocode/mpack@^1.1.1
```
Or vendor the single-file version (mpack.h + mpack.c).

### Decision 2: LXMF app_name / destination

**Recommendation: Use `lxmf.delivery` as the primary destination. Drop `traildrop.waypoint`.**

Rationale:
- The whole point of using LXMF (instead of a custom format) is interop with Sideband, NomadNet, and other LXMF clients
- If we use `traildrop.waypoint`, no LXMF client will see our announces or be able to send us messages
- Python LXMF hard-codes `APP_NAME = "lxmf"` (LXMF.py:1) and aspect `"delivery"` (LXMRouter.py:338)
- Destinations on receive are reconstructed as `RNS.Destination(identity, ..., APP_NAME, "delivery")` (LXMessage.py:759)
- TrailDrop-specific functionality lives in the LXMF **fields** (`FIELD_CUSTOM_TYPE = 0xFB`, `FIELD_CUSTOM_DATA = 0xFC`), not in the destination name

**Impact on existing code:**
- `config.h`: Change `APP_NAME` from `"traildrop"` to `"lxmf"`, add `APP_ASPECT "delivery"`
- `destination_derive()`: Update to hash `"lxmf.delivery"` instead of `"traildrop.waypoint"`
- `announce_build()` / `announce_process()`: Update app_data format (see decision #3)
- `transport_init()`: Unchanged (still takes one Destination)
- Peer table: Existing peers become invalid (different dest_hash) — requires re-announce
- Python test scripts: Update destination hashing

If we ever want TrailDrop-specific discovery (peer X announces "I'm a TrailDrop device"), we can encode that in the LXMF fields or in the announce app_data as a future extension. The `FIELD_CUSTOM_TYPE = b"traildrop/waypoint"` already serves this purpose at the message level.

### Decision 3: Announce app_data format

**Recommendation: Match LXMF 0.5.0+ format — `msgpack([display_name_bytes, stamp_cost_or_nil])`**

Verified from source (LXMRouter.py:985-1000):
```python
def get_announce_app_data(self, destination_hash):
    peer_data = [display_name, stamp_cost]  # display_name is bytes or None, stamp_cost is int or None
    return msgpack.packb(peer_data)
```

And from the parser (LXMF.py:113-135):
```python
def display_name_from_app_data(app_data=None):
    # 0.5.0+ format: first byte is fixarray (0x90-0x9f) or array16 (0xdc)
    if (app_data[0] >= 0x90 and app_data[0] <= 0x9f) or app_data[0] == 0xdc:
        peer_data = msgpack.unpackb(app_data)
        return peer_data[0].decode("utf-8")
    # Old format: raw UTF-8 bytes
    else:
        return app_data.decode("utf-8")
```

Example encoding verified on rflab-sam:
```
msgpack([b"TrailDrop-1", None]) = 92 c4 0b 547261696c44726f702d31 c0
  0x92 = fixarray(2)
  0xc4 0x0b = bin8, length 11
  "TrailDrop-1" = 11 bytes
  0xc0 = nil
Total: 15 bytes
```

**Impact on firmware:**
- `announce_build()` currently takes `const char* app_data` and copies raw bytes. Must change to accept display name + stamp cost, then msgpack-encode internally (or accept pre-encoded bytes).
- `announce_process()` currently treats app_data as a raw string. Must add msgpack decode for the new format.
- This means **msgpack must be available before announce changes** — do msgpack first in 4a.

### Decision 4: GPS on T-Deck Plus

**Empirical test needed.** The GPS UART is initialized at 9600 baud on pins 43/44. TinyGPSPlus is polling. Whether the GPS module actually produces NMEA data depends on the specific T-Deck Plus hardware variant.

**Recommendation**: Add a GPS data test early in 4c. If GPS is non-functional, fall back to manual coordinate entry or received-only mode.

---

## 6. Risks and Gotchas

### RISK 1: msgpack float64 endianness (HIGH)

msgpack stores float64 in **big-endian** (network byte order). ESP32 is **little-endian**. When encoding/decoding timestamps (float64), byte swapping is mandatory.

If using mpack/CMP, this is handled automatically. If hand-rolling, you MUST byte-swap the 8-byte IEEE 754 value. Get this wrong and timestamps are garbage (and hash verification fails).

### RISK 2: msgpack field key types (MEDIUM)

LXMF fields dict uses integer keys: `{0xFB: value, 0xFC: value}`. In msgpack:
- Key 0xFB (251) encodes as `0xcc 0xfb` (uint8 format, 2 bytes)
- NOT as fixint (fixint only covers 0-127)

If our encoder uses fixint for values > 127, the encoding is wrong and Python can't parse our fields dict. The msgpack spec is clear: positive fixint is 0x00-0x7f only.

### RISK 3: Title and content are BYTES, not strings (MEDIUM)

In LXMF, title and content are stored as `bytes` objects (LXMessage.py:199, 208):
```python
def set_title_from_string(self, title_string):
    self.title = title_string.encode("utf-8")  # stored as bytes
```

In msgpack, Python `bytes` encode as **bin** format (0xc4-0xc6), not **str** format (0xa0-0xbf, 0xd9-0xdb). Our encoder must use bin format for title and content. Using str format would produce different bytes, breaking hash verification on received messages.

### RISK 4: Dictionary ordering in msgpack (LOW)

msgpack maps don't guarantee order, but Python's umsgpack preserves insertion order. When we encode the fields dict, the order of keys affects the encoded bytes, which affects the hash. For messages we CREATE, this is fine (we control the order). For messages we RECEIVE, we use the raw bytes for hashing (not re-encoding the dict).

**The re-encode hazard**: If we ever need to re-encode a received payload (e.g., for stamp stripping), dictionary key order must match the original. mpack/CMP handle this correctly if we unpack-then-repack in order.

### RISK 5: Destination hash change breaks existing peers (LOW)

Switching from `traildrop.waypoint` to `lxmf.delivery` changes all destination hashes. Existing peer table entries on both devices become stale. After firmware update, devices must re-announce to discover each other.

**Mitigation**: This is expected during development. Just re-announce after updating firmware.

### RISK 6: No real-time clock for timestamps (LOW)

LXMF timestamps are float64 Unix epoch seconds. ESP32 has no battery-backed RTC. Without GPS fix, `millis()` starts at 0 on every boot.

**Mitigation options (pick one in 4c):**
- Use GPS UTC when available (preferred)
- Use NTP via WiFi during development
- Use `millis()/1000.0` as relative time and document the limitation
- Set epoch from first received LXMF message timestamp (drift-prone but functional)

### RISK 7: Existing lxmf.h struct is wrong (LOW)

The current `lxmf.h` stubs define custom structs (`WaypointMessage`, `EmergencyMessage`) that don't reflect the actual LXMF wire format. These need to be replaced with proper LXMF message structures:
- An `LxmfMessage` struct with dest_hash, source_hash, signature, timestamp, title, content, fields
- Waypoint data goes into the fields dict, not a separate struct
- The encode/decode functions should operate on LxmfMessage, not WaypointMessage

---

## 7. Summary — What Sam Got Right and What He Missed

### Got Right
- Wire format structure (pack/unpack layout)
- Opportunistic delivery optimization (dest_hash inferred from packet)
- Hash computation (hashed_part + message_hash for signing)
- Signature scheme (Ed25519 over hashed_part + hash)
- LXMF field IDs (0xFB, 0xFC for custom type/data)
- Choice of opportunistic-only delivery (correct for our use case)
- The 295-byte max content number (matches Python constant, even though the derivation was wrong)
- Sub-phase ordering (4a→4b→4c→4d is correct)
- Waypoint field structure is reasonable

### Missed or Wrong
- **Size computation**: Used H1 header (19 bytes) not RNS MDU (464), got intermediate numbers wrong. Final 295 is correct only because he quoted the Python constant.
- **Stamp handling**: Did not mention the 5th payload element (stamp), stripping, or re-packing. Critical for interop.
- **LXMF ENCRYPTED_PACKET_MDU has a +8 bug**: The `+ TIMESTAMP_SIZE` inflates the limit. Real max content is ~287, not 295. Doesn't affect us at ~80 bytes.
- **Announce app_data detection logic**: Didn't mention the first-byte check (0x90-0x9f or 0xdc) that distinguishes old vs new format. We must ensure our app_data starts with a fixarray byte.
- **Title/content are bytes (bin), not strings (str)**: msgpack encoding difference matters for hash verification.
- **Destination change scope**: Switching to `lxmf.delivery` requires updating config.h APP_NAME, destination_derive calls, announce build/parse, and invalidating existing peer tables. Should be done in 4a, not deferred.
- **The existing lxmf.h stubs are wrong**: Custom structs don't match LXMF format.
- **RNS MDU includes IFAC overhead**: `MDU = MTU - HEADER_MAXSIZE - IFAC_MIN_SIZE = 464`, not 481.

---

## 8. Concrete Phase 4a Task List (Revised)

1. Add msgpack library (mpack recommended) to platformio.ini
2. Implement/test msgpack encode: fixarray, float64, bin8, fixmap, uint8, nil
3. Implement/test msgpack decode: ALL fixint/uint/int/float/str/bin/array/map/nil types
4. Change APP_NAME to "lxmf", APP_ASPECT to "delivery" in config.h
5. Update destination_derive() for new name
6. Update announce_build() to emit msgpack app_data `[display_name, nil]`
7. Update announce_process() to parse msgpack app_data
8. Implement LxmfMessage struct (dest_hash, source_hash, signature, timestamp, title_bytes, content_bytes, fields)
9. Implement lxmf_pack(): build payload, hash, sign, assemble packed bytes
10. Implement lxmf_unpack(): deserialize, handle stamp stripping, verify signature
11. Test: ESP32 builds LXMF message → Python unpack_from_bytes() verifies it
12. Test: Python builds LXMF message (with and without stamp) → ESP32 unpack verifies it
13. Test: ESP32 announce → Python display_name_from_app_data() reads name
14. Test: Python LXMF announce → ESP32 parses display name from msgpack app_data

---

*Reviewed by Cal (firmware reviewer agent), 2026-03-01*
