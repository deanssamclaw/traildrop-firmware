# Phase 4a Build Prompt: msgpack + LXMF Message Format

## Goal
Implement minimal msgpack encoder/decoder and LXMF message build/parse on ESP32. The result must be **bit-exact** with Python LXMF — identical payloads must produce identical hashes and valid signatures.

## Background
TrailDrop firmware has a working Reticulum network layer (Phase 3). Phase 4 adds LXMF messaging. This sub-phase builds the serialization foundation.

## What to Build

### 1. msgpack encoder/decoder (`src/msg/msgpack.h`, `src/msg/msgpack.cpp`)

Implement a minimal msgpack encoder/decoder supporting ONLY these types:
- **fixarray** (0x90-0x9f) — arrays up to 15 elements
- **array16** (0xdc) — arrays up to 65535 elements (for future-proofing)
- **fixmap** (0x80-0x8f) — maps up to 15 entries
- **float64** (0xcb) — IEEE 754 double-precision, big-endian (for timestamps)
- **bin8** (0xc4) — binary data up to 255 bytes (**CRITICAL: title, content, and field values use bin, NOT str**)
- **bin16** (0xc5) — binary data up to 65535 bytes
- **fixstr** (0xa0-0xbf) — strings up to 31 bytes (for internal dict keys only)
- **str8** (0xd9) — strings up to 255 bytes
- **positive fixint** (0x00-0x7f) — integers 0-127
- **uint8** (0xcc) — unsigned integers 0-255
- **uint16** (0xcd) — unsigned integers 0-65535
- **int8** (0xd0) — signed integers -128 to 127
- **nil** (0xc0)
- **true** (0xc3) / **false** (0xc2)

**API design** — streaming encoder that writes to a buffer:
```cpp
namespace msg {

struct Encoder {
    uint8_t* buf;
    size_t cap;
    size_t pos;
    bool error;
    
    Encoder(uint8_t* buffer, size_t capacity);
    
    void write_array(uint8_t count);      // fixarray
    void write_map(uint8_t count);        // fixmap
    void write_float64(double val);       // 0xcb + 8 bytes big-endian
    void write_bin(const uint8_t* data, size_t len);  // bin8/bin16
    void write_str(const char* str, size_t len);      // fixstr/str8
    void write_uint(uint32_t val);        // fixint/uint8/uint16
    void write_int(int32_t val);          // fixint/int8
    void write_nil();                     // 0xc0
    void write_bool(bool val);            // 0xc2/0xc3
};

struct Decoder {
    const uint8_t* buf;
    size_t len;
    size_t pos;
    bool error;
    
    Decoder(const uint8_t* buffer, size_t length);
    
    uint8_t peek_type();                  // peek at next type tag without consuming
    uint8_t read_array();                 // returns element count
    uint8_t read_map();                   // returns entry count
    double read_float64();
    size_t read_bin(uint8_t* out, size_t max_len);  // returns actual length
    size_t read_str(char* out, size_t max_len);     // returns actual length
    uint32_t read_uint();
    int32_t read_int();
    void read_nil();
    bool read_bool();
    void skip();                          // skip one element (any type)
};

} // namespace msg
```

**CRITICAL ENCODING RULES:**
- Title and content MUST use `write_bin()` (bin type), NOT `write_str()` (str type)
- Field dict integer keys (like 0xFB, 0xFC) use `write_uint()` (positive fixint or uint8)
- Field dict binary values use `write_bin()`
- The timestamp is `write_float64()` — must be IEEE 754 double, big-endian
- Map entries: write key, then value, for each entry
- Float64 format: tag 0xcb + 8 bytes of IEEE 754 binary64 in big-endian byte order

### 2. LXMF message build/parse (`src/msg/lxmf.h`, `src/msg/lxmf.cpp`)

```cpp
namespace msg {

// Maximum sizes
static const size_t LXMF_MAX_CONTENT = 280;  // Conservative limit for single-packet opportunistic
static const size_t LXMF_SIGNATURE_LEN = 64;
static const size_t LXMF_HASH_LEN = 32;

struct LXMessage {
    uint8_t dest_hash[16];
    uint8_t source_hash[16];
    uint8_t signature[64];
    uint8_t message_hash[32];
    double timestamp;
    
    // Title and content as raw bytes
    uint8_t title[64];
    size_t title_len;
    uint8_t content[LXMF_MAX_CONTENT];
    size_t content_len;
    
    // Fields (simplified: we only care about CUSTOM_TYPE and CUSTOM_DATA)
    uint8_t custom_type[32];    // e.g., "traildrop/waypoint"
    size_t custom_type_len;
    uint8_t custom_data[256];   // msgpack-encoded waypoint data
    size_t custom_data_len;
    
    bool has_custom_fields;
    bool signature_valid;
};

// Build an LXMF message for opportunistic delivery
// Returns the bytes to encrypt and send (source_hash + signature + msgpack(payload))
// The dest_hash is NOT included (inferred from RNS packet destination)
bool lxmf_build(
    const crypto::Identity& source_identity,
    const uint8_t source_dest_hash[16],   // our lxmf.delivery dest hash
    const uint8_t dest_hash[16],          // recipient's lxmf.delivery dest hash
    const uint8_t* title, size_t title_len,
    const uint8_t* content, size_t content_len,
    const uint8_t* custom_type, size_t custom_type_len,  // nullable
    const uint8_t* custom_data, size_t custom_data_len,  // nullable
    uint8_t* out, size_t* out_len,        // output: plaintext LXMF bytes to encrypt
    uint8_t message_hash[32]              // output: message hash
);

// Parse a received LXMF message
// Input: full LXMF bytes (dest_hash prepended by caller after decryption)
bool lxmf_parse(
    const uint8_t* lxmf_data, size_t lxmf_len,
    LXMessage& msg
);

// Verify signature on a parsed message (requires source identity's Ed25519 public key)
bool lxmf_verify(
    const LXMessage& msg,
    const uint8_t source_ed25519_public[32]
);

} // namespace msg
```

**BUILD PROCESS (lxmf_build):**
1. Create payload array: `[timestamp, title_bytes, content_bytes, fields_dict]`
   - timestamp = current time as float64
   - title = bin-encoded UTF-8
   - content = bin-encoded UTF-8
   - fields = map with uint keys → bin values (or empty map if no custom fields)
2. Pack payload with msgpack → `packed_payload`
3. Compute hash: `hashed_part = dest_hash + source_hash + packed_payload`
4. `message_hash = sha256(hashed_part)` (full 32 bytes)
5. Compute signature: `signed_part = hashed_part + message_hash`
6. `signature = ed25519_sign(source_identity.ed25519_private, signed_part)`
7. Assemble output (for opportunistic delivery, no dest_hash):
   `source_hash(16) + signature(64) + packed_payload`

**PARSE PROCESS (lxmf_parse):**
1. Extract: `dest_hash(16) + source_hash(16) + signature(64) + packed_payload`
2. Unpack msgpack payload → array
3. **If array has 5 elements: strip element [4] (stamp), re-pack as 4-element array**
4. Extract: timestamp, title (bin), content (bin), fields (map)
5. Compute hash: `hashed_part = dest_hash + source_hash + re_packed_payload`
6. `message_hash = sha256(hashed_part)`
7. Store in LXMessage struct

**VERIFY PROCESS (lxmf_verify):**
1. Reconstruct: `signed_part = dest_hash + source_hash + packed_payload_4elem + message_hash`
2. `ed25519_verify(source_ed25519_public, signed_part, msg.signature)`

### 3. Test vectors (`tests/lxmf_test_vectors.py`)

Write a Python script that generates known-good test vectors using actual Python LXMF:

```python
import RNS
import LXMF
import RNS.vendor.umsgpack as msgpack

# Create two identities
sender = RNS.Identity()
receiver = RNS.Identity()

# Create destinations
sender_dest = RNS.Destination(sender, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
receiver_dest = RNS.Destination(receiver, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")

# Build a message
msg = LXMF.LXMessage(receiver_dest, sender_dest, content="Hello from Python!", title="Test")
msg.pack()

# Output:
# - Sender keys (x25519_priv, x25519_pub, ed25519_priv, ed25519_pub)
# - Receiver keys
# - Sender dest_hash (lxmf.delivery)
# - Receiver dest_hash (lxmf.delivery)  
# - Full packed bytes (hex)
# - Message hash (hex)
# - Just the packed_payload bytes (hex) — for msgpack verification
# - Payload as parsed: [timestamp, title, content, fields]

# Also generate a message WITH custom fields:
msg2 = LXMF.LXMessage(receiver_dest, sender_dest, 
    content="Camp waypoint", title="Waypoint",
    fields={0xFB: b"traildrop/waypoint", 0xFC: msgpack.packb({"lat": 38.9717, "lon": -95.2353})})
msg2.pack()
# Output same info
```

Run this on rflab-sam and save output as `tests/lxmf_test_vectors.json`.

### 4. Firmware tests (`src/main_test.cpp`)

Add a test suite that:
1. **msgpack roundtrip**: encode → decode → verify values match
2. **msgpack binary match**: encode known values → verify bytes match expected (from Python)
3. **LXMF build with known keys**: using test vector keys, build message → verify hash matches Python's hash
4. **LXMF parse**: parse Python's packed bytes → verify fields extracted correctly
5. **LXMF signature verify**: parse Python's message → verify signature validates
6. **LXMF with fields**: build message with CUSTOM_TYPE + CUSTOM_DATA → verify Python can parse
7. **LXMF stamp handling**: parse a stamped message (5-element payload) → verify hash still matches after stamp removal

## File Organization
```
src/msg/
├── msgpack.h       # msgpack encoder/decoder declarations
├── msgpack.cpp     # msgpack implementation
├── lxmf.h          # LXMF message declarations
└── lxmf.cpp        # LXMF message implementation
tests/
├── lxmf_test_vectors.py    # Python script to generate test vectors
└── lxmf_test_vectors.json  # Generated test vector data
```

## Frozen Layers — DO NOT MODIFY
- `src/crypto/*` — all crypto functions
- `src/hal/*` — all HAL functions
- `src/net/*` — all networking functions (packet, announce, transport, peer)

## Build & Test
- Compile: `ssh rflab-sam "cd ~/traildrop-firmware && git pull && pio run -e t-deck-plus"`
- Flash (when needed): `ssh rflab-sam "cd ~/traildrop-firmware && pio run -e t-deck-plus -t upload --upload-port /dev/ttyACM0"`
- Generate test vectors: `ssh rflab-sam "cd ~/traildrop-firmware && python3 tests/lxmf_test_vectors.py > tests/lxmf_test_vectors.json"`
- Git: individual commands only (`git add -A`, `git commit -m "..."`, `git push`)

## Acceptance Criteria
1. ✅ msgpack encoder produces correct bytes for all supported types (verified against Python msgpack)
2. ✅ msgpack decoder correctly parses all supported types
3. ✅ LXMF build produces message whose hash matches Python's hash for identical inputs
4. ✅ LXMF build produces valid signature that Python can verify
5. ✅ LXMF parse correctly extracts all fields from Python-generated messages
6. ✅ LXMF parse handles stamped messages (5-element payload) correctly
7. ✅ LXMF with custom fields (CUSTOM_TYPE + CUSTOM_DATA) round-trips between ESP32 and Python
8. ✅ All tests pass on hardware (compile + flash + serial output)
9. ✅ Flash/RAM usage stays under 20% each
10. ✅ No modifications to frozen layers

## Constants (from config.h — do NOT redefine)
- `RNS_MTU` = 500
- `DEST_HASH_SIZE` = 16
- `NAME_HASH_LENGTH` = 10
- `DERIVED_KEY_LENGTH` = 64

## New Constants Needed (add to config.h or msg/lxmf.h)
- `LXMF_OVERHEAD` = 112 (2*16 + 64 + 8 + 8)
- `LXMF_MAX_CONTENT` = 280 (conservative single-packet limit)
- `FIELD_CUSTOM_TYPE` = 0xFB
- `FIELD_CUSTOM_DATA` = 0xFC

## References
- Cal's review: `memory/topics/sam-infra/phase4-cal-review.md`
- Research: `PHASE4_RESEARCH.md`
- Python LXMF on rflab: `/usr/local/lib/python3.13/dist-packages/LXMF/LXMessage.py`
- Python msgpack on rflab: `/usr/local/lib/python3.13/dist-packages/RNS/vendor/umsgpack.py`
- msgpack spec: https://github.com/msgpack/msgpack/blob/master/spec.md
