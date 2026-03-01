# Phase 3a: Wire Format + Packet Serialize/Deserialize — Build Prompt

## Context

TrailDrop firmware on LilyGO T-Deck Plus (ESP32-S3). Phase 1 (HAL) and Phase 2 (crypto) are hardware-verified. Phase 2.5 (SPI cleanup + boot health) just shipped. This is the first sub-phase of networking.

**Primary source:** The Reticulum Python reference implementation. Cal (our firmware reviewer) read every relevant source file and documented the exact wire format. His analysis is the spec for this build. Read it carefully — every byte offset matters.

**Your job:** Rebuild the `Packet` struct, implement serialize/deserialize for both header types, and implement the packet hash algorithm. Include tests with hardcoded test vectors.

Work in: `/Users/systems/.openclaw/workspace/traildrop-firmware/`

## Wire Format Spec (from Cal's Reticulum source analysis)

### Packet Flags Byte (byte 0)

The flags byte packs 5 fields:

```
Bit 7:   unused (always 0)
Bit 6:   header_type      0=HEADER_1 (no transport), 1=HEADER_2 (with transport_id)
Bit 5:   context_flag     used in announces (ratchet presence)
Bit 4:   transport_type   0=BROADCAST, 1=TRANSPORT
Bit 3-2: destination_type 00=SINGLE, 01=GROUP, 10=PLAIN, 11=LINK
Bit 1-0: packet_type      00=DATA, 01=ANNOUNCE, 02=LINKREQUEST, 03=PROOF

Construction:
  flags = (header_type << 6) | (context_flag << 5) | (transport_type << 4)
        | (destination_type << 2) | packet_type

Unpacking:
  header_type      = (flags >> 6) & 0x01
  context_flag     = (flags >> 5) & 0x01
  transport_type   = (flags >> 4) & 0x01
  destination_type = (flags >> 2) & 0x03
  packet_type      = flags & 0x03
```

### Two Header Formats

**HEADER_1** (normal, no transport) — 19 bytes header:
```
Offset  Size   Field
0       1      flags
1       1      hops
2       16     destination_hash
18      1      context
19+     N      payload (max MTU-19 = 481 bytes)
```

**HEADER_2** (with transport_id) — 35 bytes header:
```
Offset  Size   Field
0       1      flags
1       1      hops
2       16     transport_id
18      16     destination_hash
34      1      context
35+     N      payload (max MTU-35 = 465 bytes)
```

### Constants

**Important:** `include/config.h` already defines `RNS_MTU (500)`, `DEST_HASH_SIZE (16)`, `NAME_HASH_LENGTH (10)`, `TOKEN_OVERHEAD (48)`, `DERIVED_KEY_LENGTH (64)`, and `ANNOUNCE_INTERVAL (300)`. Do NOT redefine these. Add only the NEW constants that don't exist yet. Put new protocol constants in config.h alongside the existing "Reticulum Protocol" section:

```cpp
// Add to config.h (these are NEW — do not duplicate existing defines):
#define RNS_HEADER1_SIZE      19   // HEADER_1 overhead
#define RNS_HEADER2_SIZE      35   // HEADER_2 overhead
#define RNS_MAX_PAYLOAD_H1   481   // MTU - HEADER_1
#define RNS_MAX_PAYLOAD_H2   465   // MTU - HEADER_2
#define RNS_HASH_LENGTH       32   // Full SHA-256
#define RNS_TRUNCATED_HASH    16   // Truncated hash (128 bits) — same value as DEST_HASH_SIZE

// Already in config.h (DO NOT redefine):
// RNS_MTU (500), DEST_HASH_SIZE (16), NAME_HASH_LENGTH (10)
```

In packet.h, `#include "config.h"` to get all constants. Use `DEST_HASH_SIZE` for hash buffer sizes (it equals `RNS_TRUNCATED_HASH`). Do not create duplicate defines.

### Packet Hash Algorithm

**Critical:** The packet hash is NOT SHA-256 of the raw bytes. It's computed over a "hashable part" that strips transport metadata:

```
For HEADER_1:
  hashable_part = (flags & 0x0F) || raw_bytes[2:]
  // byte 0: only keep dest_type + pkt_type (strip header_type, context_flag, transport_type)
  // skip byte 1 (hops)
  // include: destination_hash + context + payload

For HEADER_2:
  hashable_part = (flags & 0x0F) || raw_bytes[18:]
  // byte 0: only keep dest_type + pkt_type
  // skip: hops(1) + transport_id(16) = 17 bytes
  // include: destination_hash + context + payload

packet_hash = SHA-256(hashable_part)       // full 32 bytes
truncated_hash = packet_hash[0:16]         // first 16 bytes for addressing
```

This ensures the same logical packet hashes identically regardless of transport path or hop count. If you hash raw bytes, you'll never match packet hashes with Python Reticulum nodes.

### Context Byte Constants

```cpp
enum PacketContext : uint8_t {
    CTX_NONE           = 0x00,
    CTX_RESOURCE        = 0x01,
    CTX_RESOURCE_ADV    = 0x02,
    CTX_RESOURCE_REQ    = 0x03,
    CTX_RESOURCE_HMU    = 0x04,
    CTX_RESOURCE_PRF    = 0x05,
    CTX_RESOURCE_ICL    = 0x06,
    CTX_RESOURCE_RCL    = 0x07,
    CTX_CACHE_REQUEST   = 0x08,
    CTX_REQUEST         = 0x09,
    CTX_RESPONSE        = 0x0A,
    CTX_PATH_RESPONSE   = 0x0B,
    CTX_COMMAND         = 0x0C,
    CTX_COMMAND_STATUS  = 0x0D,
    CTX_KEEPALIVE       = 0xFA,
    CTX_LINK_IDENTIFY   = 0xFB,
    CTX_LINK_CLOSE      = 0xFC,
    CTX_LINK_PROOF      = 0xFD,
    CTX_LRRTT           = 0xFE,
    CTX_LRPROOF         = 0xFF,
};
```

Phase 3 only needs CTX_NONE. Include the full enum for forward compatibility.

### Packet Type and Destination Type Enums

```cpp
enum PacketType : uint8_t {
    PKT_DATA         = 0x00,
    PKT_ANNOUNCE     = 0x01,
    PKT_LINKREQUEST  = 0x02,
    PKT_PROOF        = 0x03,
};

enum DestinationType : uint8_t {
    DEST_SINGLE = 0x00,
    DEST_GROUP  = 0x01,
    DEST_PLAIN  = 0x02,
    DEST_LINK   = 0x03,
};

enum HeaderType : uint8_t {
    HEADER_1 = 0x00,  // No transport
    HEADER_2 = 0x01,  // With transport_id
};

enum TransportType : uint8_t {
    TRANSPORT_BROADCAST = 0x00,
    TRANSPORT_TRANSPORT = 0x01,
};
```

## What to Build

### 1. Rebuild `src/net/packet.h`

Replace the existing packet.h with a proper implementation:

```cpp
#pragma once
#include <cstdint>
#include <cstddef>
#include "config.h"  // Gets RNS_MTU, DEST_HASH_SIZE, etc.

// [Include all enums from above]
// [Include NEW constants: RNS_HEADER1_SIZE, RNS_HEADER2_SIZE, etc.]

struct Packet {
    uint8_t flags;
    uint8_t hops;
    uint8_t transport_id[DEST_HASH_SIZE];  // Only valid when has_transport==true
    uint8_t dest_hash[DEST_HASH_SIZE];
    uint8_t context;
    uint8_t payload[RNS_MTU];              // Buffer; actual data size = payload_len
    size_t payload_len;                     // Number of valid bytes in payload[]
    bool has_transport;                     // True if HEADER_2

    // Flag accessors — return enum types for type safety
    HeaderType      get_header_type()      const { return (HeaderType)((flags >> 6) & 0x01); }
    bool            get_context_flag()     const { return (flags >> 5) & 0x01; }
    TransportType   get_transport_type()   const { return (TransportType)((flags >> 4) & 0x01); }
    DestinationType get_destination_type() const { return (DestinationType)((flags >> 2) & 0x03); }
    PacketType      get_packet_type()      const { return (PacketType)(flags & 0x03); }

    // Flag setter — constructs the full flags byte from components
    void set_flags(HeaderType ht, bool ctx_flag, TransportType tt,
                   DestinationType dt, PacketType pt) {
        flags = ((uint8_t)ht << 6) | ((uint8_t)ctx_flag << 5) |
                ((uint8_t)tt << 4) | ((uint8_t)dt << 2) | (uint8_t)pt;
    }
};

namespace net {

// Serialize a Packet struct into raw bytes for radio transmission.
// out_buf must be at least RNS_MTU (500) bytes.
// Returns bytes written (19-500 for H1, 35-500 for H2), or -1 on error
// (e.g., payload too large for header type).
int packet_serialize(const Packet& pkt, uint8_t* out_buf, size_t out_max);

// Deserialize raw bytes (received from radio) into a Packet struct.
// raw_len = total number of received bytes.
// Returns true on success. Returns false if raw_len < minimum header size
// (19 for HEADER_1, 35 for HEADER_2). Zero-length payload is valid.
bool packet_deserialize(const uint8_t* raw, size_t raw_len, Packet& pkt);

// Compute packet hash over the hashable part (strips transport metadata).
// raw/raw_len = the full serialized packet bytes from packet_serialize.
// is_header2 = whether the packet uses HEADER_2 format.
// out_hash = full 32-byte SHA-256, out_truncated = first 16 bytes.
void packet_hash(const uint8_t* raw, size_t raw_len, bool is_header2,
                 uint8_t out_hash[32], uint8_t out_truncated[16]);

} // namespace net
```

### 2. Implement `src/net/packet.cpp`

**packet_serialize:**
- If `pkt.has_transport` (HEADER_2): write flags, hops, transport_id(16), dest_hash(16), context, payload
- Else (HEADER_1): write flags, hops, dest_hash(16), context, payload
- Enforce max payload size based on header type
- Return total bytes written

**packet_deserialize:**
- Check minimum size (at least 3 bytes for flags+hops+context with empty payload... actually minimum is 19 for HEADER_1 or 35 for HEADER_2)
- Read flags byte, determine header_type
- Parse fields based on header type
- Extract payload (remaining bytes after header)
- Return false if raw_len < minimum header size for the detected type

**packet_hash:**
- Build hashable_part per the algorithm above
- Use `crypto::sha256()` (already available from Phase 2)
- Write full hash and truncated hash

### 3. Add tests in `src/main_test.cpp`

Add a `run_packet_tests()` function called from setup() after crypto tests. Include these tests:

**Test 1: Flags construction and unpacking**
- Construct flags for HEADER_1, BROADCAST, SINGLE, DATA → should be 0x00
- Construct flags for HEADER_1, BROADCAST, SINGLE, ANNOUNCE → should be 0x01
- Construct flags for HEADER_2, TRANSPORT, SINGLE, DATA → should be 0x50
- Construct flags for HEADER_1, BROADCAST, LINK, PROOF → should be 0x0F
- Unpack each and verify all 5 fields round-trip correctly

**Test 2: HEADER_1 serialize/deserialize roundtrip**
- Create a Packet with known fields (has_transport=false, dest_hash=0x00..0x0F, context=0x00, payload="Hello TrailDrop")
- Serialize → deserialize → compare all fields match original

**Test 3: HEADER_2 serialize/deserialize roundtrip**
- Create a Packet with has_transport=true, transport_id and dest_hash set to known values
- Serialize → deserialize → compare all fields

**Test 4: HEADER_1 packet hash with known test vector**
- Create a packet: flags=0x01, hops=0x03, dest_hash=bytes 0x00-0x0F, context=0x00, payload="test_payload_data"
- Serialize it, then compute packet_hash
- The hashable_part is: `01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 00` + "test_payload_data"
  (flags & 0x0F = 0x01, then dest_hash(16) + context(1) + payload — hops stripped)
- Expected full hash (SHA-256 of hashable_part):
  ```cpp
  const uint8_t expected_full[32] = {
      0x84, 0xdb, 0xe6, 0xcd, 0x02, 0x86, 0x40, 0x2b,
      0x42, 0x1e, 0x6c, 0x72, 0xe1, 0xdb, 0xa3, 0xb6,
      0x0a, 0x57, 0x0f, 0xad, 0x27, 0x66, 0x08, 0x62,
      0x93, 0xd4, 0xa2, 0xaf, 0x5c, 0x7b, 0x43, 0x58,
  };
  ```
- Expected truncated hash (first 16 bytes): `84 db e6 cd 02 86 40 2b 42 1e 6c 72 e1 db a3 b6`

**Test 5: HEADER_2 packet hash strips transport metadata**
- Create a HEADER_2 packet (with transport_id) and a HEADER_1 packet (without transport_id), both with identical dest_hash, context, and payload. Use different hops values.
- Verify they produce the SAME truncated packet hash (this is the key property — transport metadata is stripped from the hashable part)

**Test 6: Max payload enforcement**
- Try to serialize a HEADER_1 packet with payload_len > 481 → should return -1
- Try to serialize a HEADER_2 packet with payload_len > 465 → should return -1

**Test 7: Deserialize rejects undersized packets**
- Pass 10 bytes to packet_deserialize → should return false
- Minimum valid size: 19 bytes for HEADER_1 (zero-length payload is valid), 35 bytes for HEADER_2

**Test 8: Empty payload**
- HEADER_1 packet with payload_len=0 serializes to exactly 19 bytes
- Deserialize those 19 bytes → payload_len should be 0

**Test 9: Exact max payload boundary**
- HEADER_1 with payload_len=481 → should succeed (serialize returns 500)
- HEADER_1 with payload_len=482 → should fail (returns -1)
- HEADER_2 with payload_len=465 → should succeed (serialize returns 500)
- HEADER_2 with payload_len=466 → should fail (returns -1)

### 4. Update `docs/wire_format.md`

Create or overwrite this file with the complete wire format documentation from above. This becomes the reference for all future Phase 3 work. Include:
- Flags byte layout with bit diagram
- Both header formats with offset tables
- Packet hash algorithm with step-by-step
- Constants table
- All enums

## Constraints

- **DO NOT modify any file in `src/hal/`** — HAL is frozen
- **DO NOT modify any crypto code in `src/crypto/`** — Phase 2 is frozen
- **DO NOT modify the BootHealth struct or boot sequence** — Phase 2.5 is frozen
- **USE `crypto::sha256()` from `src/crypto/hash.h`** for packet hash computation — add `#include "crypto/hash.h"` in packet.cpp. Do not add a new SHA implementation
- **Keep existing tests** — crypto tests and boot sequence must still work
- **Keep `framework = arduino`**
- Must compile clean with `pio run -e t-deck-plus`

## File Structure

```
src/net/
├── packet.h          # Rebuild (replace existing)
├── packet.cpp        # Implement (new or replace existing)
├── destination.h     # DO NOT MODIFY in this phase
├── destination.cpp   # DO NOT MODIFY in this phase
├── announce.h        # DO NOT MODIFY in this phase
├── announce.cpp      # DO NOT MODIFY in this phase
├── transport.h       # DO NOT MODIFY in this phase
├── transport.cpp     # DO NOT MODIFY in this phase
└── lxmf.h           # DO NOT MODIFY in this phase

docs/
└── wire_format.md    # Create/overwrite

src/main_test.cpp     # Add run_packet_tests() after crypto tests
```

## Acceptance Criteria

1. ✅ `Packet` struct has full flags byte with 5-field accessors and setters
2. ✅ All enums defined: PacketType, DestinationType, HeaderType, TransportType, PacketContext
3. ✅ `packet_serialize()` handles both HEADER_1 and HEADER_2 formats correctly
4. ✅ `packet_deserialize()` handles both header formats, rejects malformed data
5. ✅ `packet_hash()` computes hashable_part correctly for both header types (strips transport metadata)
6. ✅ HEADER_2 and HEADER_1 packets with same logical content produce same packet hash
7. ✅ Max payload enforcement (481 for H1, 465 for H2)
8. ✅ All 9 tests pass
9. ✅ `docs/wire_format.md` created (overwrite completely if it exists) with complete spec
10. ✅ Existing crypto tests and boot sequence unmodified and still work
11. ✅ `pio run -e t-deck-plus` compiles clean
12. ✅ Committed and pushed to `deanssamclaw/traildrop-firmware`

If any criterion is not met, the work is incomplete. Do not declare done.

When completely finished, run:
`openclaw system event --text "Done: Phase 3a wire format + packet serialize/deserialize" --mode now`
