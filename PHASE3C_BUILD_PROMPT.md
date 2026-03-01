# Phase 3c: Announce Send/Receive + Peer Table — Build Prompt

## Context

TrailDrop firmware on LilyGO T-Deck Plus (ESP32-S3). Phases 1-3b complete and compiled clean. This sub-phase implements Reticulum announce packets — how nodes discover each other's identities over LoRa.

Work in: `/Users/systems/.openclaw/workspace/traildrop-firmware/`

**Primary source:** Cal's wire format analysis in `memory/topics/sam-infra/cal-notes.md` (search for "Announce Payload Structure"). All byte layouts and validation steps come from the Python Reticulum reference implementation.

## Announce Payload Spec (from Reticulum source)

### Announce Payload (without ratchet, context_flag=0):
```
Offset  Size   Field
0       32     x25519_public_key
32      32     ed25519_public_key
64      10     name_hash
74      10     random_hash (random nonce)
84      64     Ed25519 signature
148     N      app_data (optional, e.g. display name)
```

### Signed Data (what the Ed25519 signature covers):
```
signed_data = destination_hash(16) + public_key(64) + name_hash(10) + random_hash(10) [+ app_data(N)]
```

Note: `destination_hash` comes from the PACKET HEADER (dest_hash field), not the payload. The signed data concatenates the header's dest_hash with payload fields (excluding the signature itself).

### Announce Validation (receiving side):
1. Extract `public_key` from payload[0:64] (x25519[0:32] + ed25519[32:64])
2. Compute `identity_hash = SHA-256(public_key)[0:16]`
3. Extract `name_hash` from payload[64:74]
4. Compute `expected_dest = SHA-256(name_hash + identity_hash)[0:16]`
5. Verify `expected_dest == packet.dest_hash` (from the packet header)
6. Reconstruct `signed_data = dest_hash + public_key + name_hash + random_hash [+ app_data]`
7. Ed25519 verify(signature, signed_data, ed25519_public_key)
8. If valid: store identity in peer table

### Announce Packet Construction (sending side):
The announce is a normal Reticulum packet with:
- `packet_type = PKT_ANNOUNCE (0x01)`
- `destination_type = DEST_SINGLE (0x00)`
- `header_type = HEADER_1 (0x00)` (single-hop LoRa, no transport)
- `transport_type = TRANSPORT_BROADCAST (0x00)`
- `context_flag = 0` (no ratchet for Phase 3)
- `hops = 0`
- `dest_hash = destination.hash` (from net::Destination)
- `context = CTX_NONE (0x00)`
- `payload = announce payload built as above`

## What to Build

### 1. Peer Table (`src/net/peer.h` and `src/net/peer.cpp` — NEW files)

```cpp
#pragma once
#include <cstdint>
#include <cstddef>
#include "config.h"

namespace net {

struct Peer {
    uint8_t dest_hash[DEST_HASH_SIZE];        // Destination hash (lookup key)
    uint8_t x25519_public[32];                 // For encryption
    uint8_t ed25519_public[32];                // For signature verification
    uint8_t identity_hash[DEST_HASH_SIZE];     // SHA-256(public_keys)[0:16]
    char app_data[DISPLAY_NAME_MAX];           // Display name or other app data
    uint32_t last_announce;                     // millis() timestamp of last announce
    bool valid;                                // Slot in use
};

// Initialize peer table (clear all slots)
void peer_table_init();

// Store or update a validated peer. Returns true if stored, false if table full.
bool peer_store(const uint8_t dest_hash[DEST_HASH_SIZE],
                const uint8_t x25519_pub[32],
                const uint8_t ed25519_pub[32],
                const uint8_t identity_hash[DEST_HASH_SIZE],
                const char* app_data);

// Look up a peer by destination hash. Returns pointer or nullptr.
const Peer* peer_lookup(const uint8_t dest_hash[DEST_HASH_SIZE]);

// Get count of valid peers
int peer_count();

} // namespace net
```

Implementation notes:
- Use a fixed array of `MAX_PEERS` (50, defined in config.h) `Peer` structs
- `peer_store`: if dest_hash already exists, update it (refresh `last_announce = millis()`, update app_data). If new, find first invalid slot. Set `last_announce = millis()` on store.
- `peer_lookup`: linear scan by dest_hash (50 entries, memcmp is fine)
- `peer_table_init`: set all `valid = false`

### 2. Rebuild `src/net/announce.h`

```cpp
#pragma once
#include <cstdint>
#include <cstddef>
#include "config.h"
#include "crypto/identity.h"
#include "net/destination.h"
#include "net/packet.h"

namespace net {

// Build an announce packet for our identity and destination.
// app_data is optional (e.g., display name). Pass nullptr and 0 if none.
// Fills out_pkt with a ready-to-serialize announce packet.
// Returns true on success.
bool announce_build(const crypto::Identity& id,
                    const Destination& dest,
                    const char* app_data,
                    Packet& out_pkt);

// Validate and process a received announce packet.
// pkt = the deserialized packet (packet_type must be PKT_ANNOUNCE).
// Returns true if announce is valid and peer was stored.
bool announce_process(const Packet& pkt);

} // namespace net
```

### 3. Implement `src/net/announce.cpp`

**Important context — Destination struct** (from `src/net/destination.h`):
```cpp
struct Destination {
    uint8_t hash[DEST_HASH_SIZE];  // 16-byte destination hash
    char app_name[64];              // e.g., "traildrop"
    char aspects[64];               // e.g., "waypoint"
};
```
To get the full_name for name_hash, concatenate: `snprintf(full_name, sizeof(full_name), "%s.%s", dest.app_name, dest.aspects)`

**`announce_build`:**
1. Build the announce payload:
   - Copy x25519_public (32 bytes) + ed25519_public (32 bytes) from identity — **x25519 FIRST, ed25519 SECOND** (this is the "public_key(64)" throughout this doc, always in this order)
   - Compute name_hash: `SHA-256(full_name)[0:10]` where full_name = "app_name.aspects" from dest
   - Generate random_hash: 10 bytes from `RNG.rand()` or `os_random()` — use the Arduino `RNG` library already in the project (see main_test.cpp includes `<RNG.h>`)
   - Build signed_data into a stack buffer:
     ```cpp
     // Max signed_data size: 16 + 64 + 10 + 10 + app_data_len
     uint8_t signed_data[16 + 64 + 10 + 10 + DISPLAY_NAME_MAX]; // ~132 bytes max
     size_t signed_len = 0;
     memcpy(&signed_data[signed_len], dest.hash, 16); signed_len += 16;
     memcpy(&signed_data[signed_len], id.x25519_public, 32); signed_len += 32;
     memcpy(&signed_data[signed_len], id.ed25519_public, 32); signed_len += 32;
     memcpy(&signed_data[signed_len], name_hash, 10); signed_len += 10;
     memcpy(&signed_data[signed_len], random_hash, 10); signed_len += 10;
     if (app_data && app_data_len > 0) {
         memcpy(&signed_data[signed_len], app_data, app_data_len);
         signed_len += app_data_len;
     }
     ```
   - Sign with Ed25519: `crypto::identity_sign(id, signed_data, signed_len, signature)`
   - Assemble payload: `public_key(64) + name_hash(10) + random_hash(10) + signature(64) [+ app_data]`
2. Fill out_pkt:
   - `set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_ANNOUNCE)`
   - `hops = 0`
   - `has_transport = false`
   - Copy `dest.hash` into `dest_hash`
   - `context = CTX_NONE`
   - Copy assembled payload into `payload`, set `payload_len`
3. Return true

**`announce_process`:**
1. Check `pkt.get_packet_type() == PKT_ANNOUNCE` — return false if not
2. Check `pkt.payload_len >= 148` (minimum: 64 pubkey + 10 name + 10 random + 64 sig)
3. Extract fields from payload at correct offsets
4. Compute `identity_hash = SHA-256(public_key[0:64])[0:16]`
5. Extract `name_hash` from payload[64:74]
6. Compute `expected_dest = SHA-256(name_hash + identity_hash)[0:16]`
7. Verify `expected_dest == pkt.dest_hash` — return false if mismatch
8. Build signed_data (same buffer layout as announce_build):
   ```cpp
   uint8_t signed_data[16 + 64 + 10 + 10 + DISPLAY_NAME_MAX];
   size_t signed_len = 0;
   memcpy(&signed_data[signed_len], pkt.dest_hash, 16); signed_len += 16;      // from packet header
   memcpy(&signed_data[signed_len], &pkt.payload[0], 64); signed_len += 64;    // public_key
   memcpy(&signed_data[signed_len], &pkt.payload[64], 10); signed_len += 10;   // name_hash
   memcpy(&signed_data[signed_len], &pkt.payload[74], 10); signed_len += 10;   // random_hash
   if (app_data_len > 0) {
       memcpy(&signed_data[signed_len], &pkt.payload[148], app_data_len);
       signed_len += app_data_len;
   }
   ```
9. Ed25519 verify using the Ed25519 public key (payload bytes 32-63, NOT bytes 0-31 which are x25519):
   ```cpp
   const uint8_t* ed25519_pub = &pkt.payload[32];
   const uint8_t* signature = &pkt.payload[84];
   if (!crypto::identity_verify(ed25519_pub, signed_data, signed_len, signature)) return false;
   ```
10. Extract and truncate app_data safely:
   ```cpp
   char app_data_str[DISPLAY_NAME_MAX] = {0};
   if (app_data_len > 0) {
       size_t copy_len = app_data_len;
       if (copy_len >= DISPLAY_NAME_MAX) copy_len = DISPLAY_NAME_MAX - 1;
       memcpy(app_data_str, &pkt.payload[148], copy_len);
       app_data_str[copy_len] = '\0';
   }
   ```
11. Store peer: `peer_store(pkt.dest_hash, &pkt.payload[0], &pkt.payload[32], identity_hash, app_data_str)`
11. Return true

**For the random_hash generation**, use:
```cpp
#include <RNG.h>
// ...
uint8_t random_hash[10];
RNG.rand(random_hash, 10);
```
Note: RNG uses ESP32 hardware RNG (cryptographically secure). No explicit init needed — it auto-initializes.

**For app_data handling:**
- On build: if `app_data != nullptr`, append after signature in payload
- On process: if `payload_len > 148`, extract `app_data = payload[148..payload_len]` as a string. Copy into a local buffer, null-terminate. Pass to `peer_store`.

### 4. Add tests in `src/main_test.cpp`

Add a `run_announce_tests()` function after packet tests. Tests:

**Test 1: Announce build produces valid payload**
- Generate an identity, derive a destination
- Call `announce_build(id, dest, "TestNode", pkt)`
- Verify pkt.flags = announce flags (PKT_ANNOUNCE, DEST_SINGLE, HEADER_1)
- Verify pkt.payload_len >= 148 + strlen("TestNode")
- Verify payload[0:32] = identity's x25519_public
- Verify payload[32:64] = identity's ed25519_public

**Test 2: Announce roundtrip (build → process)**
- Generate identity, derive destination
- `announce_build(id, dest, "Alice", pkt)`
- `peer_table_init()` (clear table)
- `announce_process(pkt)` → should return true
- `peer_lookup(dest.hash)` → should return non-null
- Verify stored peer's x25519_public matches original identity
- Verify stored peer's app_data is "Alice"

**Test 3: Announce with wrong signature fails**
- Build a valid announce
- Corrupt one byte of the signature (payload[84])
- `announce_process(pkt)` → should return false

**Test 4: Announce with wrong dest_hash fails**
- Build a valid announce
- Corrupt pkt.dest_hash[0]
- `announce_process(pkt)` → should return false (dest hash verification fails)

**Test 5: Peer table stores and looks up**
- `peer_table_init()`
- Store a peer manually via `peer_store()`
- `peer_lookup()` → should find it
- `peer_count()` → should be 1
- Lookup with different hash → nullptr

**Test 6: Announce without app_data**
- Build announce with `app_data = nullptr`
- Process it → should succeed
- Stored peer's app_data should be empty string
- Verify pkt.payload_len == 148 (no app_data bytes)

**Test 7: Payload too short**
- Create a packet manually with packet_type=PKT_ANNOUNCE but payload_len=100
- `announce_process(pkt)` → should return false

**Test 8: Duplicate announce updates peer**
- Build and process announce for identity A with app_data "Alice"
- `peer_count()` == 1
- Build and process second announce for same identity with app_data "AliceV2"
- `peer_count()` still 1 (updated, not duplicated)
- `peer_lookup()` → app_data should be "AliceV2"

**Test 9: Peer table stores multiple peers**
- Generate 3 different identities, build and process announces for each
- `peer_count()` == 3
- All 3 lookups succeed with correct data

### 5. Call `peer_table_init()` in setup()

In main_test.cpp setup(), call `net::peer_table_init()` early (after includes, before identity loading). Add `#include "net/peer.h"` and `#include "net/announce.h"`.

## Constraints

- **DO NOT modify `src/crypto/`** — Phase 2 is frozen
- **DO NOT modify `src/hal/`** — HAL is frozen
- **DO NOT modify `src/net/packet.h` or `src/net/packet.cpp`** — Phase 3a is frozen (except the buffer overflow fix already applied)
- **DO NOT modify `src/net/destination.h` or `src/net/destination.cpp`** — Phase 3b is frozen
- **Keep existing tests** — all crypto, packet, and destination tests must still pass
- **Use `crypto::sha256()` from `src/crypto/hash.h`** — add `#include "crypto/hash.h"` where needed
- **Use `crypto::identity_sign()` and `crypto::identity_verify()`** from `src/crypto/identity.h`
- **Use `RNG` from `<RNG.h>`** for random_hash generation (already in project dependencies)
- Must compile clean with `pio run -e t-deck-plus`

## File Structure

```
src/net/
├── peer.h           # NEW — peer table
├── peer.cpp         # NEW — peer table implementation
├── announce.h       # REBUILD (replace existing)
├── announce.cpp     # REBUILD (replace existing)
├── packet.h         # DO NOT MODIFY
├── packet.cpp       # DO NOT MODIFY
├── destination.h    # DO NOT MODIFY
├── destination.cpp  # DO NOT MODIFY
├── transport.h      # DO NOT MODIFY (Phase 3d)
├── transport.cpp    # DO NOT MODIFY (Phase 3d)
└── lxmf.h          # DO NOT MODIFY (Phase 4)

src/main_test.cpp    # Add run_announce_tests(), peer_table_init() call
```

## Acceptance Criteria

1. ✅ `Peer` struct with all required fields (dest_hash, keys, identity_hash, app_data, timestamp, valid)
2. ✅ `peer_table_init()`, `peer_store()`, `peer_lookup()`, `peer_count()` implemented
3. ✅ `announce_build()` produces correct Reticulum announce payload with Ed25519 signature
4. ✅ `announce_process()` validates: dest_hash derivation, Ed25519 signature, stores peer
5. ✅ Signed data constructed correctly: `dest_hash + public_key + name_hash + random_hash [+ app_data]`
6. ✅ Name hash computed as `SHA-256(app_name.aspects)[0:10]`
7. ✅ Random hash generated using RNG library
8. ✅ App data handled correctly (optional, included in signature if present)
9. ✅ All 9 announce/peer tests pass
10. ✅ Existing crypto, packet, and destination tests still pass
11. ✅ `peer_table_init()` called in setup()
12. ✅ `pio run -e t-deck-plus` compiles clean
13. ✅ Committed and pushed to `deanssamclaw/traildrop-firmware`

When completely finished, run:
`openclaw system event --text "Done: Phase 3c announce send/receive + peer table" --mode now`
