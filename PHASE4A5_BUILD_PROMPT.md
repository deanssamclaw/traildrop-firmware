# Phase 4a.5 Build Prompt: Announce Format Migration + Dual Destinations

## Goal
Migrate announce format to LXMF 0.5.0+ and add `lxmf.delivery` destination alongside `traildrop.waypoint`. This enables interoperability with Python LXMF clients (Sideband, NomadNet).

## What to Build

### 1. Announce app_data format migration

**Current:** `announce_build()` in `src/net/announce.cpp` passes raw UTF-8 string as app_data.

**New:** app_data must be msgpack-encoded: `[display_name_bytes, null]`
- `display_name_bytes` = bin-encoded UTF-8 device name (e.g., "TrailDrop-A")
- `null` = stamp_cost (we don't use stamps)
- First byte of packed data must be 0x92 (fixarray of 2 elements)
- Use the msgpack encoder from `src/msg/msgpack.h`

**On receive:** `announce_process()` must handle both formats:
- If `app_data[0] >= 0x90 && app_data[0] <= 0x9f` → LXMF 0.5.0+ format, decode msgpack array
- Else → legacy format, treat as raw UTF-8 display name

Verified from Python LXMF source (`LXMF.py:113-135`, `LXMRouter.py:985-996`).

### 2. Dual destination support

Each device needs TWO destinations computed from the SAME identity:
- `lxmf.delivery` — for sending/receiving LXMF messages
- `traildrop.waypoint` — for discovery (existing)

Both use `destination_compute(identity_hash, app_name, aspects)`:
- `lxmf.delivery`: name_hash = sha256("lxmf.delivery")[:10], dest_hash = sha256(name_hash + identity_hash)[:16]
- `traildrop.waypoint`: existing computation

**In main_test.cpp setup():**
- Compute both destinations after identity loads
- Store both (e.g., `device_lxmf_destination` and `device_destination`)
- Use `lxmf.delivery` dest_hash for LXMF messaging (Phase 4b will wire this)
- Use `traildrop.waypoint` dest_hash for announces (existing behavior)

### 3. Peer table extension

**Current Peer struct** (in `src/net/peer.h` or similar):
- Stores one `dest_hash[16]`

**New:** Add a second hash field for the peer's `lxmf.delivery` dest_hash:
- `uint8_t dest_hash[16]` — announce destination (traildrop.waypoint)  
- `uint8_t lxmf_dest_hash[16]` — message destination (lxmf.delivery)

When processing an announce from a peer, we know their public keys and identity_hash. Compute their `lxmf.delivery` dest_hash and store it:
```cpp
// In announce_process after extracting peer identity:
uint8_t lxmf_dest[16];
crypto::destination_compute(peer_identity_hash, "lxmf", "delivery", lxmf_dest);
// Store in peer entry
```

### 4. Tests

Add to test suite:
1. **Announce app_data encoding:** Build announce with new format, verify first byte is 0x92, verify Python can decode display name
2. **Announce app_data decoding:** Parse both legacy (raw string) and 0.5.0+ (msgpack array) formats
3. **Dual destination computation:** For a known identity, compute both dest hashes, verify they're different and both correct
4. **Peer lxmf_dest_hash:** After processing an announce, verify peer has correct lxmf.delivery dest_hash stored

Generate Python test vectors:
```python
import RNS
id = RNS.Identity()
# Compute traildrop.waypoint dest
td_dest = RNS.Destination(id, RNS.Destination.IN, RNS.Destination.SINGLE, "traildrop", "waypoint")
# Compute lxmf.delivery dest  
lxmf_dest = RNS.Destination(id, RNS.Destination.IN, RNS.Destination.SINGLE, "lxmf", "delivery")
# Output both hashes + identity keys for firmware test vectors
```

## Files to Modify
- `src/net/announce.cpp` — update announce_build() and announce_process()
- `src/net/announce.h` — update function signatures if needed
- `src/net/peer.h` — add lxmf_dest_hash field to Peer struct
- `src/net/peer.cpp` — update peer storage to include lxmf_dest_hash
- `src/main_test.cpp` — add dual dest computation in setup(), add tests
- `tests/phase4a5_test_vectors.py` — Python test vector generator

## Files NOT to Modify (frozen)
- `src/crypto/*`
- `src/hal/*`
- `src/msg/*` (just built in 4a — use it, don't modify)

## Build & Test
- Compile: `ssh rflab-sam "cd ~/traildrop-firmware && git pull && pio run -e t-deck-plus"`
- Git: individual commands (`git add -A`, `git commit -m "..."`, `git push`)
- Generate test vectors: `ssh rflab-sam "cd ~/traildrop-firmware && python3 tests/phase4a5_test_vectors.py"`

## Acceptance Criteria
1. ✅ announce_build() emits msgpack [name_bytes, null] as app_data
2. ✅ announce_process() handles both legacy and 0.5.0+ app_data formats
3. ✅ Device computes both traildrop.waypoint and lxmf.delivery dest hashes on boot
4. ✅ Peer table stores lxmf_dest_hash computed from peer's announced identity
5. ✅ Test vectors from Python match firmware computation for both destinations
6. ✅ All existing tests still pass (no regressions)
7. ✅ Compiles on rflab, flash/RAM under 20%

## Constants
- LXMF app_name: `"lxmf"`, aspects: `"delivery"`
- TrailDrop app_name: `"traildrop"`, aspects: `"waypoint"`
- Display name: `"TrailDrop"` (or configurable)

## References
- Cal's Phase 4 review: `memory/topics/sam-infra/phase4-cal-review.md` (section on Design Decision 2 and 3)
- Python LXMF announce format: `LXMF.py:113-135` (display_name_from_app_data)
- Python LXMF router announce: `LXMRouter.py:985-996` (get_announce_app_data)
- Existing announce code: `src/net/announce.cpp`, `src/net/announce.h`
- Existing peer code: `src/net/peer.h`, `src/net/peer.cpp`
- msgpack encoder: `src/msg/msgpack.h` (use this for encoding app_data)
