# Phase 3b: Identity Persistence + Destination Fix — Build Prompt

## Context

TrailDrop firmware on LilyGO T-Deck Plus (ESP32-S3). Phases 1-2.5 hardware-verified. Phase 3a (wire format) just shipped. This sub-phase fixes the destination derivation to use the existing crypto layer and adds identity load-or-generate on boot.

Work in: `/Users/systems/.openclaw/workspace/traildrop-firmware/`

## What to Build

### 1. Fix `src/net/destination.cpp` — delegate to crypto layer

The current `destination_derive()` returns false (stub). The correct algorithm is ALREADY implemented in `crypto::identity_destination_hash()` in `src/crypto/identity.h`. Do NOT reimplement it. Delegate:

```cpp
#include "destination.h"
#include "crypto/identity.h"
#include <cstdio>
#include <cstring>

namespace net {

bool destination_derive(const crypto::Identity& id,
                        const char* app_name,
                        const char* aspects,
                        Destination& dest) {
    // Build full_name = "app_name.aspects"
    char full_name[128];
    snprintf(full_name, sizeof(full_name), "%s.%s", app_name, aspects);
    
    // Delegate to crypto layer (correct two-step hash process)
    crypto::identity_destination_hash(full_name, id, dest.hash);
    
    // Store names for later use (announces, etc.)
    strncpy(dest.app_name, app_name, sizeof(dest.app_name) - 1);
    dest.app_name[sizeof(dest.app_name) - 1] = '\0';
    strncpy(dest.aspects, aspects, sizeof(dest.aspects) - 1);
    dest.aspects[sizeof(dest.aspects) - 1] = '\0';
    
    return true;
}

} // namespace net
```

This is nearly exact — implement it as shown. The key point: `crypto::identity_destination_hash()` already does the correct two-step process (name_hash → concat with identity_hash → sha256 → truncate). Do not duplicate that logic.

### 2. Add identity load-or-generate to boot sequence

In `src/main_test.cpp`, add identity management after the boot health checks and before crypto tests. The device should:

1. Check if identity file exists on SD card at `/traildrop/identity.dat`
2. If yes: load it with `crypto::identity_load()`
3. If no: generate new identity with `crypto::identity_generate()`, save with `crypto::identity_save()`
4. Derive the TrailDrop destination using `net::destination_derive()`
5. Print identity hash and destination hash to Serial

Add the identity path constant to `include/config.h`:
```cpp
#define IDENTITY_PATH       "/traildrop/identity.dat"
```

**Implementation in setup():** Add after boot health summary, before crypto tests. Gate on `boot.storage` (need SD card for identity persistence):

```cpp
#include "net/destination.h"

// Device identity (global, used by networking later)
static crypto::Identity device_identity;
static net::Destination device_destination;
static bool identity_ready = false;

// In setup(), after boot health summary and before crypto tests:
if (boot.storage) {
    // Ensure /traildrop directory exists
    // (hal::storage_* doesn't have mkdir, use SD.mkdir directly)
    SD.mkdir("/traildrop");
    
    if (hal::storage_exists(IDENTITY_PATH)) {
        if (crypto::identity_load(device_identity, IDENTITY_PATH)) {
            Serial.println("[ID] Identity loaded from SD");
        } else {
            Serial.println("[ID] Failed to load identity, generating new");
            if (crypto::identity_generate(device_identity)) {
                crypto::identity_save(device_identity, IDENTITY_PATH);
                Serial.println("[ID] New identity generated and saved");
            }
        }
    } else {
        if (crypto::identity_generate(device_identity)) {
            crypto::identity_save(device_identity, IDENTITY_PATH);
            Serial.println("[ID] New identity generated and saved");
        } else {
            Serial.println("[ID] CRITICAL: Failed to generate identity");
        }
    }
    
    // Derive destination
    if (net::destination_derive(device_identity, APP_NAME, "waypoint", device_destination)) {
        identity_ready = true;
        
        // Print identity info
        Serial.printf("[ID] Identity hash: ");
        for (int i = 0; i < 16; i++) Serial.printf("%02x", device_identity.hash[i]);
        Serial.println();
        Serial.printf("[ID] Destination:   ");
        for (int i = 0; i < 16; i++) Serial.printf("%02x", device_destination.hash[i]);
        Serial.println();
        
        // Show on display
        // (Don't increment line counter excessively — use one line)
        hal::display_printf(0, line * 18, 0x07FF, 1, "ID: %02x%02x%02x%02x...",
            device_identity.hash[0], device_identity.hash[1],
            device_identity.hash[2], device_identity.hash[3]);
        line++;
    }
} else {
    Serial.println("[ID] Skipping identity — no SD card");
}
```

**Important notes:**
- You'll need `#include <SD.h>` for `SD.mkdir()` — it's already included indirectly through hal/storage.h, but add it explicitly if needed
- `APP_NAME` is already defined in config.h as "traildrop"
- The identity should persist across reboots — same identity file, same hashes
- `device_identity` and `device_destination` are global statics for Phase 3c/3d to use

### 3. Add identity persistence test

Add to `run_packet_tests()` (or create a new `run_identity_tests()` section — your call, but keep it after packet tests):

**Test: Identity persistence roundtrip**
- Generate a fresh identity
- Derive destination with `net::destination_derive(id, "traildrop", "waypoint", dest)`
- Verify `dest.hash` matches `crypto::identity_destination_hash("traildrop.waypoint", id, ...)`
- Verify destination app_name and aspects are stored correctly

**Test: Destination derive consistency**
- Same identity + same app_name + same aspects → same dest_hash every time
- Different aspects → different dest_hash

Note: Don't test identity_save/identity_load here — that's already covered by the Phase 2 crypto test `test_identity_save_load()`.

### 4. Update boot health to include identity status

After the boot health summary line, add identity_ready to the can_network check:

Update the `BootHealth` struct — but wait, identity_ready is separate from boot health (it depends on storage + crypto working). Instead, just add a serial log line:

```cpp
if (boot.can_network() && identity_ready) {
    Serial.println("[BOOT] Full network-ready: radio + storage + identity");
} else if (boot.can_network()) {
    Serial.println("[BOOT] Network-partial: radio + storage OK, identity missing");
}
```

This replaces/augments the existing can_network() message.

## Constraints

- **DO NOT modify `src/crypto/`** — Phase 2 is frozen
- **DO NOT modify `src/hal/`** — HAL is frozen
- **DO NOT modify `src/net/packet.h` or `src/net/packet.cpp`** — Phase 3a is frozen
- **DO NOT duplicate crypto::identity_destination_hash logic** — delegate to it
- **Keep existing tests** — all crypto and packet tests must still pass
- Must compile clean with `pio run -e t-deck-plus`

## Acceptance Criteria

1. ✅ `destination_derive()` delegates to `crypto::identity_destination_hash()` — no duplicate logic
2. ✅ `destination_derive()` stores app_name and aspects in the Destination struct (null-terminated)
3. ✅ Identity loaded from SD on boot if `/traildrop/identity.dat` exists
4. ✅ Identity generated and saved if no identity file exists
5. ✅ `/traildrop/` directory created if missing
6. ✅ Destination derived using `APP_NAME` ("traildrop") and "waypoint"
7. ✅ Identity hash and destination hash printed to Serial
8. ✅ Identity and destination available as globals for Phase 3c/3d
9. ✅ Destination derive tests pass (consistency + correctness)
10. ✅ Existing crypto and packet tests still pass
11. ✅ `pio run -e t-deck-plus` compiles clean
12. ✅ Committed and pushed to `deanssamclaw/traildrop-firmware`

When completely finished, run:
`openclaw system event --text "Done: Phase 3b identity persistence + destination fix" --mode now`
