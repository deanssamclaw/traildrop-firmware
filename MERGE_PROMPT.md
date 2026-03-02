# Merge Prompt: Cal's Phase 5 LVGL UI + Our Phase 4 LXMF Stack

## Goal
Merge Cal's Phase 5 LVGL touch UI with our Phase 4a-4d LXMF messaging stack into a unified codebase. The result should compile clean on rflab and have Cal's touch UI wired to our LXMF send/receive pipeline.

## What Cal Built (Phase 5)
Cal built a full LVGL touch UI on a branch that diverged after Phase 3c. His work is in `merge-staging/`:
- `merge-staging/ui-cal/` — 7 screens: boot, main, drop, peers, detail, settings, emergency
- `merge-staging/touch.cpp`, `touch.h` — GT911 touch driver (I2C 0x5D)
- `merge-staging/lv_conf.h` — LVGL 8.3 configuration
- `merge-staging/app/` — Application layer: waypoint categories, waypoint DB stubs, peers, GPX
- `merge-staging/platformio-cal.ini` — His platformio.ini (has LVGL + ArduinoJson deps)
- `merge-staging/config-cal.h` — His config.h (has TOUCH_I2C_ADDR)
- `merge-staging/ui-cal/theme.cpp`, `theme.h` — Dark theme with consistent color palette

Cal's UI uses `app::WaypointCategory` (CAMP, WATER, FUEL, HAZARD, SCENIC, INFO, EMERGENCY) and `app::Waypoint` as its data model.

## What We Built (Phase 4a-4d)
Our codebase has:
- `src/msg/msgpack.h/.cpp` — msgpack encoder/decoder
- `src/msg/lxmf.h/.cpp` — LXMF message build/parse/verify
- `src/msg/lxmf_transport.h/.cpp` — LXMF send/receive over encrypted LoRa
- `src/msg/waypoint.h/.cpp` — Waypoint encode/decode (msgpack dict) + send
- `src/ui/display_ui.h/.cpp` — Text-based TFT UI (Phase 4d — REPLACE with Cal's LVGL UI)
- Phase 4a.5 announce migration (msgpack app_data, dual destinations)
- 58 tests across all phases

## Merge Instructions

### Step 1: Add Cal's new files
Copy from `merge-staging/` into the correct locations:
- `merge-staging/touch.cpp` → `src/hal/touch.cpp`
- `merge-staging/touch.h` → `src/hal/touch.h`
- `merge-staging/lv_conf.h` → `include/lv_conf.h`
- `merge-staging/app/` → `src/app/` (entire directory)
- `merge-staging/ui-cal/theme.cpp` → `src/ui/theme.cpp`
- `merge-staging/ui-cal/theme.h` → `src/ui/theme.h`
- `merge-staging/ui-cal/screen_boot.cpp` → `src/ui/screen_boot.cpp`
- `merge-staging/ui-cal/screen_main.cpp` → `src/ui/screen_main.cpp`
- `merge-staging/ui-cal/screen_drop.cpp` → `src/ui/screen_drop.cpp`
- `merge-staging/ui-cal/screen_peers.cpp` → `src/ui/screen_peers.cpp`
- `merge-staging/ui-cal/screen_detail.cpp` → `src/ui/screen_detail.cpp`
- `merge-staging/ui-cal/screen_settings.cpp` → `src/ui/screen_settings.cpp`
- `merge-staging/ui-cal/screen_emergency.cpp` → `src/ui/screen_emergency.cpp`
- `merge-staging/ui-cal/screen_send.cpp` → `src/ui/screen_send.cpp`
- `merge-staging/ui-cal/ui.cpp` → `src/ui/ui.cpp`
- `merge-staging/ui-cal/ui.h` → `src/ui/ui.h`

### Step 2: Remove our old text UI
Delete `src/ui/display_ui.h` and `src/ui/display_ui.cpp` (replaced by Cal's LVGL screens).

### Step 3: Merge platformio.ini
Add Cal's dependencies to our existing platformio.ini:
- Add `lvgl/lvgl@^8.3.0` to lib_deps
- Add `bblanchon/ArduinoJson@^7.0.0` to lib_deps
- Add to build_flags:
  - `-DLV_CONF_INCLUDE_SIMPLE`
  - `-I${PROJECT_DIR}/include`

### Step 4: Merge config.h
Add Cal's touch config to our existing config.h:
- Add `#define TOUCH_I2C_ADDR 0x5D` in the Touch section

Keep our LXMF config section intact.

### Step 5: Wire LXMF messaging to Cal's UI

**The critical integration: Cal's UI needs to call our msg::waypoint_send() and receive callbacks.**

In `src/main_test.cpp`, update the integration:

a) **Replace display_ui includes with Cal's ui includes:**
```cpp
// Remove: #include "ui/display_ui.h"
// Add: #include "ui/ui.h"
```

b) **Update the LXMF receive callback to feed Cal's UI:**
```cpp
void on_lxmf_received(const msg::LXMessage& msg, int rssi, float snr) {
    if (msg.has_custom_fields && msg.custom_type_len == 18 &&
        memcmp(msg.custom_type, "traildrop/waypoint", 18) == 0) {
        msg::Waypoint wp;
        if (msg::waypoint_decode(msg.custom_data, msg.custom_data_len, wp)) {
            const net::Peer* sender = net::peer_lookup_by_lxmf_dest(msg.source_hash);
            // Feed Cal's LVGL UI
            ui::ui_on_waypoint_received(
                sender ? sender->app_data : "Unknown",
                wp.name,
                wp.lat, wp.lon, wp.ele,
                app::WaypointCategory::INFO,  // Default category for now
                rssi
            );
            Serial.printf("[WAYPOINT] %s: %.6f, %.6f\n", wp.name, wp.lat, wp.lon);
        }
    }
}
```

c) **Update setup() to init Cal's UI:**
```cpp
// Replace display_ui init with:
if (!ui::ui_init()) {
    Serial.println("[BOOT] UI init failed");
}
```

d) **Update loop() to call Cal's UI:**
```cpp
// Replace display_ui update with:
ui::ui_update();

// Feed keyboard to LVGL:
char key = hal::keyboard_read();
if (key) {
    ui::ui_feed_key(key);
}
```

e) **Wire the Drop screen to waypoint_send:**
In `src/ui/screen_drop.cpp`, find where the "send" action triggers. It likely calls a placeholder. Wire it to:
```cpp
#include "msg/waypoint.h"
// When user taps send:
msg::waypoint_send(identity, lxmf_dest, peer_dest, name, notes);
```

The Drop screen needs access to the device identity and LXMF destination. The cleanest approach: add setter functions to ui.h similar to how display_ui had `ui_set_send_context()`:
```cpp
void ui_set_send_context(const crypto::Identity* id, const uint8_t* lxmf_dest);
```
Call this from main_test.cpp after identity loads.

f) **Feed peer discovery to Cal's UI:**
When an announce is processed and a new peer is found, call:
```cpp
ui::ui_on_peer_discovered(peer->app_data, rssi);
```

### Step 6: Handle `app::WaypointCategory`

Cal's UI uses `app::WaypointCategory`. Our `msg::Waypoint` doesn't have a category field. For now:
- Incoming waypoints default to `app::WaypointCategory::INFO`
- The Drop screen can let users pick a category from Cal's enum
- The category is stored in the UI data model but NOT sent over the wire yet (future: add to msgpack waypoint dict)

### Step 7: Compile and verify

1. Compile: `ssh rflab-sam "cd ~/traildrop-firmware && git pull && pio run -e t-deck-plus"`
2. Verify all existing 58 tests still pass (they run from main_test.cpp which we're modifying)
3. Verify RAM/flash are under 30% (LVGL will use more)

## Files NOT to Modify (frozen)
- `src/crypto/*`
- `src/hal/power.*`, `src/hal/display.*`, `src/hal/radio.*`, `src/hal/keyboard.*`, `src/hal/trackball.*`, `src/hal/gps.*`, `src/hal/storage.*`, `src/hal/battery.*`
- `src/net/*`
- `src/msg/*` (our Phase 4 messaging stack — use it, don't modify)

## New files OK to create/modify
- Everything in `src/ui/` (Cal's new LVGL files replace our old text UI)
- `src/hal/touch.*` (Cal's new touch driver)
- `src/app/*` (Cal's new app layer)
- `include/lv_conf.h` (LVGL config)
- `include/config.h` (add touch config)
- `platformio.ini` (add deps)
- `src/main_test.cpp` (integration wiring)

## Acceptance Criteria
1. ✅ Cal's LVGL UI compiles and initializes (boot screen shows)
2. ✅ GT911 touch driver initializes at 0x5D
3. ✅ Main screen shows GPS position, peer count, battery, waypoint list
4. ✅ Drop screen triggers `msg::waypoint_send()` when user sends
5. ✅ Received LXMF waypoints appear in Cal's UI waypoint list
6. ✅ Peer discovery feeds Cal's peer list
7. ✅ All 58 existing tests still pass
8. ✅ Old text UI files removed (display_ui.h/.cpp)
9. ✅ Compiles on rflab, RAM < 30%, Flash < 25%
10. ✅ No protocol internals visible on any screen (same design rule)

## Build & Test
- Compile: `ssh rflab-sam "cd ~/traildrop-firmware && git pull && pio run -e t-deck-plus"`
- Git: individual commands (`git add -A`, `git commit -m "..."`, `git push`)

## Important Notes
- Cal's `app/waypoint.cpp` and `app/peers.cpp` have stub implementations (Phase 6 persistent storage). That's fine — the UI data model (`UiWaypoint`, `UiPeer`) lives in `ui.cpp` as runtime state.
- The `screen_send.cpp` in Cal's code may be a stub or duplicate of `screen_drop.cpp`. Check both and keep whichever is the actual drop/share screen.
- Cal's `app/gpx.cpp` is for GPX export — ignore for now, it will compile as stubs.
- LVGL needs a tick source and display flush callback. Cal's `ui.cpp` should have this wired to our `hal::display_*` functions. If not, wire `lv_disp_flush` to the TFT_eSPI driver.
