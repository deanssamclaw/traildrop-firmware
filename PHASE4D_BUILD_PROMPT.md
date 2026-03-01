# Phase 4d Build Prompt: Display UI

## Design Philosophy

> "Users should see simplicity, very few options, something that appreciates their time and attention, then helps them get back to the trail." — Dean

The entire TrailDrop stack (crypto, Reticulum wire format, LXMF, msgpack, GPS) exists so this screen can be simple. **None of that complexity should be visible to the user.** No protocol names, no hash displays, no "announce mode," no "LXMF delivery." The T-Deck is a trail tool, not a radio terminal.

**Design principles:**
- Respect the user's time and attention
- One primary action: share your location
- Information appears when relevant, disappears when not
- The trail is the point — the device gets out of the way

## Hardware

- **Display:** 320x240 TFT (ST7789), landscape orientation
- **Input:** Physical QWERTY keyboard (directly wired, directly available via `hal::keyboard_read()` or similar)
- **Library:** Use `hal::display_*` functions from `src/hal/display.h` (frozen — use what's there)
- Check what display functions exist before designing. You have at minimum `display_init()`, `display_clear()`, `display_printf()`. Work with what's available.

## Screens

### 1. Main Screen (default — what you see 99% of the time)

```
┌──────────────────────────────┐
│  TrailDrop            ◉ 2    │  ← name + peer count
│                              │
│  38.8814°N  94.8191°W        │  ← your position (big, readable)
│  267m  ▲5 sats               │  ← elevation + satellite count
│                              │
│  ━━━━━━━━━━━━━━━━━━━━━━━━━━  │  ← divider
│                              │
│  Riley    0.3 mi  2m ago     │  ← peer waypoints (name, distance, recency)
│  Jordan   1.1 mi  8m ago     │  
│                              │
│  [S] Share spot              │  ← hint: press S to share
└──────────────────────────────┘
```

**Details:**
- **Top bar:** "TrailDrop" + connection indicator (◉ = radio active) + peer count
- **Your position:** Large text. Decimal degrees, not DMS. Show "No GPS" if no fix, with satellite count so user knows it's searching.
- **Peer list:** Show received waypoints as `name  distance  time_ago`. Sort by most recent. Max 4-5 visible (scroll if more). Distance calculated from your GPS position to theirs.
- **Bottom hint:** Single action prompt. Minimal.
- **No GPS fix state:** Show "Searching... ▲3 sats" instead of coordinates. Still show peers. User understands the device is working.

### 2. Share Screen (press 'S' from main screen)

```
┌──────────────────────────────┐
│  Share Your Spot             │
│                              │
│  Name: Camp_                 │  ← cursor, keyboard input
│                              │
│  38.8814°N  94.8191°W        │  ← confirming what you're sharing
│                              │
│                              │
│                              │
│                              │
│  [Enter] Send  [Esc] Cancel  │
└──────────────────────────────┘
```

**Details:**
- Press 'S' → opens share screen
- Keyboard input for waypoint name (short — 20 chars max on screen)
- Shows current GPS position so user confirms what they're sharing
- Enter sends, Esc cancels → back to main screen
- No notes field in v1. Keep it to one input. Notes can come later.
- If no GPS fix: show "No GPS fix — can't share yet" and return to main on any key
- After sending: brief flash "✓ Sent to 2 peers" (1 second), then back to main screen

### 3. Waypoint Detail (press Enter on a peer in the list, or auto-show on receive)

```
┌──────────────────────────────┐
│  ← Back                     │
│                              │
│  Riley's Spot                │
│  38.9012°N  94.7834°W        │
│  312m elevation              │
│  0.3 miles away              │
│                              │
│  Received 2 min ago          │
│  Signal: Strong              │
│                              │
│  [Esc] Back                  │
└──────────────────────────────┘
```

**Details:**
- Shows full detail for one waypoint
- Distance from your current position
- Signal strength in human words (Strong/Good/Weak), not dBm
- "Received X min ago" — relative time
- Esc returns to main screen

### 4. Boot Screen (shown during startup, 2-3 seconds)

```
┌──────────────────────────────┐
│                              │
│                              │
│       TrailDrop              │
│                              │
│       Starting...            │
│                              │
│                              │
│                              │
└──────────────────────────────┘
```

Then transition to main screen. No version numbers, no protocol info, no hash dumps.

## What NOT to Show

- No destination hashes
- No "LXMF" or "Reticulum" or "msgpack" — ever
- No "Announce sent" / "Announce received"
- No packet counts or byte counts
- No RSSI numbers (translate to Strong/Good/Weak)
- No encryption indicators (it's always encrypted — don't make users think about it)
- No settings menu in v1
- No debug output on screen (keep serial logging for development)

## Implementation

### Display module (`src/ui/display_ui.h`, `src/ui/display_ui.cpp`)

```cpp
namespace ui {

enum class Screen {
    BOOT,
    MAIN,
    SHARE,
    DETAIL
};

void ui_init();
void ui_update();          // Call from loop() — handles screen drawing + input
Screen ui_current_screen();

// Called by LXMF receive callback to notify UI of new waypoint
void ui_on_waypoint_received(const msg::Waypoint& wp, const char* sender_name, int rssi);

} // namespace ui
```

### Input handling

Read keyboard in `ui_update()`. Map keys:
- 'S' or 's' → open Share screen (from Main only)
- Enter → send waypoint (Share screen) or view detail (Main screen, selected peer)
- Esc or Backspace → cancel/back
- Up/Down arrows (if available) or 'J'/'K' → scroll peer list
- Regular keys → text input on Share screen

### Distance calculation

```cpp
// Haversine formula — distance between two GPS coordinates
float distance_miles(double lat1, double lon1, double lat2, double lon2);
```

Simple haversine. Output in miles. Put in `src/ui/geo.h` or inline in the UI module.

### Signal strength translation

```cpp
const char* signal_label(int rssi) {
    if (rssi > -70) return "Strong";
    if (rssi > -90) return "Good";
    if (rssi > -110) return "Weak";
    return "Faint";
}
```

### Waypoint storage for display

The UI needs to keep received waypoints for display. Simple fixed array:

```cpp
struct DisplayWaypoint {
    msg::Waypoint wp;
    char sender_name[32];
    int rssi;
    uint32_t received_at;  // millis()
    bool valid;
};

static const size_t MAX_DISPLAY_WAYPOINTS = 16;
static DisplayWaypoint display_waypoints[MAX_DISPLAY_WAYPOINTS];
```

Sort by `received_at` (most recent first) for display.

### Screen refresh rate

Don't redraw every loop iteration. Use a dirty flag or timer:
- Main screen: refresh every 1 second (GPS position + time ago updates)
- Share screen: refresh on keypress only
- Detail screen: refresh every 5 seconds (distance updates as you move)

### Integration with main_test.cpp

Replace the current serial-only receive callback with one that also notifies the UI:

```cpp
void on_lxmf_received(const msg::LXMessage& msg, int rssi, float snr) {
    if (msg.has_custom_fields && msg.custom_type_len == 18 &&
        memcmp(msg.custom_type, "traildrop/waypoint", 18) == 0) {
        msg::Waypoint wp;
        if (msg::waypoint_decode(msg.custom_data, msg.custom_data_len, wp)) {
            const net::Peer* sender = net::peer_lookup_by_lxmf_dest(msg.source_hash);
            ui::ui_on_waypoint_received(wp, sender ? sender->app_data : "Unknown", rssi);
        }
    }
    // Keep serial logging for development
}
```

Replace the 's' key handler in the main loop with `ui::ui_update()` handling all input.

### GPS display formatting

```cpp
// Format: "38.8814°N" or "38.8814°S"
void format_lat(double lat, char* buf, size_t cap);
// Format: "94.8191°W" or "94.8191°E"  
void format_lon(double lon, char* buf, size_t cap);
```

4 decimal places = ~11 meter accuracy. Enough for trail use without visual clutter.

## Files to Create
- `src/ui/display_ui.h` — UI declarations
- `src/ui/display_ui.cpp` — UI implementation (screens, input, drawing)

## Files to Modify
- `src/main_test.cpp` — integrate ui_init(), ui_update(), update receive callback, remove old key handlers

## Files NOT to Modify (frozen)
- `src/crypto/*`
- `src/hal/*` (use display functions as-is)
- `src/net/*`
- `src/msg/*`

## Build & Test
- Compile: `ssh rflab-sam "cd ~/traildrop-firmware && git pull && pio run -e t-deck-plus"`
- Flash device A: `ssh rflab-sam "cd ~/traildrop-firmware && pio run -e t-deck-plus -t upload --upload-port /dev/ttyACM1"`
- Git: individual commands (`git add -A`, `git commit -m "..."`, `git push`)

## Acceptance Criteria
1. ✅ Boot screen shows "TrailDrop" / "Starting..." for 2-3 seconds
2. ✅ Main screen shows GPS position (or "Searching..." with sat count)
3. ✅ Main screen shows peer waypoints with name, distance, time ago
4. ✅ Press 'S' opens Share screen with keyboard input for waypoint name
5. ✅ Enter on Share screen sends waypoint via `waypoint_send()`, shows confirmation, returns to main
6. ✅ Esc cancels share, returns to main
7. ✅ Received waypoints appear in peer list automatically
8. ✅ Detail view shows full waypoint info with human-readable signal strength
9. ✅ No protocol internals visible on any screen (no hashes, no "LXMF", no RSSI numbers)
10. ✅ All existing tests still pass
11. ✅ Compiles on rflab, flash/RAM under 25% (UI will use more RAM for display buffers)

## Important Notes
- The display HAL is frozen. Work with whatever `display_printf`, `display_clear`, `display_fill_rect` etc. are available. If the HAL only supports text rendering, use text-based UI. Don't try to draw complex graphics.
- Read `src/hal/display.h` and `src/hal/display.cpp` FIRST to understand what drawing primitives you have.
- Read `src/hal/keyboard.h` (if it exists) to understand input. If no keyboard HAL exists, check how main_test.cpp currently reads Serial input and adapt.
- The T-Deck Plus keyboard sends ASCII characters over a specific I2C or GPIO interface. Check the existing code.
- Keep serial debug logging — it's essential for development. Just don't put debug info on the TFT screen.
