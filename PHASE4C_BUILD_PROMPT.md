# Phase 4c Build Prompt: GPS + Waypoint Payload

## Goal
Integrate GPS hardware with the LXMF messaging layer. Devices should read their GPS position, encode it as a TrailDrop waypoint in LXMF custom fields, and send/receive waypoints over LoRa. This is TrailDrop's core function: sharing backcountry waypoints.

## Background
- GPS HAL exists: `src/hal/gps.h` (frozen — use it, don't modify)
- LXMF send/receive works: `src/msg/lxmf_transport.h` (Phase 4b)
- LXMF custom fields work: `FIELD_CUSTOM_TYPE` (0xFB) + `FIELD_CUSTOM_DATA` (0xFC)
- msgpack encoder/decoder: `src/msg/msgpack.h` (frozen — use it)

## What to Build

### 1. Waypoint codec (`src/msg/waypoint.h`, `src/msg/waypoint.cpp`)

```cpp
namespace msg {

struct Waypoint {
    double lat;          // Latitude (decimal degrees)
    double lon;          // Longitude (decimal degrees)
    float ele;           // Elevation (meters)
    char name[32];       // Waypoint name (null-terminated)
    char notes[128];     // Optional notes (null-terminated)
    uint32_t timestamp;  // Unix timestamp (seconds)
    bool valid;
};

// Encode waypoint to msgpack dict
// Returns encoded length, or 0 on failure
size_t waypoint_encode(const Waypoint& wp, uint8_t* out, size_t out_cap);

// Decode msgpack dict to waypoint
// Returns true if decoded successfully
bool waypoint_decode(const uint8_t* data, size_t len, Waypoint& wp);

} // namespace msg
```

**msgpack format** (dict with string keys):
```
{
    "lat": <float64>,
    "lon": <float64>,
    "ele": <float32>,
    "name": <str>,
    "notes": <str>,       // omit if empty
    "ts": <uint32>
}
```

Use the msgpack encoder from `src/msg/msgpack.h`. The encoder supports `write_map()`, `write_str()`, `write_float()`, `write_double()`, `write_uint()`. Check what's available — if `write_double` doesn't exist, you'll need to add it to msgpack.h (this is the ONE exception to the frozen rule for src/msg/ — double precision is needed for lat/lon).

**Important:** Latitude and longitude MUST be double precision (float64). Single-precision float only has ~7 decimal digits, which gives ~1 meter accuracy. Double has ~15 digits. For backcountry navigation, use double.

### 2. Waypoint send function (`src/msg/waypoint.h`)

```cpp
// Send current GPS position as a waypoint to a peer
bool waypoint_send(
    const crypto::Identity& our_identity,
    const uint8_t our_lxmf_dest[16],
    const uint8_t peer_announce_dest[16],
    const char* name,           // waypoint name (e.g., "Camp", "Water")
    const char* notes           // optional notes (nullable)
);
```

**Flow:**
1. Read GPS position from HAL: `gps_latitude()`, `gps_longitude()`, `gps_altitude()`
2. Check `gps_has_fix()` — refuse to send without a fix
3. Build Waypoint struct with GPS data + name + notes + timestamp
4. Encode waypoint to msgpack → this becomes `FIELD_CUSTOM_DATA`
5. Call `lxmf_send()` with:
   - title: waypoint name
   - content: notes (or empty string)
   - custom_type: `"traildrop/waypoint"` (18 bytes)
   - custom_data: msgpack-encoded waypoint

### 3. Waypoint receive handling

In `main_test.cpp`, update the LXMF receive callback:
```cpp
void on_lxmf_received(const msg::LXMessage& msg, int rssi, float snr) {
    // Check if this is a waypoint
    if (msg.has_custom_fields && 
        msg.custom_type_len == 18 &&
        memcmp(msg.custom_type, "traildrop/waypoint", 18) == 0) {
        
        // Decode waypoint from custom_data
        msg::Waypoint wp;
        if (msg::waypoint_decode(msg.custom_data, msg.custom_data_len, wp)) {
            Serial.printf("[WAYPOINT] Received: %s\n", wp.name);
            Serial.printf("[WAYPOINT] Position: %.6f, %.6f, %.1fm\n", wp.lat, wp.lon, wp.ele);
            if (wp.notes[0]) Serial.printf("[WAYPOINT] Notes: %s\n", wp.notes);
            Serial.printf("[WAYPOINT] Sig: %s | RSSI=%d SNR=%.1f\n",
                          msg.signature_valid ? "VALID" : "INVALID", rssi, snr);
        }
    } else {
        // Regular LXMF message
        Serial.printf("[LXMF] Title: %.*s\n", (int)msg.title_len, msg.title);
        Serial.printf("[LXMF] Content: %.*s\n", (int)msg.content_len, msg.content);
    }
}
```

### 4. GPS status display

In `main_test.cpp` loop, add GPS polling and status:
```cpp
// Poll GPS every loop iteration
hal::gps_poll();

// Display GPS status (every 5 seconds)
if (millis() - last_gps_display > 5000) {
    if (hal::gps_has_fix()) {
        Serial.printf("[GPS] Fix: %.6f, %.6f, %.1fm | Sats=%d HDOP=%.1f\n",
                      hal::gps_latitude(), hal::gps_longitude(), hal::gps_altitude(),
                      hal::gps_satellites(), hal::gps_hdop());
    } else {
        Serial.printf("[GPS] No fix (sats=%d)\n", hal::gps_satellites());
    }
    last_gps_display = millis();
}
```

### 5. Update key handler

Change 's' key to send a waypoint (with GPS data) instead of a test LXMF message:
```cpp
case 's': {
    if (!hal::gps_has_fix()) {
        Serial.println("[TX] No GPS fix — cannot send waypoint");
        break;
    }
    const net::Peer* peer = net::peer_first();
    if (peer) {
        msg::waypoint_send(device_identity, device_lxmf_destination.hash,
                           peer->dest_hash, "Waypoint", "Shared from TrailDrop");
    }
    break;
}
```

### 6. GPS init in setup()

Add to setup(), after identity and radio init:
```cpp
hal::gps_init();
Serial.println("[BOOT] GPS initialized");
```

### 7. Tests

Add to test suite:
1. **Waypoint encode/decode roundtrip** — Encode known waypoint, decode, verify all fields match
2. **Waypoint encode Python match** — Encode a waypoint, verify output matches Python `msgpack.packb({"lat": ..., "lon": ..., ...})`
3. **Waypoint in LXMF roundtrip** — Build LXMF with waypoint custom fields, parse, extract waypoint
4. **Waypoint without GPS fix** — waypoint_send returns false when no GPS fix
5. **Waypoint with empty notes** — Notes field omitted from msgpack when empty

Generate Python test vectors:
```python
import msgpack
wp = {"lat": 38.9717, "lon": -95.2353, "ele": 267.0, "name": "Camp", "notes": "Water source", "ts": 1709312400}
packed = msgpack.packb(wp, use_bin_type=True)
print(packed.hex())
```

## Files to Create
- `src/msg/waypoint.h` — Waypoint struct + encode/decode/send declarations
- `src/msg/waypoint.cpp` — Implementation
- `tests/phase4c_test_vectors.py` — Python test vector generator

## Files to Modify
- `src/main_test.cpp` — GPS init, GPS polling, waypoint receive callback, 's' key handler, tests
- `src/msg/msgpack.h` and `src/msg/msgpack.cpp` — ONLY if `write_double` / `read_double` don't exist (needed for lat/lon precision)

## Files NOT to Modify (frozen)
- `src/crypto/*`
- `src/hal/*` (including gps.h/gps.cpp)
- `src/net/*`
- `src/msg/lxmf.*`
- `src/msg/lxmf_transport.*`

## Build & Test
- Compile: `ssh rflab-sam "cd ~/traildrop-firmware && git pull && pio run -e t-deck-plus"`
- Flash device A: `ssh rflab-sam "cd ~/traildrop-firmware && pio run -e t-deck-plus -t upload --upload-port /dev/ttyACM1"`
- Flash device B: `ssh rflab-sam "cd ~/traildrop-firmware && pio run -e t-deck-plus -t upload --upload-port /dev/ttyACM0"`
- Serial monitor A: `ssh rflab-sam "cd ~/traildrop-firmware && pio device monitor -p /dev/ttyACM1 -b 115200"`
- Serial monitor B: `ssh rflab-sam "cd ~/traildrop-firmware && pio device monitor -p /dev/ttyACM0 -b 115200"`
- Git: individual commands (`git add -A`, `git commit -m "..."`, `git push`)

## Acceptance Criteria
1. ✅ Waypoint struct encodes to msgpack dict with string keys
2. ✅ Lat/lon use double precision (float64) — NOT float32
3. ✅ Waypoint encode/decode roundtrip preserves all fields
4. ✅ Python test vectors match firmware output byte-for-byte
5. ✅ Waypoint embeds in LXMF custom_type="traildrop/waypoint" + custom_data=msgpack
6. ✅ GPS polled in loop, status logged every 5 seconds
7. ✅ 's' key sends waypoint with live GPS data (or refuses without fix)
8. ✅ Receiver extracts and displays waypoint from incoming LXMF
9. ✅ All existing tests still pass
10. ✅ Compiles on rflab, flash/RAM under 20%

## Notes
- The T-Deck Plus devices are indoors at rflab — they probably won't get a GPS fix. That's fine. The software tests verify the encode/decode pipeline. GPS fix will be tested when Dean takes them outside.
- For indoor testing, the 's' key should report "No GPS fix" and refuse to send. The test suite should have a mock/hardcoded waypoint for the encode/decode tests.
- The waypoint_send function should work even without GPS by accepting coordinates directly in a separate overload, for testing purposes.
