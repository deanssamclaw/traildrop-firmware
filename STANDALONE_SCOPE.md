# TrailDrop Standalone: T-Deck Plus Native App

## Vision
A fully standalone waypoint sharing device. No phone, no laptop, no internet.
Pick it up, turn it on, drop and share waypoints over LoRa radio.

## Hardware: LilyGO T-Deck Plus
- **MCU:** ESP32-S3 (dual-core, 16MB flash, 8MB PSRAM)
- **Radio:** SX1262 LoRa (915 MHz for US)
- **Screen:** 2.8" ST7789 IPS LCD, 320×240
- **Input:** Physical keyboard + trackball
- **GPS:** Built-in module (UART on pins 43/44)
- **Audio:** Speaker + microphone (ES7210)
- **Power:** 2000mAh battery
- **Storage:** SD card slot
- **Dev platform:** Arduino / PlatformIO (C/C++)

Pin mappings are documented: [utilities.h](https://github.com/Xinyuan-LilyGO/T-Deck/blob/master/examples/UnitTest/utilities.h)

---

## Architecture Decision: Reticulum-Compatible vs Reticulum Port

### Option A: Minimal Reticulum-Compatible Protocol (Recommended)
Implement just enough of the Reticulum wire protocol to be interoperable with
full Reticulum nodes. TrailDrop devices talk to each other AND to laptops/phones
running the Python version.

**What to implement:**
- Reticulum packet framing (HDLC-like, 500 byte MTU)
- Identity (X25519 keypair + Ed25519 signing)
- Destination addressing (truncated SHA-256 → 16 byte hash)
- Announce packets (so other nodes discover you)
- Single packet encryption (per-packet X25519 ECDH + AES-256-CBC)
- LXMF message format (subset: waypoint and emergency message types)

**What to skip (initially):**
- Links (persistent encrypted channels) — single packets suffice for waypoints
- Multi-hop transport routing — start with single-hop direct LoRa
- Propagation nodes / store-and-forward
- Forward secrecy / key ratcheting

### Option B: Full Reticulum Port to C
Port the entire Python RNS library to C. Massive effort, probably months.
Not recommended as a starting point.

**Recommendation: Option A.** Get interoperable single-hop working first.
Add features incrementally.

---

## Development Phases

### Phase 1: Hardware Bringup (1-2 days)
Get all peripherals working individually in Arduino/PlatformIO.

- [ ] Screen: ST7789 via TFT_eSPI library — display text, basic graphics
- [ ] Keyboard: I2C read from ESP32-C3 keyboard controller
- [ ] Trackball: Navigation input
- [ ] GPS: UART serial read, parse NMEA sentences (TinyGPS++ library)
- [ ] LoRa: SX1262 init + raw packet send/receive (RadioLib library)
- [ ] SD card: Read/write files for waypoint storage
- [ ] Battery: ADC read for battery level display
- [ ] Power management: Deep sleep, wake on keypress

**Libraries:**
- `TFT_eSPI` — display driver
- `RadioLib` — SX1262 LoRa driver (used by RNode firmware, well-tested)
- `TinyGPS++` — NMEA GPS parsing
- `LVGL` — UI framework (LilyGO already has examples for T-Deck)
- `ArduinoJson` — message serialization

**Risk:** Low. All peripherals have working example code from LilyGO.

### Phase 2: Crypto Foundation (2-3 days)
Implement the cryptographic primitives Reticulum requires.

- [ ] X25519 key generation and ECDH key exchange
- [ ] Ed25519 signing and verification
- [ ] AES-256-CBC encryption/decryption with PKCS7 padding
- [ ] SHA-256 hashing (for destination addressing)
- [ ] HMAC-SHA256 (for packet authentication)
- [ ] Secure random number generation (ESP32 hardware RNG)

**Libraries:**
- `libsodium` (via `esp-idf` component) — has X25519, Ed25519, AES, SHA-256, HMAC, all hardware-accelerated on ESP32-S3
- Alternative: `Mbed TLS` (included in ESP-IDF) — also has everything needed

**Risk:** Low. ESP32-S3 has hardware crypto acceleration. libsodium is well-ported to ESP-IDF.

### Phase 3: Reticulum Wire Protocol (3-5 days)
Implement the packet format to be interoperable with Python Reticulum nodes.

- [ ] Packet structure: header flags, destination hash, context, payload
- [ ] HDLC-like framing for LoRa transport
- [ ] Identity: generate and persist X25519+Ed25519 keypair to flash/SD
- [ ] Destination: derive 16-byte hash from identity + app name + aspects
- [ ] Announce: broadcast identity + destination to network
- [ ] Path request / response: find routes to destinations
- [ ] Single packet encryption: ephemeral ECDH per-packet
- [ ] Packet authentication: HMAC verification

**Key constraint:** Reticulum MTU = 500 bytes. Waypoint messages are small
(~100 bytes JSON), so single packets work fine.

**Reference:** The Python source (`RNS/Packet.py`, `RNS/Identity.py`,
`RNS/Destination.py`) is the authoritative spec. No separate protocol doc exists.

**Risk:** Medium. The wire format isn't formally documented — must reverse-engineer
from Python source. But it's clean code and others have done partial ports.

### Phase 4: LXMF Message Layer (2-3 days)
Implement the LXMF message format for waypoint exchange.

- [ ] LXMF message structure (source, destination, content, title, timestamp)
- [ ] Waypoint message type: `{"type":"waypoint","waypoint":{lat,lon,category,desc,timestamp}}`
- [ ] Emergency beacon type: `{"type":"emergency","beacon":{lat,lon,status,timestamp}}`
- [ ] Message serialization/deserialization (msgpack or JSON)
- [ ] Delivery confirmation handling

**Risk:** Low-medium. LXMF is simpler than RNS. Message format is JSON that
we already defined in the Python TrailDrop.

### Phase 5: UI — Waypoint Management (3-5 days)
Build the on-device interface using LVGL.

- [ ] Boot screen with identity/address display
- [ ] Main screen: list of waypoints with category icons
- [ ] Drop waypoint: select category, type description, auto-fill GPS coords
- [ ] Send waypoint: select from known peers, send via LoRa
- [ ] Receive waypoint: notification, auto-store, display
- [ ] Emergency beacon: dedicated button/shortcut
- [ ] Peer list: discovered peers from announces
- [ ] Settings: frequency, TX power, display name
- [ ] Battery indicator
- [ ] GPS fix status indicator

**UI framework:** LVGL (Light and Versatile Graphics Library)
- LilyGO provides LVGL examples for T-Deck
- Supports keyboard and trackball input natively
- Rich widget set (lists, buttons, text areas, message boxes)

**Risk:** Medium. LVGL has a learning curve but T-Deck examples exist.
The keyboard/trackball integration is the tricky part.

### Phase 6: Storage & Persistence (1-2 days)
- [ ] SQLite on SD card (or LittleFS on flash for small datasets)
- [ ] Save/load identity keypair
- [ ] Save/load known peers
- [ ] Waypoint database with search
- [ ] GPX export to SD card

**Risk:** Low. ESP32 has good SQLite and filesystem support.

### Phase 7: Integration & Testing (2-3 days)
- [ ] End-to-end: T-Deck Plus ↔ T-Deck Plus waypoint exchange
- [ ] Cross-platform: T-Deck Plus ↔ laptop running Python TrailDrop
- [ ] Range testing outdoors
- [ ] Battery life profiling
- [ ] Edge cases: GPS cold start, out-of-range, message queuing

---

## Total Effort Estimate

| Phase | Days | Risk |
|-------|------|------|
| 1. Hardware bringup | 1-2 | Low |
| 2. Crypto foundation | 2-3 | Low |
| 3. Reticulum wire protocol | 3-5 | Medium |
| 4. LXMF message layer | 2-3 | Low-Med |
| 5. UI | 3-5 | Medium |
| 6. Storage & persistence | 1-2 | Low |
| 7. Integration & testing | 2-3 | Medium |
| **Total** | **14-23 days** | |

**Calendar time:** 3-5 weeks with focused effort, accounting for debugging
and protocol edge cases.

**Biggest risk:** Phase 3 (Reticulum wire protocol). The protocol is defined
by its Python implementation, not a formal spec. Getting the packet format,
crypto handshake, and announce mechanism exactly right for interoperability
requires careful reading of the Python source. If we only target T-Deck ↔
T-Deck (not interop with Python nodes), this simplifies dramatically — we
could define our own simpler wire format.

---

## Decision Points

1. **Interop or standalone?**
   - Interop with Python Reticulum = harder but connects to the whole ecosystem
   - Standalone T-Deck-only protocol = easier but isolated
   - **Recommendation:** Start with interop as the goal, but build incrementally.
     Phase 1-2 work is the same either way.

2. **Arduino/PlatformIO or ESP-IDF?**
   - Arduino: easier, more examples for T-Deck, faster prototyping
   - ESP-IDF: more control, better crypto support (libsodium component), FreeRTOS native
   - **Recommendation:** PlatformIO with ESP-IDF framework. Best of both worlds.

3. **Map display?**
   - 320×240 is small but usable for a simple waypoint dot map
   - Could store offline map tiles on SD card (OpenStreetMap)
   - **Phase 2 feature** — get text-based UI working first

4. **Build it ourselves or contribute to existing projects?**
   - The RNode firmware Community Edition accepts board support PRs
   - Sideband has a plugin system
   - A standalone Reticulum-compatible C library would benefit the whole community
   - **Consider:** Building the C crypto+protocol layer as a reusable library,
     then TrailDrop as an application on top

---

## Prior Art

- **RNode Firmware** (C/Arduino): Already runs on T-Deck, handles LoRa.
  Uses RadioLib for SX1262. Good reference for radio code.
- **Meshtastic** (C++/Arduino): Full mesh firmware for ESP32+LoRa.
  Has T-Deck support with UI. Different protocol but similar hardware abstraction.
- **Reticulum MeshChat** (Python+Web): LXMF client, good reference for message handling.
- **Sideband** (Python/Kivy): Full LXMF client with telemetry/location. Plugin system.

---

## Getting Started

```bash
# Clone T-Deck examples
git clone https://github.com/Xinyuan-LilyGO/T-Deck.git

# Install PlatformIO
pip install platformio

# Build and flash UnitTest to verify hardware
cd T-Deck
pio run -e T-Deck -t upload
```

Then: Phase 1 hardware bringup, one peripheral at a time.
