# TrailDrop Firmware

Standalone backcountry waypoint sharing firmware for the LilyGO T-Deck Plus. Drop, send, and receive GPS waypoints over LoRa radio — no phone, no internet, no infrastructure.

## What It Does

Two (or more) T-Deck Plus devices can share waypoints directly over LoRa radio using the [Reticulum](https://reticulum.network) network protocol. Each device is fully standalone with GPS, keyboard, screen, and battery.

**Features:**
- 📍 Drop waypoints at your current GPS location with category and description
- 📤 Send waypoints to other TrailDrop devices over LoRa
- 📥 Receive waypoints from peers automatically
- 🚨 Emergency beacon — broadcast your location and status
- 🗺️ View and manage stored waypoints on-screen
- 📁 Export waypoints to GPX on SD card
- 🔒 End-to-end encrypted communication (X25519 + AES-256)
- 🔗 Interoperable with [TrailDrop CLI](https://github.com/deanssamclaw/traildrop) (Python/Reticulum)

## Hardware

**Target device:** [LilyGO T-Deck Plus](https://www.lilygo.cc/products/t-deck-plus) (~$71)

| Component | Chip/Spec | Use |
|-----------|-----------|-----|
| MCU | ESP32-S3 (dual-core, 16MB flash, 8MB PSRAM) | Application processor |
| Radio | Semtech SX1262 LoRa (433/868/915 MHz) | Peer-to-peer communication |
| Display | 2.8" ST7789 IPS LCD (320×240) | Waypoint UI |
| Input | Physical keyboard + trackball | Text entry and navigation |
| GPS | Built-in GNSS module | Location acquisition |
| Storage | SD card slot + onboard flash | Waypoint database, GPX export |
| Power | 2000mAh battery | Portable operation |
| Audio | Speaker + ES7210 mic | Future: audio alerts |

## Project Structure

```
traildrop-firmware/
├── README.md
├── STANDALONE_SCOPE.md          # Detailed development scope and phases
├── platformio.ini               # PlatformIO build configuration
├── sdkconfig.defaults           # ESP-IDF defaults (crypto, etc.)
│
├── include/
│   └── config.h                 # Pin definitions, radio defaults, feature flags
│
├── src/
│   ├── main.cpp                 # Entry point, task initialization
│   │
│   ├── hal/                     # Hardware abstraction layer
│   │   ├── display.h / .cpp     # ST7789 screen via TFT_eSPI
│   │   ├── keyboard.h / .cpp    # I2C keyboard controller
│   │   ├── trackball.h / .cpp   # Trackball navigation input
│   │   ├── gps.h / .cpp         # UART GPS with NMEA parsing
│   │   ├── radio.h / .cpp       # SX1262 LoRa via RadioLib
│   │   ├── storage.h / .cpp     # SD card + flash filesystem
│   │   ├── battery.h / .cpp     # ADC battery level
│   │   └── power.h / .cpp       # Sleep, wake, peripheral power
│   │
│   ├── crypto/                  # Cryptographic primitives
│   │   ├── identity.h / .cpp    # X25519 + Ed25519 keypair management
│   │   ├── encrypt.h / .cpp     # AES-256-CBC encrypt/decrypt
│   │   └── hash.h / .cpp        # SHA-256, HMAC-SHA256
│   │
│   ├── net/                     # Reticulum protocol implementation
│   │   ├── packet.h / .cpp      # Packet framing, header flags, MTU
│   │   ├── destination.h / .cpp # Destination hash derivation
│   │   ├── announce.h / .cpp    # Announce broadcast and processing
│   │   ├── transport.h / .cpp   # Packet routing (single-hop initially)
│   │   └── lxmf.h / .cpp       # LXMF message format (waypoint, emergency)
│   │
│   ├── app/                     # Application logic
│   │   ├── waypoint.h / .cpp    # Waypoint data model and database
│   │   ├── peers.h / .cpp       # Discovered peer tracking
│   │   └── gpx.h / .cpp         # GPX export to SD card
│   │
│   └── ui/                      # LVGL user interface
│       ├── ui.h / .cpp          # UI manager, screen transitions
│       ├── screen_main.cpp      # Waypoint list (home screen)
│       ├── screen_drop.cpp      # Drop new waypoint
│       ├── screen_send.cpp      # Send waypoint to peer
│       ├── screen_peers.cpp     # Discovered peers list
│       ├── screen_detail.cpp    # Waypoint detail view
│       ├── screen_settings.cpp  # Radio, display, identity settings
│       └── screen_emergency.cpp # Emergency beacon
│
├── lib/                         # Third-party libraries (managed by PlatformIO)
│
├── test/                        # Unit tests (PlatformIO test framework)
│   ├── test_crypto/             # Crypto primitive tests
│   ├── test_packet/             # Packet framing tests
│   └── test_waypoint/           # Waypoint model tests
│
├── docs/
│   └── wire_format.md           # Reticulum packet format notes (from source reading)
│
└── assets/
    └── icons/                   # Category icons for UI (camp, water, fuel, etc.)
```

## Building

Requires [PlatformIO](https://platformio.org/).

```bash
# Clone
git clone https://github.com/deanssamclaw/traildrop-firmware.git
cd traildrop-firmware

# Build
pio run

# Flash to T-Deck Plus via USB
pio run -t upload

# Monitor serial output
pio run -t monitor
```

## Development Phases

See [STANDALONE_SCOPE.md](STANDALONE_SCOPE.md) for detailed breakdown.

1. **Hardware bringup** — get all peripherals initialized and talking
2. **Crypto foundation** — libsodium integration for Reticulum crypto
3. **Reticulum wire protocol** — packet format, identity, announces
4. **LXMF messages** — waypoint and emergency message types
5. **UI** — LVGL screens for waypoint management
6. **Storage** — persistent waypoints, keypairs, peer list
7. **Integration testing** — device-to-device and cross-platform with Python TrailDrop

## Interoperability

TrailDrop Firmware implements a subset of the [Reticulum](https://reticulum.network) protocol, enough to exchange LXMF messages with:

- Other T-Deck Plus devices running this firmware
- The [Python TrailDrop CLI](https://github.com/deanssamclaw/traildrop) on laptops/desktops
- Any Reticulum/LXMF client (Sideband, MeshChat, Nomad Network)

## Radio

Uses raw LoRa modulation via the SX1262 (not LoRaWAN). Default configuration:

| Parameter | Value |
|-----------|-------|
| Frequency | 915 MHz (US ISM band) |
| Bandwidth | 125 kHz |
| Spreading Factor | 8 |
| TX Power | 7 dBm (configurable up to 22 dBm) |

Typical range: 1-3 km in hilly/forested terrain, 10+ km line of sight.

## License

MIT

## Related

- [TrailDrop CLI](https://github.com/deanssamclaw/traildrop) — Python version for laptops
- [Reticulum](https://reticulum.network) — The networking stack
- [LXMF](https://github.com/markqvist/lxmf) — The messaging protocol
- [T-Deck Hardware](https://github.com/Xinyuan-LilyGO/T-Deck) — LilyGO's reference code and pin maps
