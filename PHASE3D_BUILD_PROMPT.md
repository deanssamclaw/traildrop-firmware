# Phase 3d: Transport Layer — Send/Receive Loop — Build Prompt

## Context

TrailDrop firmware on LilyGO T-Deck Plus (ESP32-S3). Phases 1-3c complete. This is the final networking sub-phase — wiring up the transport layer to actually send and receive packets over LoRa radio.

Work in: `/Users/systems/.openclaw/workspace/traildrop-firmware/`

## What This Phase Does

The transport layer connects everything:
- **Send:** Serialize a `Packet` struct → transmit raw bytes via `hal::radio_send()`
- **Receive:** `hal::radio_receive()` raw bytes → deserialize → dispatch by packet_type
- **Dispatch:** ANNOUNCE → `announce_process()`, DATA → decrypt if for us, PROOF → match + confirm
- **Periodic announce:** Send our identity announce every `ANNOUNCE_INTERVAL` seconds

## What to Build

### 1. Rebuild `src/net/transport.h`

```cpp
#pragma once
#include <cstdint>
#include <cstddef>
#include "config.h"
#include "net/packet.h"
#include "crypto/identity.h"
#include "net/destination.h"

namespace net {

// Initialize transport layer. Call after radio, identity, and destination are ready.
// Stores references to device identity and destination for packet handling.
bool transport_init(const crypto::Identity& id, const Destination& dest);

// Send a packet over LoRa radio.
// Serializes the packet and transmits via hal::radio_send().
// Returns true on success.
bool transport_send(const Packet& pkt);

// Send a data packet to a known peer (by destination hash).
// Encrypts payload for the peer using identity_encrypt.
// Returns true on success, false if peer unknown or encryption fails.
bool transport_send_data(const uint8_t peer_dest_hash[DEST_HASH_SIZE],
                         const uint8_t* data, size_t data_len);

// Poll for incoming packets. Call from loop().
// Receives raw bytes from radio, deserializes, dispatches by packet_type.
void transport_poll();

// Send our announce packet. Called periodically and on demand.
bool transport_announce(const char* app_data);

// Get transport statistics
uint32_t transport_rx_count();
uint32_t transport_tx_count();

// Callback type for received data packets addressed to us
typedef void (*data_callback_t)(const uint8_t* sender_dest_hash,
                                 const uint8_t* data, size_t data_len);

// Register callback for incoming data packets
void transport_on_data(data_callback_t cb);

} // namespace net
```

### 2. Implement `src/net/transport.cpp`

```cpp
#include "transport.h"
#include "net/announce.h"
#include "net/peer.h"
#include "hal/radio.h"
#include "crypto/identity.h"
#include "crypto/encrypt.h"
#include <Arduino.h>
#include <cstring>
```

**State variables (file-scope static):**
```cpp
static const crypto::Identity* s_identity = nullptr;
static const net::Destination* s_destination = nullptr;
static uint32_t s_last_announce = 0;
static uint32_t s_rx_count = 0;
static uint32_t s_tx_count = 0;
static net::data_callback_t s_data_callback = nullptr;
```

**`transport_init`:**
- Store pointers to identity and destination
- Set `s_last_announce = 0` to trigger immediate first announce
- Return true

**`transport_send`:**
1. Serialize packet: `net::packet_serialize(pkt, buf, RNS_MTU)`
2. If serialize fails, return false
3. Send raw bytes: `hal::radio_send(buf, len)`
4. Increment `s_tx_count`
5. Return `result == RADIOLIB_ERR_NONE` (radio_send returns RadioLib error code)
6. Log to Serial: `Serial.printf("[TX] %d bytes, type=%d\n", len, pkt.get_packet_type())`

**`transport_send_data`:**
1. Look up peer: `net::peer_lookup(peer_dest_hash)` — return false if nullptr
2. Build a temporary `crypto::Identity` for the peer with just the public keys (x25519_public, ed25519_public) from the Peer struct — you need this for `crypto::identity_encrypt()`
3. Encrypt: `crypto::identity_encrypt(peer_id, data, data_len, encrypted, &enc_len)` 
4. Build a Packet:
   - `set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_DATA)`
   - `hops = 0`, `has_transport = false`
   - `dest_hash = peer_dest_hash`
   - `context = CTX_NONE`
   - `payload = encrypted data`, `payload_len = enc_len`
5. Call `transport_send(pkt)`

**Important note on `transport_send_data` step 2:** The `crypto::Identity` struct has both public and private keys. For encryption to a peer, you only need their public x25519 key. Check how `crypto::identity_encrypt()` works — read `src/crypto/encrypt.h` and `encrypt.cpp`. It uses the RECIPIENT's x25519_public to do ECDH with an ephemeral key. You just need to populate the x25519_public field of a temporary Identity struct. The private keys and ed25519 fields can be zeroed.

**`transport_poll`:**
1. Try receive: `hal::radio_receive(rx_buf, sizeof(rx_buf))`
2. If `rx_len <= 0`, return (nothing received)
3. Deserialize: `net::packet_deserialize(rx_buf, rx_len, pkt)`
4. If deserialize fails, log error and return
5. Increment `s_rx_count`
6. Log: `Serial.printf("[RX] %d bytes, type=%d, RSSI=%.1f SNR=%.1f\n", rx_len, pkt.get_packet_type(), hal::radio_rssi(), hal::radio_snr())`
7. Dispatch by packet_type:
   - **PKT_ANNOUNCE:** `net::announce_process(pkt)` — log success/failure
   - **PKT_DATA:** Check if `memcmp(pkt.dest_hash, s_destination->hash, DEST_HASH_SIZE) == 0` (addressed to us). If yes, decrypt with `crypto::identity_decrypt(*s_identity, pkt.payload, pkt.payload_len, decrypted, &dec_len)`. If decrypt succeeds and callback registered, call `s_data_callback(pkt.dest_hash, decrypted, dec_len)`. If decrypt fails, log and ignore.
   - **PKT_PROOF:** Log receipt, don't process yet (Phase 4)
   - **PKT_LINKREQUEST:** Log receipt, ignore (not implementing links)

**Important for PKT_DATA decryption:** `identity_decrypt` uses our PRIVATE keys. The `*s_identity` has both public and private keys (it's our device identity). Read `src/crypto/encrypt.cpp` to verify the decrypt function signature.

**Buffer sizing rule (from Cal):** All receive buffers must be sized to maximum INPUT. Use `uint8_t rx_buf[RNS_MTU]` for radio receive. Use `uint8_t decrypted[RNS_MTU]` for decrypt output.

**`transport_announce`:**
1. Check if `s_identity` and `s_destination` are set — return false if not
2. Build announce: `net::announce_build(*s_identity, *s_destination, app_data, pkt)`
3. Send: `transport_send(pkt)`
4. Update `s_last_announce = millis()`
5. Log: `Serial.println("[TX] Announce sent")`

**`transport_on_data`:** Store callback pointer in `s_data_callback`.

**Statistics:** Simple getters returning `s_rx_count` / `s_tx_count`.

### 3. Integrate into main_test.cpp

**In setup(), after identity is ready:**
```cpp
if (identity_ready && boot.radio) {
    net::transport_init(device_identity, device_destination);
    
    // Register data callback
    net::transport_on_data([](const uint8_t* sender, const uint8_t* data, size_t len) {
        Serial.printf("[DATA] Received %d bytes from ", len);
        for (int i = 0; i < 4; i++) Serial.printf("%02x", sender[i]);
        Serial.printf("...\n");
        // Print data as string if printable
        Serial.printf("[DATA] Content: %.*s\n", (int)len, (const char*)data);
    });
    
    // Send initial announce
    net::transport_announce(APP_NAME);
    Serial.println("[NET] Transport initialized, announce sent");
}
```

**In loop(), add transport polling and periodic announce:**
```cpp
// --- Network polling ---
if (identity_ready && boot.radio) {
    net::transport_poll();
    
    // Periodic announce
    static uint32_t last_announce_check = 0;
    if (now - last_announce_check >= (ANNOUNCE_INTERVAL * 1000UL)) {
        last_announce_check = now;
        net::transport_announce(APP_NAME);
    }
}
```

**Add a transport status line to the periodic display update:**
```cpp
// Network status
if (identity_ready) {
    hal::display_printf(0, y_start, 0x07FF, 1,
        "Net: TX=%lu RX=%lu Peers=%d   ",
        net::transport_rx_count(), net::transport_tx_count(),
        net::peer_count());
}
```

### 4. Add tests

Add `run_transport_tests()` after announce tests. Since transport tests involve the radio HAL which may not be available in all test environments, keep tests focused on serialization and logic rather than actual radio I/O:

**Test 1: Transport send serializes correctly**
- Create a known DATA packet
- Mock: we can't actually test radio_send, but we can test that packet_serialize produces valid output that packet_deserialize can round-trip
- This is really a packet integration test — serialize a DATA packet with encrypted payload, deserialize, verify fields match

**Test 2: Announce timer logic**
- Verify ANNOUNCE_INTERVAL is defined and > 0
- Verify `transport_announce()` returns false before `transport_init()` is called

**Test 3: Data callback registration**
- Register a callback via `transport_on_data()`
- Verify it's stored (call transport_init, register callback — no crash)

Note: Full integration tests (actual radio send/receive between two devices) are Phase 7 (interop testing). These unit tests verify the logic layer works correctly.

### 5. Update docs/wire_format.md

Add a "Transport Layer" section at the end documenting:
- Send flow: Packet → serialize → radio_send
- Receive flow: radio_receive → deserialize → dispatch
- Announce interval (300s default)
- Packet type dispatch table

## Constraints

- **DO NOT modify `src/crypto/`** — Phase 2 is frozen
- **DO NOT modify `src/hal/`** — HAL is frozen
- **DO NOT modify `src/net/packet.h` or `src/net/packet.cpp`** — frozen
- **DO NOT modify `src/net/destination.h` or `src/net/destination.cpp`** — frozen
- **DO NOT modify `src/net/announce.h`, `src/net/announce.cpp`, `src/net/peer.h`, `src/net/peer.cpp`** — frozen
- **Buffer sizing rule:** All buffers handling incoming data sized to max INPUT (RNS_MTU), not max output
- Must compile clean with `pio run -e t-deck-plus`

## Acceptance Criteria

1. ✅ `transport_init()` stores identity and destination references
2. ✅ `transport_send()` serializes packet and calls `hal::radio_send()`
3. ✅ `transport_send_data()` encrypts for peer and sends DATA packet
4. ✅ `transport_poll()` receives, deserializes, and dispatches by packet_type
5. ✅ ANNOUNCE dispatched to `announce_process()`
6. ✅ DATA packets addressed to us are decrypted and delivered via callback
7. ✅ DATA packets not for us are silently ignored
8. ✅ `transport_announce()` builds and sends announce packet
9. ✅ Periodic announce wired into loop() with ANNOUNCE_INTERVAL
10. ✅ Transport stats (rx_count, tx_count) tracked and displayed
11. ✅ Data callback mechanism works
12. ✅ All transport tests pass
13. ✅ Network status displayed on LCD
14. ✅ Existing tests unmodified and still pass
15. ✅ `pio run -e t-deck-plus` compiles clean
16. ✅ Committed and pushed to `deanssamclaw/traildrop-firmware`

When completely finished, run:
`openclaw system event --text "Done: Phase 3d transport layer — send/receive loop" --mode now`
