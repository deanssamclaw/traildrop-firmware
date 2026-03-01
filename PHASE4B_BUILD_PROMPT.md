# Phase 4b Build Prompt: LXMF Over Transport

## Goal
Wire LXMF message build/parse into the existing transport layer. Two devices should be able to send and receive actual LXMF messages (with title, content, and custom fields) encrypted over LoRa.

## Background
- Phase 3: Transport layer works — encrypted DATA packets between devices ✅
- Phase 4a: msgpack + LXMF build/parse/verify — bit-exact with Python ✅
- Phase 4a.5: Dual destinations (lxmf.delivery + traildrop.waypoint) + announce migration ✅
- Currently `transport_send_data()` sends raw plaintext bytes. We need to send LXMF-formatted messages instead.

## What to Build

### 1. LXMF send function (`src/msg/lxmf_transport.h`, `src/msg/lxmf_transport.cpp`)

```cpp
namespace msg {

// Send an LXMF message to a peer (opportunistic, encrypted)
// Looks up peer by announce dest_hash, encrypts to their lxmf.delivery dest_hash
// Returns true if message was built, encrypted, and transmitted
bool lxmf_send(
    const crypto::Identity& our_identity,
    const uint8_t our_lxmf_dest[16],     // our lxmf.delivery dest hash
    const uint8_t peer_announce_dest[16], // peer's traildrop.waypoint dest hash (for peer lookup)
    const char* title,
    const char* content,
    const uint8_t* custom_type, size_t custom_type_len,  // nullable
    const uint8_t* custom_data, size_t custom_data_len,  // nullable
    uint8_t message_hash_out[32]          // output: message hash for dedup
);

// Callback type for received LXMF messages
typedef void (*lxmf_receive_callback_t)(const LXMessage& msg, int rssi, float snr);

// Register callback for incoming LXMF messages
void lxmf_set_receive_callback(lxmf_receive_callback_t cb);

} // namespace msg
```

**Send flow:**
1. Look up peer by `peer_announce_dest` → get peer's x25519_public, identity_hash, lxmf_dest_hash
2. Call `lxmf_build()` with our identity, our lxmf dest, peer's lxmf dest, title, content, fields
3. Encrypt the LXMF plaintext with `identity_encrypt()` using peer's x25519 public key
4. Build an RNS DATA packet: dest_hash = peer's lxmf_dest_hash, payload = encrypted data
5. Transmit via `hal::radio_send()`

**Important:** The DATA packet's `dest_hash` must be the peer's `lxmf_dest_hash` (lxmf.delivery), NOT their announce dest_hash (traildrop.waypoint). This is what makes it routable to LXMF clients.

### 2. LXMF receive integration

**In `transport_receive()` or as a new handler:**
1. When a DATA packet arrives, check if `pkt.dest_hash` matches OUR `lxmf_dest_hash`
2. If yes: decrypt with our identity → get plaintext LXMF bytes
3. Prepend our lxmf_dest_hash to the decrypted data (reconstruct full LXMF format)
4. Call `lxmf_parse()` to extract message fields
5. Call `lxmf_verify()` with the sender's ed25519 public key (look up from peer table by source_hash)
6. Call the registered callback with the parsed message

**Peer lookup for verification:** The LXMF message contains `source_hash` (the sender's lxmf.delivery dest_hash). We need to find the peer whose `lxmf_dest_hash` matches this source_hash to get their ed25519 public key for signature verification.

Add to peer.h:
```cpp
// Look up peer by lxmf_dest_hash (for LXMF source verification)
const Peer* peer_lookup_by_lxmf_dest(const uint8_t lxmf_dest[16]);
```

### 3. Message deduplication

Add a ring buffer of recently-seen message hashes to prevent processing duplicates:

```cpp
static const size_t DEDUP_BUFFER_SIZE = 64;
static uint8_t dedup_hashes[DEDUP_BUFFER_SIZE][32];
static size_t dedup_index = 0;

bool is_duplicate(const uint8_t hash[32]);
void record_message(const uint8_t hash[32]);
```

Check before delivering to callback. This handles retransmissions and multi-path reception.

### 4. Update main_test.cpp

**Replace the current 's' key handler:** Instead of sending raw "Hello from TrailDrop!", send an actual LXMF message:
```cpp
// On 's' key press:
msg::lxmf_send(
    device_identity,
    device_lxmf_destination.hash,
    peer->dest_hash,               // announce dest for peer lookup
    "Test",                         // title
    "Hello from TrailDrop!",        // content
    (const uint8_t*)"traildrop/waypoint", 19,  // custom_type
    nullptr, 0,                     // no custom_data yet
    msg_hash
);
```

**Add receive callback that logs the parsed LXMF message:**
```cpp
void on_lxmf_received(const msg::LXMessage& msg, int rssi, float snr) {
    Serial.printf("[LXMF] Received message!\n");
    Serial.printf("[LXMF] Title: %.*s\n", (int)msg.title_len, msg.title);
    Serial.printf("[LXMF] Content: %.*s\n", (int)msg.content_len, msg.content);
    Serial.printf("[LXMF] Signature valid: %s\n", msg.signature_valid ? "YES" : "NO");
    if (msg.has_custom_fields) {
        Serial.printf("[LXMF] Custom type: %.*s\n", (int)msg.custom_type_len, msg.custom_type);
    }
    Serial.printf("[LXMF] RSSI=%d SNR=%.1f\n", rssi, snr);
}
```

**Keep the auto-send feature** (30s after peer discovery) but send LXMF instead of raw data.

**Add tests:**
1. LXMF send builds correct packet (verify encrypted payload can be decrypted and parsed)
2. LXMF receive parses correctly (craft a known LXMF packet, feed to receiver)
3. Dedup: same message hash rejected on second delivery
4. Peer lookup by lxmf_dest works

### 5. Wire compatibility test update

Update `tests/hardware_wire_compat_test.py` to capture and parse LXMF packets:
- Capture encrypted DATA packet from device
- Decrypt using device's known keys
- Parse as LXMF using Python `LXMessage.unpack_from_bytes()`
- Verify title, content, fields match what was sent

## Files to Create
- `src/msg/lxmf_transport.h` — LXMF send/receive declarations
- `src/msg/lxmf_transport.cpp` — LXMF send/receive implementation

## Files to Modify
- `src/net/peer.h` — add `peer_lookup_by_lxmf_dest()`
- `src/net/peer.cpp` — implement lookup
- `src/main_test.cpp` — new 's' key handler, receive callback, tests, auto-send update
- `tests/hardware_wire_compat_test.py` — LXMF packet capture/parse (optional, if time)

## Files NOT to Modify (frozen)
- `src/crypto/*`
- `src/hal/*`
- `src/net/packet.*`, `src/net/announce.*`, `src/net/transport.*` (Phase 3 frozen)
- `src/msg/msgpack.*`, `src/msg/lxmf.*` (Phase 4a frozen)

## Important Details

- **Timestamp:** Use `millis() / 1000.0` as a relative timestamp for now (ESP32 has no RTC). Python LXMF uses `time.time()` (Unix epoch). For device-to-device this is fine; for Python interop we'll need NTP or GPS time later.
- **Encryption:** Use `crypto::identity_encrypt()` — same as current transport_send_data. The plaintext is the LXMF bytes (source_hash + signature + packed_payload), NOT the full packed message (dest_hash is excluded for opportunistic delivery).
- **DATA packet context byte:** Use `0x00` (no link context) for opportunistic delivery.
- **The dest_hash in the RNS packet header** = peer's lxmf.delivery dest_hash. This is how the receiver knows the packet is for their LXMF handler.

## Build & Test
- Compile: `ssh rflab-sam "cd ~/traildrop-firmware && git pull && pio run -e t-deck-plus"`
- Git: individual commands (`git add -A`, `git commit -m "..."`, `git push`)

## Acceptance Criteria
1. ✅ lxmf_send() builds, encrypts, and transmits LXMF message to peer
2. ✅ Receiver decrypts, parses LXMF, verifies signature, delivers to callback
3. ✅ Title, content, and custom fields round-trip correctly between two devices
4. ✅ Message deduplication prevents double-delivery
5. ✅ Peer lookup by lxmf_dest_hash works for source verification
6. ✅ 's' key sends LXMF message, serial output shows parsed fields on receiver
7. ✅ Auto-send (30s after discovery) sends LXMF instead of raw data
8. ✅ All existing tests still pass
9. ✅ Compiles on rflab, flash/RAM under 20%

## References
- LXMF build/parse: `src/msg/lxmf.h`, `src/msg/lxmf.cpp`
- Transport send/receive: `src/net/transport.cpp` (reference for radio TX/RX flow)
- Encryption: `src/crypto/identity.cpp` (`identity_encrypt`, `identity_decrypt`)
- Peer table: `src/net/peer.h`, `src/net/peer.cpp`
- Cal's Phase 4 review: `memory/topics/sam-infra/phase4-cal-review.md`
- Python LXMF delivery: `LXMRouter.py:1817-1843` (delivery_packet, lxmf_delivery)
