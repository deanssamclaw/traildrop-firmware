# Phase 4 Research: LXMF Message Layer for TrailDrop

## What LXMF Is

LXMF (Lightweight Extensible Message Format) is the messaging layer on top of Reticulum. It adds:
- Source + destination identity
- Signed messages (Ed25519)
- Timestamps
- Structured fields (title, content, custom fields via msgpack)
- Delivery methods: opportunistic (single packet), direct (link), propagated (store-and-forward)

**For TrailDrop, we only need OPPORTUNISTIC delivery** — single-packet messages broadcast to a known destination. No links, no propagation nodes, no store-and-forward. That dramatically simplifies the implementation.

## LXMF Wire Format (from LXMessage.py source)

### Packed Message Structure
```
dest_hash(16) + source_hash(16) + signature(64) + msgpack(payload)
```

### Payload (msgpack array)
```
[timestamp, title, content, fields]
```
- `timestamp`: float64 (Unix epoch seconds)
- `title`: bytes (UTF-8 encoded string)
- `content`: bytes (UTF-8 encoded string)
- `fields`: dict (field_id → value, msgpack encoded)

### Message Hash
```
hashed_part = dest_hash + source_hash + msgpack(payload)
message_hash = sha256(hashed_part)   // full 32 bytes
```

### Signature
```
signed_part = hashed_part + message_hash
signature = ed25519_sign(source_identity_private_key, signed_part)
```

### Opportunistic Delivery (what we implement)
When sent as an opportunistic single packet:
- The packet's destination IS the recipient, so `dest_hash` is already in the RNS packet header
- The LXMF data sent in the packet EXCLUDES the dest_hash (it's inferred from packet destination)
- On receive, the router prepends `packet.destination.hash` to reconstruct full LXMF data
- Encrypted with recipient's public key (identity_encrypt — we already have this!)

So the encrypted payload of our existing DATA packet would contain:
```
source_hash(16) + signature(64) + msgpack([timestamp, title, content, fields])
```

### LXMF Overhead
```
LXMF_OVERHEAD = 2*16 + 64 + 8 + 8 = 112 bytes
  - 16 bytes dest_hash (inferred from packet in opportunistic mode)
  - 16 bytes source_hash
  - 64 bytes Ed25519 signature
  - 8 bytes timestamp (in msgpack)
  - 8 bytes msgpack structure overhead
```

### Maximum Content Size (Opportunistic)
```
ENCRYPTED_PACKET_MDU = RNS_MAX_PAYLOAD - 32(ephemeral) - 16(iv) - 32(hmac) - 16(padding_worst_case)
                     ≈ 481 - 96 = ~385 bytes after encryption overhead
                     
Wait, let me compute precisely:
  RNS_MTU = 500
  H1 packet: flags(1) + hops(1) + dest_hash(16) + context(1) + payload
  Max payload = 500 - 19 = 481 bytes
  
  Encryption overhead: ephemeral_pub(32) + iv(16) + hmac(32) + padding(up to 16) = 96 max
  Max plaintext in encrypted packet ≈ 481 - 96 = 385 bytes
  
  LXMF overhead (opportunistic, dest_hash inferred): 16 + 64 + ~16 = ~96 bytes
  (source_hash=16, signature=64, msgpack overhead ~16 for timestamp+structure)
  
  Max LXMF content ≈ 385 - 96 = ~289 bytes

Python Reticulum says: ENCRYPTED_PACKET_MAX_CONTENT = 295 bytes (close enough, they compute more precisely)
```

For waypoints this is plenty: `{"lat":38.9717,"lon":-95.2353,"ele":267,"name":"Camp","notes":"Water source nearby"}` ≈ 80 bytes.

## LXMF Fields for TrailDrop

We'll use `FIELD_CUSTOM_TYPE` (0xFB) and `FIELD_CUSTOM_DATA` (0xFC) to embed waypoint data:

```python
fields = {
    0xFB: b"traildrop/waypoint",     # FIELD_CUSTOM_TYPE
    0xFC: msgpack_encoded_waypoint   # FIELD_CUSTOM_DATA
}
```

Waypoint structure (msgpack dict):
```json
{
    "lat": 38.9717,
    "lon": -95.2353,
    "ele": 267,
    "name": "Camp",
    "notes": "Water source nearby",
    "ts": 1709312400
}
```

This is the clean way to do it — any LXMF client (Sideband, NomadNet) would see a message with custom fields, and TrailDrop clients would know to parse the waypoint data.

## Dependencies

### Already Have (Phase 3)
- ✅ Identity (key generation, persistence, sign/verify, encrypt/decrypt)
- ✅ Destination (hash computation)
- ✅ Packet (serialize/deserialize, wire format)
- ✅ Announce (peer discovery)
- ✅ Transport (send/receive over LoRa)

### Need for Phase 4
- **msgpack**: Serialize/deserialize LXMF payload and fields
  - Options: lightweight C msgpack library for ESP32 (e.g., mpack, CMP, or manual encoding)
  - For our simple structures, manual encoding may be simplest (msgpack format is straightforward for arrays and maps)
- **LXMF message build/parse**: Construct and parse LXMF packed format
- **GPS reading**: Parse NMEA sentences from GPS UART (already initialized in HAL)
- **Waypoint storage**: Save received waypoints to SD card
- **Display UI**: Show peers, waypoints, GPS position on TFT

## Proposed Sub-Phases

### Phase 4a: msgpack + LXMF message format
- Implement minimal msgpack encoder/decoder (array, map, bin, str, float64, int)
- Build LXMF message: pack payload, compute hash, sign, assemble packed bytes
- Parse LXMF message: unpack, verify signature, extract fields
- Test with known vectors from Python LXMF
- **Acceptance criteria**: Build an LXMF message on ESP32, verify Python can unpack_from_bytes() it. And vice versa.

### Phase 4b: LXMF over transport
- Integrate LXMF build/parse with existing transport layer
- Send LXMF message to peer (opportunistic, encrypted)
- Receive and decrypt LXMF message, parse, deliver to callback
- Replace current "Hello from TrailDrop!" test message with actual LXMF
- **Acceptance criteria**: Device A sends LXMF message, Device B receives and decrypts, Python can also parse the raw bytes

### Phase 4c: Waypoint payload + GPS
- Define waypoint JSON/msgpack schema
- Read GPS NMEA sentences, parse lat/lon/ele
- Send waypoint LXMF message (current GPS position + name)
- Receive waypoint, store to SD card
- **Acceptance criteria**: Press key → sends current GPS as waypoint → other device receives and stores it

### Phase 4d: Display UI
- Show discovered peers (name, dest hash, RSSI, last seen)
- Show received waypoints (name, lat/lon, distance from current position)
- Show current GPS status (fix, satellites, position)
- Basic keyboard navigation
- **Acceptance criteria**: Functional UI showing network state and waypoints

## Key Design Decisions Needed

1. **msgpack library**: Use an existing C library or hand-roll minimal encoder? Our structures are simple enough for manual encoding, but a library is less error-prone.

2. **LXMF app_name**: Python LXMF uses `"lxmf"` as app_name with `"delivery"` as aspect. Our current announce uses `"traildrop"` with `"waypoint"`. For LXMF compatibility, the delivery destination should be `lxmf.delivery`. We might need TWO destinations: one for LXMF delivery (`lxmf.delivery`) and one for TrailDrop-specific discovery (`traildrop.waypoint`).

3. **Announce app_data format**: LXMF 0.5.0+ uses msgpack array for announce app_data: `[display_name, stamp_cost]`. We should match this so LXMF clients can read our display name.

4. **GPS on T-Deck Plus**: The GPS UART is initialized but we haven't tested if the GPS module actually produces NMEA data. Need to verify.

## Reference Files
- Python LXMF source: `/usr/local/lib/python3.13/dist-packages/LXMF/`
- Key files: `LXMessage.py` (message format), `LXMF.py` (constants/fields), `LXMRouter.py` (delivery)
- Our firmware: `src/net/` (transport, announce, packet), `src/crypto/` (frozen)
- msgpack spec: https://msgpack.org/index.html
