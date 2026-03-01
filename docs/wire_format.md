# Reticulum Wire Format — TrailDrop Implementation

This document describes the exact Reticulum packet wire format implemented in TrailDrop firmware, based on analysis of the Python reference implementation (`RNS/Packet.py`).

## Packet Flags Byte (byte 0)

The flags byte packs 5 fields into a single byte:

```
Bit 7:   unused (always 0)
Bit 6:   header_type      0=HEADER_1 (no transport), 1=HEADER_2 (with transport_id)
Bit 5:   context_flag     used in announces (ratchet presence)
Bit 4:   transport_type   0=BROADCAST, 1=TRANSPORT
Bit 3-2: destination_type 00=SINGLE, 01=GROUP, 10=PLAIN, 11=LINK
Bit 1-0: packet_type      00=DATA, 01=ANNOUNCE, 02=LINKREQUEST, 03=PROOF
```

### Construction

```cpp
flags = (header_type << 6) | (context_flag << 5) | (transport_type << 4)
      | (destination_type << 2) | packet_type
```

### Unpacking

```cpp
header_type      = (flags >> 6) & 0x01
context_flag     = (flags >> 5) & 0x01
transport_type   = (flags >> 4) & 0x01
destination_type = (flags >> 2) & 0x03
packet_type      = flags & 0x03
```

## Header Formats

### HEADER_1 (normal, no transport) — 19 bytes header

```
Offset  Size   Field
0       1      flags
1       1      hops
2       16     destination_hash
18      1      context
19+     N      payload (max MTU-19 = 481 bytes)
```

Total packet size: 19 + payload_len (range: 19-500 bytes)

### HEADER_2 (with transport_id) — 35 bytes header

```
Offset  Size   Field
0       1      flags
1       1      hops
2       16     transport_id
18      16     destination_hash
34      1      context
35+     N      payload (max MTU-35 = 465 bytes)
```

Total packet size: 35 + payload_len (range: 35-500 bytes)

## Packet Hash Algorithm

**Critical:** The packet hash is NOT computed over raw bytes. It's computed over a "hashable part" that strips transport metadata to ensure the same logical packet hashes identically regardless of transport path or hop count.

### Algorithm

```
For HEADER_1:
  hashable_part = (flags & 0x0F) || raw_bytes[2:]
  // byte 0: only keep dest_type + pkt_type (strip header_type, context_flag, transport_type)
  // skip byte 1 (hops)
  // include: destination_hash + context + payload

For HEADER_2:
  hashable_part = (flags & 0x0F) || raw_bytes[18:]
  // byte 0: only keep dest_type + pkt_type
  // skip: hops(1) + transport_id(16) = 17 bytes
  // include: destination_hash + context + payload

packet_hash = SHA-256(hashable_part)       // full 32 bytes
truncated_hash = packet_hash[0:16]         // first 16 bytes for addressing
```

### Why This Matters

Two packets with:
- Same destination_hash, context, and payload
- Different transport_id, hops, or header_type

Will produce the **same packet hash**. This is fundamental to Reticulum's deduplication and routing.

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `RNS_MTU` | 500 | Maximum transmission unit (bytes) |
| `RNS_HEADER1_SIZE` | 19 | HEADER_1 overhead |
| `RNS_HEADER2_SIZE` | 35 | HEADER_2 overhead |
| `RNS_MAX_PAYLOAD_H1` | 481 | Max payload for HEADER_1 (500-19) |
| `RNS_MAX_PAYLOAD_H2` | 465 | Max payload for HEADER_2 (500-35) |
| `DEST_HASH_SIZE` | 16 | Truncated SHA-256 hash (128 bits) |
| `RNS_HASH_LENGTH` | 32 | Full SHA-256 output |
| `RNS_TRUNCATED_HASH` | 16 | Truncated hash for addressing |

## Enums

### PacketType
```cpp
enum PacketType : uint8_t {
    PKT_DATA         = 0x00,
    PKT_ANNOUNCE     = 0x01,
    PKT_LINKREQUEST  = 0x02,
    PKT_PROOF        = 0x03,
};
```

### DestinationType
```cpp
enum DestinationType : uint8_t {
    DEST_SINGLE = 0x00,
    DEST_GROUP  = 0x01,
    DEST_PLAIN  = 0x02,
    DEST_LINK   = 0x03,
};
```

### HeaderType
```cpp
enum HeaderType : uint8_t {
    HEADER_1 = 0x00,  // No transport
    HEADER_2 = 0x01,  // With transport_id
};
```

### TransportType
```cpp
enum TransportType : uint8_t {
    TRANSPORT_BROADCAST = 0x00,
    TRANSPORT_TRANSPORT = 0x01,
};
```

### PacketContext
```cpp
enum PacketContext : uint8_t {
    CTX_NONE           = 0x00,
    CTX_RESOURCE        = 0x01,
    CTX_RESOURCE_ADV    = 0x02,
    CTX_RESOURCE_REQ    = 0x03,
    CTX_RESOURCE_HMU    = 0x04,
    CTX_RESOURCE_PRF    = 0x05,
    CTX_RESOURCE_ICL    = 0x06,
    CTX_RESOURCE_RCL    = 0x07,
    CTX_CACHE_REQUEST   = 0x08,
    CTX_REQUEST         = 0x09,
    CTX_RESPONSE        = 0x0A,
    CTX_PATH_RESPONSE   = 0x0B,
    CTX_COMMAND         = 0x0C,
    CTX_COMMAND_STATUS  = 0x0D,
    CTX_KEEPALIVE       = 0xFA,
    CTX_LINK_IDENTIFY   = 0xFB,
    CTX_LINK_CLOSE      = 0xFC,
    CTX_LINK_PROOF      = 0xFD,
    CTX_LRRTT           = 0xFE,
    CTX_LRPROOF         = 0xFF,
};
```

## Examples

### Example 1: Simple HEADER_1 Packet

```
Flags:    0x01  (HEADER_1, BROADCAST, SINGLE, ANNOUNCE)
Hops:     0x03
Dest:     00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
Context:  0x00
Payload:  "test_payload_data"

Serialized (hex):
01 03 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 00 74 65 73 74 5f 70 61 79 6c 6f 61 64 5f 64 61 74 61

Total size: 36 bytes (19 header + 17 payload)

Hashable part (for packet hash):
01 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 00 74 65 73 74 5f 70 61 79 6c 6f 61 64 5f 64 61 74 61
(flags & 0x0F, then dest_hash + context + payload — hops stripped)

Packet hash (SHA-256):
84 db e6 cd 02 86 40 2b 42 1e 6c 72 e1 db a3 b6
0a 57 0f ad 27 66 08 62 93 d4 a2 af 5c 7b 43 58

Truncated hash (first 16 bytes):
84 db e6 cd 02 86 40 2b 42 1e 6c 72 e1 db a3 b6
```

### Example 2: HEADER_2 vs HEADER_1 Hash Equivalence

```
Packet A (HEADER_1):
  Flags:  0x00  (HEADER_1, BROADCAST, SINGLE, DATA)
  Hops:   3
  Dest:   [00-0f]
  Context: 0x00
  Payload: "same payload"

Packet B (HEADER_2):
  Flags:  0x50  (HEADER_2, TRANSPORT, SINGLE, DATA)
  Hops:   7
  Transport: [aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa]
  Dest:   [00-0f]
  Context: 0x00
  Payload: "same payload"

Result: Both packets produce the SAME truncated packet hash because:
- Hashable part for both = (0x00) + dest_hash + context + payload
- Transport metadata (hops, transport_id, header_type, transport_type) is stripped
```

## Implementation Notes

### Serialization

1. Determine header size based on `has_transport` flag
2. Check payload size against max for header type
3. Write fields in order: flags, hops, [transport_id if H2], dest_hash, context, payload
4. Return total bytes written

### Deserialization

1. Read flags byte to determine header type
2. Validate minimum packet size (19 for H1, 35 for H2)
3. Parse fields based on header type
4. Extract payload (remaining bytes after header)
5. Return success/failure

### Packet Hash Computation

1. Determine skip offset: 2 for HEADER_1 (flags+hops), 18 for HEADER_2 (flags+hops+transport_id)
2. Build hashable_part: (flags & 0x0F) || raw[skip_offset:]
3. Compute SHA-256 of hashable_part
4. Return full hash and truncated (first 16 bytes)

## Transport Layer

### Send Flow

```
Application Data
      ↓
Build Packet struct
      ↓
transport_send(pkt)
      ↓
packet_serialize(pkt, buf, RNS_MTU)
      ↓
hal::radio_send(buf, len)
      ↓
LoRa Radio Transmission
```

### Receive Flow

```
LoRa Radio Reception
      ↓
hal::radio_receive(buf, RNS_MTU)
      ↓
packet_deserialize(raw, len, pkt)
      ↓
Dispatch by packet_type:
  - PKT_ANNOUNCE → announce_process(pkt)
  - PKT_DATA → decrypt if for us, call callback
  - PKT_PROOF → match and confirm (Phase 4)
  - PKT_LINKREQUEST → ignore (not implementing links)
```

### Periodic Announce

- **Interval:** `ANNOUNCE_INTERVAL` seconds (default: 300s = 5 minutes)
- **Trigger:** Called from main loop every `ANNOUNCE_INTERVAL` seconds
- **Function:** `transport_announce(app_data)`
- **Behavior:** Builds and sends an ANNOUNCE packet with device identity and destination

### Packet Type Dispatch Table

| Packet Type | Action | Handler |
|-------------|--------|---------|
| PKT_ANNOUNCE (0x01) | Process announce, update peer table | `announce_process(pkt)` |
| PKT_DATA (0x00) | Check destination, decrypt if for us, deliver via callback | `identity_decrypt()` + callback |
| PKT_PROOF (0x03) | Log receipt (Phase 4 implementation pending) | None (logged only) |
| PKT_LINKREQUEST (0x02) | Ignore (links not implemented) | None |

### Buffer Sizing Rule

**All buffers for incoming data must be sized to maximum INPUT, not maximum output.**

- Radio receive buffer: `uint8_t rx_buf[RNS_MTU]`
- Decrypt output buffer: `uint8_t decrypted[RNS_MTU]`

This ensures that the buffer can hold the maximum possible received data regardless of actual payload size.

### Statistics

The transport layer tracks:
- **TX count:** Number of packets sent via `transport_send()`
- **RX count:** Number of packets received and successfully deserialized

Access via:
- `transport_tx_count()` — returns total packets transmitted
- `transport_rx_count()` — returns total packets received

## Reference

This specification is derived from:
- `RNS/Packet.py` — Reticulum reference implementation
- Cal's source code analysis (Feb 2026)
- TrailDrop Phase 3a implementation and test vectors
- TrailDrop Phase 3d transport layer (Mar 2026)

For questions or clarifications, consult the Python reference implementation source code.
