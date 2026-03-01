#pragma once
#include <cstdint>
#include <cstddef>
#include "config.h"  // Gets RNS_MTU, DEST_HASH_SIZE, etc.

// Packet type
enum PacketType : uint8_t {
    PKT_DATA         = 0x00,
    PKT_ANNOUNCE     = 0x01,
    PKT_LINKREQUEST  = 0x02,
    PKT_PROOF        = 0x03,
};

// Destination type
enum DestinationType : uint8_t {
    DEST_SINGLE = 0x00,
    DEST_GROUP  = 0x01,
    DEST_PLAIN  = 0x02,
    DEST_LINK   = 0x03,
};

// Header type
enum HeaderType : uint8_t {
    HEADER_1 = 0x00,  // No transport
    HEADER_2 = 0x01,  // With transport_id
};

// Transport type
enum TransportType : uint8_t {
    TRANSPORT_BROADCAST = 0x00,
    TRANSPORT_TRANSPORT = 0x01,
};

// Context byte constants
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

struct Packet {
    uint8_t flags;
    uint8_t hops;
    uint8_t transport_id[DEST_HASH_SIZE];  // Only valid when has_transport==true
    uint8_t dest_hash[DEST_HASH_SIZE];
    uint8_t context;
    uint8_t payload[RNS_MTU];              // Buffer; actual data size = payload_len
    size_t payload_len;                     // Number of valid bytes in payload[]
    bool has_transport;                     // True if HEADER_2

    // Flag accessors — return enum types for type safety
    HeaderType      get_header_type()      const { return (HeaderType)((flags >> 6) & 0x01); }
    bool            get_context_flag()     const { return (flags >> 5) & 0x01; }
    TransportType   get_transport_type()   const { return (TransportType)((flags >> 4) & 0x01); }
    DestinationType get_destination_type() const { return (DestinationType)((flags >> 2) & 0x03); }
    PacketType      get_packet_type()      const { return (PacketType)(flags & 0x03); }

    // Flag setter — constructs the full flags byte from components
    void set_flags(HeaderType ht, bool ctx_flag, TransportType tt,
                   DestinationType dt, PacketType pt) {
        flags = ((uint8_t)ht << 6) | ((uint8_t)ctx_flag << 5) |
                ((uint8_t)tt << 4) | ((uint8_t)dt << 2) | (uint8_t)pt;
    }
};

namespace net {

// Serialize a Packet struct into raw bytes for radio transmission.
// out_buf must be at least RNS_MTU (500) bytes.
// Returns bytes written (19-500 for H1, 35-500 for H2), or -1 on error
// (e.g., payload too large for header type).
int packet_serialize(const Packet& pkt, uint8_t* out_buf, size_t out_max);

// Deserialize raw bytes (received from radio) into a Packet struct.
// raw_len = total number of received bytes.
// Returns true on success. Returns false if raw_len < minimum header size
// (19 for HEADER_1, 35 for HEADER_2). Zero-length payload is valid.
bool packet_deserialize(const uint8_t* raw, size_t raw_len, Packet& pkt);

// Compute packet hash over the hashable part (strips transport metadata).
// raw/raw_len = the full serialized packet bytes from packet_serialize.
// is_header2 = whether the packet uses HEADER_2 format.
// out_hash = full 32-byte SHA-256, out_truncated = first 16 bytes.
void packet_hash(const uint8_t* raw, size_t raw_len, bool is_header2,
                 uint8_t out_hash[32], uint8_t out_truncated[16]);

} // namespace net
