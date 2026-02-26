#pragma once
// Reticulum packet framing and parsing
// Reference: RNS/Packet.py
// TODO: Phase 3 implementation

#include "config.h"
#include <cstdint>
#include <cstddef>

namespace net {

// Reticulum packet header flags
enum PacketType : uint8_t {
    DATA    = 0x00,
    ANNOUNCE = 0x01,
    LINKREQUEST = 0x02,
    PROOF   = 0x03,
};

struct Packet {
    uint8_t header_flags;
    uint8_t hops;
    uint8_t dest_hash[DEST_HASH_SIZE];
    uint8_t context;
    uint8_t payload[RNS_MTU];
    size_t payload_len;
};

bool packet_serialize(const Packet& pkt, uint8_t* buf, size_t* len);
bool packet_deserialize(const uint8_t* buf, size_t len, Packet& pkt);

} // namespace net
