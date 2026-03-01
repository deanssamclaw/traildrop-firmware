#pragma once
// LXMF message build/parse — bit-exact with Python LXMF
// Wire format: dest_hash(16) + source_hash(16) + signature(64) + msgpack(payload)
// Payload: [timestamp, title_bin, content_bin, fields_map]

#include <cstdint>
#include <cstddef>
#include "crypto/identity.h"

namespace msg {

static const size_t LXMF_MAX_TITLE = 64;
static const size_t LXMF_MAX_CONTENT = 280;
static const size_t LXMF_SIGNATURE_LEN = 64;
static const size_t LXMF_HASH_LEN = 32;
static const uint8_t FIELD_CUSTOM_TYPE = 0xFB;
static const uint8_t FIELD_CUSTOM_DATA = 0xFC;

struct LXMessage {
    uint8_t dest_hash[16];
    uint8_t source_hash[16];
    uint8_t signature[64];
    uint8_t message_hash[32];
    double timestamp;

    uint8_t title[LXMF_MAX_TITLE];
    size_t title_len;
    uint8_t content[LXMF_MAX_CONTENT];
    size_t content_len;

    uint8_t custom_type[32];
    size_t custom_type_len;
    uint8_t custom_data[256];
    size_t custom_data_len;

    bool has_custom_fields;
    bool signature_valid;

    // Raw 4-element packed payload bytes (after stamp stripping if needed)
    uint8_t packed_payload[512];
    size_t packed_payload_len;
};

// Build an LXMF message for opportunistic delivery.
// Output: source_hash(16) + signature(64) + packed_payload
// The dest_hash is NOT included (inferred from RNS packet destination).
bool lxmf_build(
    const crypto::Identity& source_identity,
    const uint8_t source_dest_hash[16],
    const uint8_t dest_hash[16],
    double timestamp,
    const uint8_t* title, size_t title_len,
    const uint8_t* content, size_t content_len,
    const uint8_t* custom_type, size_t custom_type_len,
    const uint8_t* custom_data, size_t custom_data_len,
    uint8_t* out, size_t* out_len,
    uint8_t message_hash[32]
);

// Parse a received LXMF message.
// Input: dest_hash(16) + source_hash(16) + signature(64) + packed_payload
bool lxmf_parse(
    const uint8_t* lxmf_data, size_t lxmf_len,
    LXMessage& msg
);

// Verify signature on a parsed message.
bool lxmf_verify(
    const LXMessage& msg,
    const uint8_t source_ed25519_public[32]
);

} // namespace msg
