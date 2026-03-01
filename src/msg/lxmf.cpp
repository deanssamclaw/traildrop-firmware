#include "lxmf.h"
#include "msgpack.h"
#include "crypto/hash.h"
#include "crypto/identity.h"
#include <cstring>

namespace msg {

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
)
{
    // Step 1: Pack payload array [timestamp, title, content, fields]
    uint8_t packed_payload[512];
    Encoder enc(packed_payload, sizeof(packed_payload));

    enc.write_array(4);
    enc.write_float64(timestamp);
    enc.write_bin(title, title_len);
    enc.write_bin(content, content_len);

    if (custom_type && custom_type_len > 0) {
        enc.write_map(2);
        enc.write_uint(FIELD_CUSTOM_TYPE);
        enc.write_bin(custom_type, custom_type_len);
        enc.write_uint(FIELD_CUSTOM_DATA);
        enc.write_bin(custom_data, custom_data_len);
    } else {
        enc.write_map(0);
    }

    if (enc.error) return false;
    size_t payload_len = enc.pos;

    // Step 2: Compute message hash
    // hashed_part = dest_hash(16) + source_hash(16) + packed_payload
    uint8_t hashed_part[544];
    memcpy(hashed_part, dest_hash, 16);
    memcpy(hashed_part + 16, source_dest_hash, 16);
    memcpy(hashed_part + 32, packed_payload, payload_len);
    size_t hashed_part_len = 32 + payload_len;

    crypto::sha256(hashed_part, hashed_part_len, message_hash);

    // Step 3: Compute signature
    // signed_part = hashed_part + message_hash
    uint8_t signed_part[576];
    memcpy(signed_part, hashed_part, hashed_part_len);
    memcpy(signed_part + hashed_part_len, message_hash, 32);
    size_t signed_part_len = hashed_part_len + 32;

    uint8_t signature[64];
    if (!crypto::identity_sign(source_identity, signed_part, signed_part_len, signature)) {
        return false;
    }

    // Step 4: Assemble output for opportunistic delivery
    // source_hash(16) + signature(64) + packed_payload
    size_t total = 16 + 64 + payload_len;
    *out_len = total;

    memcpy(out, source_dest_hash, 16);
    memcpy(out + 16, signature, 64);
    memcpy(out + 80, packed_payload, payload_len);

    return true;
}

bool lxmf_parse(
    const uint8_t* lxmf_data, size_t lxmf_len,
    LXMessage& msg
)
{
    // Minimum: dest_hash(16) + source_hash(16) + signature(64) + 1 byte payload
    if (lxmf_len < 97) return false;

    // Step 1: Extract fixed-length header fields
    memcpy(msg.dest_hash, lxmf_data, 16);
    memcpy(msg.source_hash, lxmf_data + 16, 16);
    memcpy(msg.signature, lxmf_data + 32, 64);

    const uint8_t* raw_payload = lxmf_data + 96;
    size_t raw_payload_len = lxmf_len - 96;

    // Step 2: Check array element count and handle stamp stripping
    Decoder check(raw_payload, raw_payload_len);
    uint8_t array_count = check.read_array();
    if (check.error || array_count < 4) return false;

    if (array_count >= 5) {
        // Stamped message: skip first 4 elements to find truncation point
        Decoder skip_dec(raw_payload + 1, raw_payload_len - 1);
        skip_dec.skip();  // [0] timestamp
        skip_dec.skip();  // [1] title
        skip_dec.skip();  // [2] content
        skip_dec.skip();  // [3] fields
        if (skip_dec.error) return false;

        // Re-pack as 4-element array: change header byte, keep element bytes
        msg.packed_payload[0] = 0x94;  // fixarray(4)
        memcpy(msg.packed_payload + 1, raw_payload + 1, skip_dec.pos);
        msg.packed_payload_len = 1 + skip_dec.pos;
    } else {
        // 4-element payload — use as-is
        memcpy(msg.packed_payload, raw_payload, raw_payload_len);
        msg.packed_payload_len = raw_payload_len;
    }

    // Step 3: Decode payload elements (skip array header byte)
    Decoder dec(msg.packed_payload + 1, msg.packed_payload_len - 1);

    msg.timestamp = dec.read_float64();
    if (dec.error) return false;

    msg.title_len = dec.read_bin(msg.title, sizeof(msg.title));
    if (dec.error) return false;

    msg.content_len = dec.read_bin(msg.content, sizeof(msg.content));
    if (dec.error) return false;

    // Read fields map
    uint8_t map_count = dec.read_map();
    if (dec.error) return false;

    msg.has_custom_fields = false;
    msg.custom_type_len = 0;
    msg.custom_data_len = 0;

    for (uint8_t i = 0; i < map_count; i++) {
        uint32_t key = dec.read_uint();
        if (dec.error) return false;

        if (key == FIELD_CUSTOM_TYPE) {
            msg.custom_type_len = dec.read_bin(msg.custom_type, sizeof(msg.custom_type));
            msg.has_custom_fields = true;
        } else if (key == FIELD_CUSTOM_DATA) {
            msg.custom_data_len = dec.read_bin(msg.custom_data, sizeof(msg.custom_data));
            msg.has_custom_fields = true;
        } else {
            dec.skip();  // unknown field
        }
        if (dec.error) return false;
    }

    // Step 4: Compute message hash
    // hashed_part = dest_hash + source_hash + packed_payload (4-element)
    uint8_t hashed_part[544];
    memcpy(hashed_part, msg.dest_hash, 16);
    memcpy(hashed_part + 16, msg.source_hash, 16);
    memcpy(hashed_part + 32, msg.packed_payload, msg.packed_payload_len);
    size_t hashed_part_len = 32 + msg.packed_payload_len;

    crypto::sha256(hashed_part, hashed_part_len, msg.message_hash);

    msg.signature_valid = false;
    return true;
}

bool lxmf_verify(
    const LXMessage& msg,
    const uint8_t source_ed25519_public[32]
)
{
    // signed_part = dest_hash + source_hash + packed_payload + message_hash
    uint8_t signed_part[576];
    size_t pos = 0;

    memcpy(signed_part, msg.dest_hash, 16);
    pos += 16;
    memcpy(signed_part + pos, msg.source_hash, 16);
    pos += 16;
    memcpy(signed_part + pos, msg.packed_payload, msg.packed_payload_len);
    pos += msg.packed_payload_len;
    memcpy(signed_part + pos, msg.message_hash, 32);
    pos += 32;

    return crypto::identity_verify(
        source_ed25519_public,
        signed_part, pos,
        msg.signature
    );
}

} // namespace msg
