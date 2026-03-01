#include "packet.h"
#include "crypto/hash.h"
#include <cstring>

namespace net {

int packet_serialize(const Packet& pkt, uint8_t* out_buf, size_t out_max) {
    // Determine header size based on has_transport flag
    size_t header_size = pkt.has_transport ? RNS_HEADER2_SIZE : RNS_HEADER1_SIZE;
    size_t max_payload = pkt.has_transport ? RNS_MAX_PAYLOAD_H2 : RNS_MAX_PAYLOAD_H1;
    
    // Check payload size
    if (pkt.payload_len > max_payload) {
        return -1;  // Payload too large for header type
    }
    
    size_t total_size = header_size + pkt.payload_len;
    
    // Check output buffer size
    if (total_size > out_max) {
        return -1;
    }
    
    size_t offset = 0;
    
    // Write flags
    out_buf[offset++] = pkt.flags;
    
    // Write hops
    out_buf[offset++] = pkt.hops;
    
    if (pkt.has_transport) {
        // HEADER_2: write transport_id (16 bytes)
        memcpy(out_buf + offset, pkt.transport_id, DEST_HASH_SIZE);
        offset += DEST_HASH_SIZE;
    }
    
    // Write destination_hash (16 bytes)
    memcpy(out_buf + offset, pkt.dest_hash, DEST_HASH_SIZE);
    offset += DEST_HASH_SIZE;
    
    // Write context
    out_buf[offset++] = pkt.context;
    
    // Write payload
    if (pkt.payload_len > 0) {
        memcpy(out_buf + offset, pkt.payload, pkt.payload_len);
        offset += pkt.payload_len;
    }
    
    return (int)offset;
}

bool packet_deserialize(const uint8_t* raw, size_t raw_len, Packet& pkt) {
    // Need at least flags byte to determine header type
    if (raw_len < 1) {
        return false;
    }
    
    // Read flags to determine header type
    uint8_t flags = raw[0];
    bool is_header2 = (flags >> 6) & 0x01;
    
    // Check minimum size based on header type
    size_t min_size = is_header2 ? RNS_HEADER2_SIZE : RNS_HEADER1_SIZE;
    if (raw_len < min_size) {
        return false;
    }
    
    size_t offset = 0;
    
    // Read flags
    pkt.flags = raw[offset++];
    
    // Read hops
    pkt.hops = raw[offset++];
    
    pkt.has_transport = is_header2;
    
    if (is_header2) {
        // HEADER_2: read transport_id (16 bytes)
        memcpy(pkt.transport_id, raw + offset, DEST_HASH_SIZE);
        offset += DEST_HASH_SIZE;
    } else {
        // HEADER_1: clear transport_id
        memset(pkt.transport_id, 0, DEST_HASH_SIZE);
    }
    
    // Read destination_hash (16 bytes)
    memcpy(pkt.dest_hash, raw + offset, DEST_HASH_SIZE);
    offset += DEST_HASH_SIZE;
    
    // Read context
    pkt.context = raw[offset++];
    
    // Read payload (remaining bytes)
    pkt.payload_len = raw_len - offset;
    if (pkt.payload_len > 0) {
        memcpy(pkt.payload, raw + offset, pkt.payload_len);
    }
    
    return true;
}

void packet_hash(const uint8_t* raw, size_t raw_len, bool is_header2,
                 uint8_t out_hash[32], uint8_t out_truncated[16]) {
    // Build hashable_part: (flags & 0x0F) || raw[skip_offset:]
    // For HEADER_1: skip hops (1 byte), include dest_hash + context + payload
    // For HEADER_2: skip hops + transport_id (1 + 16 = 17 bytes), include dest_hash + context + payload
    
    size_t skip_offset = is_header2 ? 18 : 2;  // HEADER_2: skip 1+1+16=18, HEADER_1: skip 1+1=2
    size_t hashable_len = 1 + (raw_len - skip_offset);  // 1 byte for masked flags + remaining
    
    // Allocate buffer for hashable part
    uint8_t hashable_part[RNS_MTU];
    
    // First byte: flags & 0x0F (keep only dest_type + pkt_type, strip transport metadata)
    hashable_part[0] = raw[0] & 0x0F;
    
    // Copy rest: destination_hash + context + payload
    memcpy(hashable_part + 1, raw + skip_offset, raw_len - skip_offset);
    
    // Compute SHA-256 of hashable_part
    crypto::sha256(hashable_part, hashable_len, out_hash);
    
    // Copy first 16 bytes to truncated hash
    memcpy(out_truncated, out_hash, 16);
}

} // namespace net
