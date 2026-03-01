#include "announce.h"
#include "peer.h"
#include "crypto/hash.h"
#include "crypto/identity.h"
#include <Arduino.h>
#include <RNG.h>
#include <cstring>

namespace net {

bool announce_build(const crypto::Identity& id,
                    const Destination& dest,
                    const char* app_data,
                    Packet& out_pkt) {
    // Compute full_name for name_hash
    char full_name[130];  // max: 64 app_name + 1 dot + 64 aspects + 1 null
    snprintf(full_name, sizeof(full_name), "%s.%s", dest.app_name, dest.aspects);
    
    // Compute name_hash = SHA-256(full_name)[0:10]
    uint8_t name_full_hash[32];
    crypto::sha256((const uint8_t*)full_name, strlen(full_name), name_full_hash);
    uint8_t name_hash[10];
    memcpy(name_hash, name_full_hash, 10);
    
    // Generate random_hash (10 bytes)
    uint8_t random_hash[10];
    RNG.rand(random_hash, 10);
    
    // Determine app_data length
    size_t app_data_len = 0;
    if (app_data) {
        app_data_len = strlen(app_data);
        if (app_data_len >= DISPLAY_NAME_MAX) {
            app_data_len = DISPLAY_NAME_MAX - 1;
        }
    }
    
    // Build signed_data: dest_hash(16) + public_key(64) + name_hash(10) + random_hash(10) [+ app_data]
    uint8_t signed_data[16 + 64 + 10 + 10 + DISPLAY_NAME_MAX];
    size_t signed_len = 0;
    
    memcpy(&signed_data[signed_len], dest.hash, 16);
    signed_len += 16;
    
    memcpy(&signed_data[signed_len], id.x25519_public, 32);
    signed_len += 32;
    
    memcpy(&signed_data[signed_len], id.ed25519_public, 32);
    signed_len += 32;
    
    memcpy(&signed_data[signed_len], name_hash, 10);
    signed_len += 10;
    
    memcpy(&signed_data[signed_len], random_hash, 10);
    signed_len += 10;
    
    if (app_data_len > 0) {
        memcpy(&signed_data[signed_len], app_data, app_data_len);
        signed_len += app_data_len;
    }
    
    // Sign with Ed25519
    uint8_t signature[64];
    if (!crypto::identity_sign(id, signed_data, signed_len, signature)) {
        return false;
    }
    
    // Assemble payload: public_key(64) + name_hash(10) + random_hash(10) + signature(64) [+ app_data]
    size_t payload_len = 64 + 10 + 10 + 64 + app_data_len;
    if (payload_len > RNS_MTU) {
        return false;  // Payload too large
    }
    
    size_t offset = 0;
    
    // x25519 public (32 bytes)
    memcpy(&out_pkt.payload[offset], id.x25519_public, 32);
    offset += 32;
    
    // ed25519 public (32 bytes)
    memcpy(&out_pkt.payload[offset], id.ed25519_public, 32);
    offset += 32;
    
    // name_hash (10 bytes)
    memcpy(&out_pkt.payload[offset], name_hash, 10);
    offset += 10;
    
    // random_hash (10 bytes)
    memcpy(&out_pkt.payload[offset], random_hash, 10);
    offset += 10;
    
    // signature (64 bytes)
    memcpy(&out_pkt.payload[offset], signature, 64);
    offset += 64;
    
    // app_data (optional)
    if (app_data_len > 0) {
        memcpy(&out_pkt.payload[offset], app_data, app_data_len);
        offset += app_data_len;
    }
    
    out_pkt.payload_len = offset;
    
    // Set packet flags for announce
    out_pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_ANNOUNCE);
    out_pkt.hops = 0;
    out_pkt.has_transport = false;
    memcpy(out_pkt.dest_hash, dest.hash, DEST_HASH_SIZE);
    out_pkt.context = CTX_NONE;
    
    return true;
}

bool announce_process(const Packet& pkt) {
    // Check packet type
    if (pkt.get_packet_type() != PKT_ANNOUNCE) {
        return false;
    }
    
    // Check minimum payload length
    if (pkt.payload_len < 148) {  // 64 + 10 + 10 + 64
        return false;
    }
    
    // Extract public keys
    const uint8_t* x25519_pub = &pkt.payload[0];
    const uint8_t* ed25519_pub = &pkt.payload[32];
    
    // Compute identity_hash = SHA-256(x25519_public + ed25519_public)[0:16]
    uint8_t pub_concat[64];
    memcpy(pub_concat, x25519_pub, 32);
    memcpy(pub_concat + 32, ed25519_pub, 32);
    uint8_t identity_full_hash[32];
    crypto::sha256(pub_concat, 64, identity_full_hash);
    uint8_t identity_hash[DEST_HASH_SIZE];
    memcpy(identity_hash, identity_full_hash, DEST_HASH_SIZE);
    
    // Extract name_hash
    uint8_t name_hash[10];
    memcpy(name_hash, &pkt.payload[64], 10);
    
    // Compute expected_dest = SHA-256(name_hash + identity_hash)[0:16]
    uint8_t concat[26];  // 10 + 16
    memcpy(concat, name_hash, 10);
    memcpy(concat + 10, identity_hash, 16);
    uint8_t expected_full[32];
    crypto::sha256(concat, 26, expected_full);
    uint8_t expected_dest[DEST_HASH_SIZE];
    memcpy(expected_dest, expected_full, DEST_HASH_SIZE);
    
    // Verify expected_dest == pkt.dest_hash
    if (memcmp(expected_dest, pkt.dest_hash, DEST_HASH_SIZE) != 0) {
        return false;
    }
    
    // Extract random_hash and signature
    uint8_t random_hash[10];
    memcpy(random_hash, &pkt.payload[74], 10);
    
    const uint8_t* signature = &pkt.payload[84];
    
    // Extract app_data if present
    size_t app_data_len = 0;
    if (pkt.payload_len > 148) {
        app_data_len = pkt.payload_len - 148;
    }
    
    // Build signed_data for verification
    // Buffer sized to max INPUT (not output) — signature covers full app_data before truncation
    // Max app_data from wire: RNS_MAX_PAYLOAD_H1 - 148 = 333 bytes
    uint8_t signed_data[16 + 64 + 10 + 10 + (RNS_MAX_PAYLOAD_H1 - 148)];
    size_t signed_len = 0;
    
    memcpy(&signed_data[signed_len], pkt.dest_hash, 16);
    signed_len += 16;
    
    memcpy(&signed_data[signed_len], &pkt.payload[0], 64);  // public_key
    signed_len += 64;
    
    memcpy(&signed_data[signed_len], &pkt.payload[64], 10);  // name_hash
    signed_len += 10;
    
    memcpy(&signed_data[signed_len], &pkt.payload[74], 10);  // random_hash
    signed_len += 10;
    
    if (app_data_len > 0) {
        memcpy(&signed_data[signed_len], &pkt.payload[148], app_data_len);
        signed_len += app_data_len;
    }
    
    // Verify Ed25519 signature
    if (!crypto::identity_verify(ed25519_pub, signed_data, signed_len, signature)) {
        return false;
    }
    
    // Extract and truncate app_data safely
    char app_data_str[DISPLAY_NAME_MAX] = {0};
    if (app_data_len > 0) {
        size_t copy_len = app_data_len;
        if (copy_len >= DISPLAY_NAME_MAX) {
            copy_len = DISPLAY_NAME_MAX - 1;
        }
        memcpy(app_data_str, &pkt.payload[148], copy_len);
        app_data_str[copy_len] = '\0';
    }
    
    // Store peer
    return peer_store(pkt.dest_hash, x25519_pub, ed25519_pub, identity_hash, app_data_str);
}

} // namespace net
