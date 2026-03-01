#pragma once
// Reticulum peer table — discovered nodes from announce packets
// Reference: Python Reticulum announce processing
// Phase 3c: Announce send/receive + peer table

#include <cstdint>
#include <cstddef>
#include "config.h"

namespace net {

struct Peer {
    uint8_t dest_hash[DEST_HASH_SIZE];        // Destination hash (lookup key)
    uint8_t x25519_public[32];                 // For encryption
    uint8_t ed25519_public[32];                // For signature verification
    uint8_t identity_hash[DEST_HASH_SIZE];     // SHA-256(public_keys)[0:16]
    char app_data[DISPLAY_NAME_MAX];           // Display name or other app data
    uint32_t last_announce;                     // millis() timestamp of last announce
    bool valid;                                 // Slot in use
};

// Initialize peer table (clear all slots)
void peer_table_init();

// Store or update a validated peer. Returns true if stored, false if table full.
bool peer_store(const uint8_t dest_hash[DEST_HASH_SIZE],
                const uint8_t x25519_pub[32],
                const uint8_t ed25519_pub[32],
                const uint8_t identity_hash[DEST_HASH_SIZE],
                const char* app_data);

// Look up a peer by destination hash. Returns pointer or nullptr.
const Peer* peer_lookup(const uint8_t dest_hash[DEST_HASH_SIZE]);

// Get count of valid peers
int peer_count();

} // namespace net
