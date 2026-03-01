#include "peer.h"
#include <Arduino.h>
#include <cstring>

namespace net {

// Fixed peer table (50 entries as per config.h)
static Peer peer_table[MAX_PEERS];

void peer_table_init() {
    for (int i = 0; i < MAX_PEERS; i++) {
        peer_table[i].valid = false;
    }
}

bool peer_store(const uint8_t dest_hash[DEST_HASH_SIZE],
                const uint8_t x25519_pub[32],
                const uint8_t ed25519_pub[32],
                const uint8_t identity_hash[DEST_HASH_SIZE],
                const char* app_data) {
    // First pass: check if peer already exists (update case)
    for (int i = 0; i < MAX_PEERS; i++) {
        if (peer_table[i].valid && 
            memcmp(peer_table[i].dest_hash, dest_hash, DEST_HASH_SIZE) == 0) {
            // Found existing peer — update it
            memcpy(peer_table[i].x25519_public, x25519_pub, 32);
            memcpy(peer_table[i].ed25519_public, ed25519_pub, 32);
            memcpy(peer_table[i].identity_hash, identity_hash, DEST_HASH_SIZE);
            
            // Update app_data
            if (app_data) {
                strncpy(peer_table[i].app_data, app_data, DISPLAY_NAME_MAX - 1);
                peer_table[i].app_data[DISPLAY_NAME_MAX - 1] = '\0';
            } else {
                peer_table[i].app_data[0] = '\0';
            }
            
            peer_table[i].last_announce = millis();
            return true;
        }
    }
    
    // Second pass: find first invalid slot (new peer)
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!peer_table[i].valid) {
            memcpy(peer_table[i].dest_hash, dest_hash, DEST_HASH_SIZE);
            memcpy(peer_table[i].x25519_public, x25519_pub, 32);
            memcpy(peer_table[i].ed25519_public, ed25519_pub, 32);
            memcpy(peer_table[i].identity_hash, identity_hash, DEST_HASH_SIZE);
            
            if (app_data) {
                strncpy(peer_table[i].app_data, app_data, DISPLAY_NAME_MAX - 1);
                peer_table[i].app_data[DISPLAY_NAME_MAX - 1] = '\0';
            } else {
                peer_table[i].app_data[0] = '\0';
            }
            
            peer_table[i].last_announce = millis();
            peer_table[i].valid = true;
            return true;
        }
    }
    
    // Table is full
    return false;
}

const Peer* peer_lookup(const uint8_t dest_hash[DEST_HASH_SIZE]) {
    for (int i = 0; i < MAX_PEERS; i++) {
        if (peer_table[i].valid && 
            memcmp(peer_table[i].dest_hash, dest_hash, DEST_HASH_SIZE) == 0) {
            return &peer_table[i];
        }
    }
    return nullptr;
}

int peer_count() {
    int count = 0;
    for (int i = 0; i < MAX_PEERS; i++) {
        if (peer_table[i].valid) {
            count++;
        }
    }
    return count;
}

} // namespace net
