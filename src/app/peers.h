#pragma once
// Discovered peer tracking from Reticulum announces
// TODO: Phase 5-6 implementation

#include "config.h"
#include <cstdint>

namespace app {

struct Peer {
    uint8_t dest_hash[DEST_HASH_SIZE];
    char display_name[DISPLAY_NAME_MAX];
    uint32_t last_seen;      // Unix timestamp
    int8_t rssi;             // Signal strength at last contact
};

bool peers_init();
bool peer_add_or_update(const Peer& peer);
bool peer_remove(const uint8_t* dest_hash);
int peer_list(Peer* out, int max);
const Peer* peer_find(const uint8_t* dest_hash);

} // namespace app
