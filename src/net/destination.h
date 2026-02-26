#pragma once
// Reticulum destination addressing
// Hash = truncated SHA-256 of (identity + app_name + aspects)
// Reference: RNS/Destination.py
// TODO: Phase 3 implementation

#include "config.h"
#include "crypto/identity.h"
#include <cstdint>

namespace net {

struct Destination {
    uint8_t hash[DEST_HASH_SIZE];
    char app_name[64];
    char aspects[64];
};

bool destination_derive(const crypto::Identity& id,
                        const char* app_name,
                        const char* aspects,
                        Destination& dest);

} // namespace net
