#pragma once
// Reticulum identity: X25519 + Ed25519 keypair
// TODO: Phase 2 implementation

#include "config.h"
#include <cstdint>

namespace crypto {

struct Identity {
    uint8_t x25519_public[IDENTITY_KEY_SIZE];
    uint8_t x25519_private[IDENTITY_KEY_SIZE];
    uint8_t ed25519_public[32];
    uint8_t ed25519_private[64];
    bool valid = false;
};

bool identity_generate(Identity& id);
bool identity_load(Identity& id, const char* path);
bool identity_save(const Identity& id, const char* path);

} // namespace crypto
