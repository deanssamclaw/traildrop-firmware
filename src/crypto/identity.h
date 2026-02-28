#pragma once
// Reticulum identity: X25519 + Ed25519 keypair
// TODO: Phase 2 implementation

#include "config.h"
#include <cstdint>
#include <cstddef>

namespace crypto {

struct Identity {
    uint8_t x25519_public[IDENTITY_KEY_SIZE];
    uint8_t x25519_private[IDENTITY_KEY_SIZE];
    uint8_t ed25519_public[32];
    uint8_t ed25519_private[32];  // Ed25519 private key is 32 bytes in rweather/Crypto
    bool valid = false;
};

bool identity_generate(Identity& id);
bool identity_load(Identity& id, const char* path);
bool identity_save(const Identity& id, const char* path);

// Reticulum-specific crypto operations
bool identity_derive_shared_key(const uint8_t their_public[32],
                                 const uint8_t our_private[32],
                                 uint8_t shared_key[32]);
bool identity_sign(const Identity& id, const uint8_t* message, size_t msg_len,
                   uint8_t signature[64]);
bool identity_verify(const uint8_t public_key[32], const uint8_t* message, size_t msg_len,
                     const uint8_t signature[64]);
void identity_destination_hash(const Identity& id, const char* app_name,
                               const char* aspects, uint8_t hash[16]);

} // namespace crypto
