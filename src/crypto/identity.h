#pragma once
// Reticulum identity: X25519 (encryption) + Ed25519 (signing) keypairs

#include "config.h"
#include <cstdint>
#include <cstddef>

namespace crypto {

struct Identity {
    uint8_t x25519_public[IDENTITY_KEY_SIZE];
    uint8_t x25519_private[IDENTITY_KEY_SIZE];
    uint8_t ed25519_public[32];
    uint8_t ed25519_private[32];
    uint8_t hash[16];           // truncated_sha256(x25519_public + ed25519_public)
    bool valid = false;
};

bool identity_generate(Identity& id);
bool identity_load(Identity& id, const char* path);
bool identity_save(const Identity& id, const char* path);

// Key export (Reticulum format: x25519 first, ed25519 second)
void identity_get_public_key(const Identity& id, uint8_t out[64]);
void identity_get_private_key(const Identity& id, uint8_t out[64]);

// Signing
bool identity_sign(const Identity& id, const uint8_t* message, size_t msg_len,
                   uint8_t signature[64]);
bool identity_verify(const uint8_t public_key[32], const uint8_t* message, size_t msg_len,
                     const uint8_t signature[64]);

// Destination hash (Reticulum two-step: name_hash + identity_hash)
// full_name is dot-separated, e.g. "traildrop.waypoint"
void identity_destination_hash(const char* full_name, const Identity& id, uint8_t out[16]);

// Encrypt plaintext for a target identity (full Reticulum flow)
// Output: ephemeral_pub(32) + iv(16) + ciphertext + hmac(32)
bool identity_encrypt(const Identity& target, const uint8_t* plaintext, size_t len,
                      uint8_t* out, size_t* out_len);

// Decrypt ciphertext_token using own private key (full Reticulum flow)
// Input: ephemeral_pub(32) + iv(16) + ciphertext + hmac(32)
bool identity_decrypt(const Identity& self, const uint8_t* ciphertext_token, size_t len,
                      uint8_t* out, size_t* out_len);

} // namespace crypto
