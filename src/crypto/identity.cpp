#include "identity.h"
#include "hash.h"
#include "hal/storage.h"
#include <Curve25519.h>
#include <Ed25519.h>
#include <RNG.h>
#include <SHA256.h>
#include <string.h>

namespace crypto {

bool identity_generate(Identity& id) {
    // Generate X25519 keypair (Curve25519 for ECDH)
    // dh1 generates: k (private key in x25519_private) and f (public key in x25519_public)
    Curve25519::dh1(id.x25519_public, id.x25519_private);

    // Generate Ed25519 keypair (for signing)
    Ed25519::generatePrivateKey(id.ed25519_private);
    Ed25519::derivePublicKey(id.ed25519_public, id.ed25519_private);

    id.valid = true;
    return true;
}

bool identity_load(Identity& id, const char* path) {
    // Identity file format: x25519_priv(32) + x25519_pub(32) + ed25519_priv(32) + ed25519_pub(32) = 128 bytes
    uint8_t buf[128];
    
    int bytes_read = hal::storage_read_file(path, buf, sizeof(buf));
    if (bytes_read != sizeof(buf)) {
        id.valid = false;
        return false;
    }

    // Parse the identity file
    memcpy(id.x25519_private, buf, 32);
    memcpy(id.x25519_public, buf + 32, 32);
    memcpy(id.ed25519_private, buf + 64, 32);
    memcpy(id.ed25519_public, buf + 96, 32);
    
    id.valid = true;
    return true;
}

bool identity_save(const Identity& id, const char* path) {
    if (!id.valid) {
        return false;
    }

    // Pack identity into buffer: x25519_priv(32) + x25519_pub(32) + ed25519_priv(32) + ed25519_pub(32) = 128 bytes
    uint8_t buf[128];
    memcpy(buf, id.x25519_private, 32);
    memcpy(buf + 32, id.x25519_public, 32);
    memcpy(buf + 64, id.ed25519_private, 32);
    memcpy(buf + 96, id.ed25519_public, 32);

    return hal::storage_write_file(path, buf, sizeof(buf));
}

// Additional Reticulum-specific functions

// ECDH shared secret derivation (X25519)
bool identity_derive_shared_key(const uint8_t their_public[32],
                                 const uint8_t our_private[32],
                                 uint8_t shared_key[32]) {
    // Use Curve25519::eval to compute shared secret: shared = our_private * their_public
    return Curve25519::eval(shared_key, our_private, their_public);
}

// Ed25519 sign
bool identity_sign(const Identity& id, const uint8_t* message, size_t msg_len,
                   uint8_t signature[64]) {
    if (!id.valid) {
        return false;
    }
    Ed25519::sign(signature, id.ed25519_private, id.ed25519_public, message, msg_len);
    return true;
}

// Ed25519 verify
bool identity_verify(const uint8_t public_key[32], const uint8_t* message, size_t msg_len,
                     const uint8_t signature[64]) {
    return Ed25519::verify(signature, public_key, message, msg_len);
}

// Destination hash derivation (truncated SHA-256 of identity + aspects)
void identity_destination_hash(const Identity& id, const char* app_name,
                               const char* aspects, uint8_t hash[16]) {
    // Reticulum destination hash = truncated SHA-256(ed25519_pub + x25519_pub + app_name + aspects)
    SHA256 sha;
    sha.reset();
    
    sha.update(id.ed25519_public, 32);
    sha.update(id.x25519_public, 32);
    sha.update((const uint8_t*)app_name, strlen(app_name));
    if (aspects) {
        sha.update((const uint8_t*)aspects, strlen(aspects));
    }
    
    uint8_t full_hash[32];
    sha.finalize(full_hash, 32);
    
    // Truncate to 16 bytes (128 bits)
    memcpy(hash, full_hash, 16);
}

} // namespace crypto
