#include "identity.h"
#include "hash.h"
#include "token.h"
#include "hal/storage.h"
#include <Curve25519.h>
#include <Ed25519.h>
#include <RNG.h>
#include <string.h>

namespace crypto {

// Compute identity hash: truncated_sha256(x25519_pub + ed25519_pub)
// Key order is CRITICAL — X25519 first, Ed25519 second (matches Reticulum)
static void compute_identity_hash(Identity& id) {
    uint8_t pub_concat[64];
    memcpy(pub_concat, id.x25519_public, 32);       // encryption key FIRST
    memcpy(pub_concat + 32, id.ed25519_public, 32);  // signing key SECOND
    uint8_t full_hash[32];
    sha256(pub_concat, 64, full_hash);
    memcpy(id.hash, full_hash, 16);  // Truncate to first 16 bytes
}

bool identity_generate(Identity& id) {
    // Generate X25519 keypair (Curve25519 for ECDH)
    Curve25519::dh1(id.x25519_public, id.x25519_private);

    // Generate Ed25519 keypair (for signing)
    Ed25519::generatePrivateKey(id.ed25519_private);
    Ed25519::derivePublicKey(id.ed25519_public, id.ed25519_private);

    compute_identity_hash(id);
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

    memcpy(id.x25519_private, buf, 32);
    memcpy(id.x25519_public, buf + 32, 32);
    memcpy(id.ed25519_private, buf + 64, 32);
    memcpy(id.ed25519_public, buf + 96, 32);

    compute_identity_hash(id);
    id.valid = true;
    return true;
}

bool identity_save(const Identity& id, const char* path) {
    if (!id.valid) {
        return false;
    }

    uint8_t buf[128];
    memcpy(buf, id.x25519_private, 32);
    memcpy(buf + 32, id.x25519_public, 32);
    memcpy(buf + 64, id.ed25519_private, 32);
    memcpy(buf + 96, id.ed25519_public, 32);

    return hal::storage_write_file(path, buf, sizeof(buf));
}

void identity_get_public_key(const Identity& id, uint8_t out[64]) {
    memcpy(out, id.x25519_public, 32);
    memcpy(out + 32, id.ed25519_public, 32);
}

void identity_get_private_key(const Identity& id, uint8_t out[64]) {
    memcpy(out, id.x25519_private, 32);
    memcpy(out + 32, id.ed25519_private, 32);
}

bool identity_sign(const Identity& id, const uint8_t* message, size_t msg_len,
                   uint8_t signature[64]) {
    if (!id.valid) {
        return false;
    }
    Ed25519::sign(signature, id.ed25519_private, id.ed25519_public, message, msg_len);
    return true;
}

bool identity_verify(const uint8_t public_key[32], const uint8_t* message, size_t msg_len,
                     const uint8_t signature[64]) {
    return Ed25519::verify(signature, public_key, message, msg_len);
}

void identity_destination_hash(const char* full_name, const Identity& id, uint8_t out[16]) {
    // Step 1: name_hash = sha256(full_name)[0:10]
    uint8_t name_full_hash[32];
    sha256((const uint8_t*)full_name, strlen(full_name), name_full_hash);

    // Step 2: concatenate name_hash(10) + identity.hash(16) = 26 bytes
    uint8_t concat[NAME_HASH_LENGTH + DEST_HASH_SIZE];
    memcpy(concat, name_full_hash, NAME_HASH_LENGTH);
    memcpy(concat + NAME_HASH_LENGTH, id.hash, DEST_HASH_SIZE);

    // Step 3: dest_hash = sha256(concat)[0:16]
    uint8_t dest_full_hash[32];
    sha256(concat, sizeof(concat), dest_full_hash);
    memcpy(out, dest_full_hash, DEST_HASH_SIZE);
}

bool identity_encrypt(const Identity& target, const uint8_t* plaintext, size_t len,
                      uint8_t* out, size_t* out_len) {
    // 1. Generate ephemeral X25519 keypair
    uint8_t eph_pub[32], eph_prv[32];
    Curve25519::dh1(eph_pub, eph_prv);

    // 2. ECDH: shared_key = eph_prv * target.x25519_public
    uint8_t shared_key[32];
    if (!Curve25519::eval(shared_key, eph_prv, target.x25519_public)) {
        return false;
    }

    // 3. HKDF-SHA256(shared_key, salt=target.hash, len=64, info=None)
    uint8_t derived[DERIVED_KEY_LENGTH];
    hkdf_sha256(shared_key, 32, target.hash, DEST_HASH_SIZE,
                nullptr, 0, derived, DERIVED_KEY_LENGTH);

    // 4. Token encrypt
    Token token;
    token_init(token, derived);

    // 5. Write ephemeral public key to output
    memcpy(out, eph_pub, 32);

    // 6. Token encrypt (iv + ciphertext + hmac) after ephemeral pub
    size_t token_len = 0;
    if (!token_encrypt(token, plaintext, len, out + 32, &token_len)) {
        return false;
    }

    *out_len = 32 + token_len;
    return true;
}

bool identity_decrypt(const Identity& self, const uint8_t* ciphertext_token, size_t len,
                      uint8_t* out, size_t* out_len) {
    // Minimum: ephemeral_pub(32) + iv(16) + one_block(16) + hmac(32) = 96
    if (len < 96 || !self.valid) {
        return false;
    }

    // 1. Extract ephemeral public key
    const uint8_t* eph_pub = ciphertext_token;

    // 2. ECDH: shared_key = self.x25519_private * eph_pub
    uint8_t shared_key[32];
    if (!Curve25519::eval(shared_key, self.x25519_private, eph_pub)) {
        return false;
    }

    // 3. HKDF-SHA256(shared_key, salt=self.hash, len=64, info=None)
    uint8_t derived[DERIVED_KEY_LENGTH];
    hkdf_sha256(shared_key, 32, self.hash, DEST_HASH_SIZE,
                nullptr, 0, derived, DERIVED_KEY_LENGTH);

    // 4. Token decrypt
    Token token;
    token_init(token, derived);

    return token_decrypt(token, ciphertext_token + 32, len - 32, out, out_len);
}

} // namespace crypto
