#include "hash.h"

namespace crypto {

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    // TODO: libsodium crypto_hash_sha256
}

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[32]) {
    // TODO: libsodium crypto_auth_hmacsha256
}

} // namespace crypto
