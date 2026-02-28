#include "hash.h"
#include <SHA256.h>
#include <string.h>

namespace crypto {

void sha256(const uint8_t* data, size_t len, uint8_t out[32]) {
    SHA256 sha;
    sha.reset();
    sha.update(data, len);
    sha.finalize(out, 32);
}

void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[32]) {
    SHA256 sha;
    sha.resetHMAC(key, key_len);
    sha.update(data, data_len);
    sha.finalizeHMAC(key, key_len, out, 32);
}

} // namespace crypto
