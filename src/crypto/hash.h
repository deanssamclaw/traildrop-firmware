#pragma once
// SHA-256 and HMAC-SHA256 for Reticulum
// TODO: Phase 2 implementation

#include <cstdint>
#include <cstddef>

namespace crypto {

void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[32]);

} // namespace crypto
