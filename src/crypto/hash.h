#pragma once
// SHA-256, HMAC-SHA256, and HKDF-SHA256 for Reticulum

#include <cstdint>
#include <cstddef>

namespace crypto {

void sha256(const uint8_t* data, size_t len, uint8_t out[32]);
void hmac_sha256(const uint8_t* key, size_t key_len,
                 const uint8_t* data, size_t data_len,
                 uint8_t out[32]);

// HKDF-SHA256: derive output key material from input key material
void hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                 const uint8_t* salt, size_t salt_len,
                 const uint8_t* info, size_t info_len,
                 uint8_t* out, size_t out_len);

} // namespace crypto
