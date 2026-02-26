#pragma once
// AES-256-CBC encryption for Reticulum packets
// TODO: Phase 2 implementation

#include <cstdint>
#include <cstddef>

namespace crypto {

bool aes256_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* plaintext, size_t len,
                        uint8_t* ciphertext, size_t* out_len);

bool aes256_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* ciphertext, size_t len,
                        uint8_t* plaintext, size_t* out_len);

} // namespace crypto
