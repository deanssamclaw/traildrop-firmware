#include "encrypt.h"

namespace crypto {

bool aes256_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* plaintext, size_t len,
                        uint8_t* ciphertext, size_t* out_len) {
    // TODO: libsodium or mbedtls AES-256-CBC + PKCS7
    return false;
}

bool aes256_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* ciphertext, size_t len,
                        uint8_t* plaintext, size_t* out_len) {
    // TODO: libsodium or mbedtls AES-256-CBC + PKCS7
    return false;
}

} // namespace crypto
