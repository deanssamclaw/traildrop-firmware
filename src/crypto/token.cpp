#include "token.h"
#include "encrypt.h"
#include "hash.h"
#include <RNG.h>
#include <string.h>

namespace crypto {

void token_init(Token& t, const uint8_t derived_key[64]) {
    memcpy(t.signing_key, derived_key, 32);
    memcpy(t.encryption_key, derived_key + 32, 32);
}

bool token_encrypt(const Token& t, const uint8_t* plaintext, size_t len,
                   uint8_t* out, size_t* out_len) {
    // Generate random IV
    uint8_t iv[16];
    RNG.rand(iv, 16);

    // Copy IV to output
    memcpy(out, iv, 16);

    // Encrypt: AES-256-CBC with PKCS7 padding
    size_t cipher_len = 0;
    if (!aes256_cbc_encrypt(t.encryption_key, iv, plaintext, len,
                            out + 16, &cipher_len)) {
        return false;
    }

    // Compute HMAC-SHA256 over iv + ciphertext
    size_t hmac_offset = 16 + cipher_len;
    hmac_sha256(t.signing_key, 32, out, hmac_offset, out + hmac_offset);

    *out_len = hmac_offset + 32;
    return true;
}

bool token_decrypt(const Token& t, const uint8_t* token_data, size_t token_len,
                   uint8_t* out, size_t* out_len) {
    // Minimum size: IV(16) + one AES block(16) + HMAC(32) = 64
    if (token_len < 64) {
        return false;
    }

    // Verify HMAC-SHA256 over iv + ciphertext (everything except last 32 bytes)
    uint8_t computed_hmac[32];
    hmac_sha256(t.signing_key, 32, token_data, token_len - 32, computed_hmac);

    // Constant-time comparison
    const uint8_t* received_hmac = token_data + token_len - 32;
    uint8_t diff = 0;
    for (size_t i = 0; i < 32; i++) {
        diff |= computed_hmac[i] ^ received_hmac[i];
    }
    if (diff != 0) {
        return false;
    }

    // Decrypt
    const uint8_t* iv = token_data;
    const uint8_t* ciphertext = token_data + 16;
    size_t cipher_len = token_len - 16 - 32;

    return aes256_cbc_decrypt(t.encryption_key, iv, ciphertext, cipher_len,
                              out, out_len);
}

} // namespace crypto
