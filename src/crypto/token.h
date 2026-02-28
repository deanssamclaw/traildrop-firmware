#pragma once
// Modified Fernet token — matches RNS/Cryptography/Token.py
// Format: iv(16) + ciphertext + hmac(32)

#include <cstdint>
#include <cstddef>

namespace crypto {

struct Token {
    uint8_t signing_key[32];
    uint8_t encryption_key[32];
};

// Split 64-byte derived key: signing_key = first 32, encryption_key = last 32
void token_init(Token& t, const uint8_t derived_key[64]);

// Encrypt: output is iv(16) + ciphertext + hmac(32). Returns total length via out_len.
bool token_encrypt(const Token& t, const uint8_t* plaintext, size_t len,
                   uint8_t* out, size_t* out_len);

// Decrypt: verifies HMAC first, then decrypts. Returns plaintext length via out_len.
bool token_decrypt(const Token& t, const uint8_t* token_data, size_t token_len,
                   uint8_t* out, size_t* out_len);

} // namespace crypto
