#include "encrypt.h"
#include <AES.h>
#include <string.h>

namespace crypto {

// PKCS7 padding helper
static void pkcs7_pad(uint8_t* data, size_t data_len, size_t block_size) {
    uint8_t pad_val = block_size - (data_len % block_size);
    for (size_t i = 0; i < pad_val; i++) {
        data[data_len + i] = pad_val;
    }
}

// PKCS7 unpadding helper - returns actual data length after removing padding
static size_t pkcs7_unpad(const uint8_t* data, size_t padded_len) {
    if (padded_len == 0) return 0;
    uint8_t pad_val = data[padded_len - 1];
    if (pad_val == 0 || pad_val > 16) return padded_len; // Invalid padding
    // Verify padding
    for (size_t i = 0; i < pad_val; i++) {
        if (data[padded_len - 1 - i] != pad_val) {
            return padded_len; // Invalid padding
        }
    }
    return padded_len - pad_val;
}

// XOR two blocks
static void xor_block(uint8_t* out, const uint8_t* a, const uint8_t* b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

bool aes256_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* plaintext, size_t len,
                        uint8_t* ciphertext, size_t* out_len) {
    // Calculate padded length (PKCS7 padding to 16-byte blocks)
    size_t padded_len = len + (16 - (len % 16));
    
    // Create padded plaintext buffer
    uint8_t* padded = new uint8_t[padded_len];
    memcpy(padded, plaintext, len);
    pkcs7_pad(padded, len, 16);
    
    // Initialize AES256
    AES256 aes;
    aes.setKey(key, 32);
    
    // CBC mode: C[i] = E(P[i] XOR C[i-1]), with C[0] = IV
    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);
    
    for (size_t i = 0; i < padded_len; i += 16) {
        uint8_t temp[16];
        xor_block(temp, padded + i, prev_block, 16);
        aes.encryptBlock(ciphertext + i, temp);
        memcpy(prev_block, ciphertext + i, 16);
    }
    
    delete[] padded;
    aes.clear();
    
    *out_len = padded_len;
    return true;
}

bool aes256_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                        const uint8_t* ciphertext, size_t len,
                        uint8_t* plaintext, size_t* out_len) {
    if (len % 16 != 0) {
        return false; // Ciphertext must be multiple of block size
    }
    
    // Initialize AES256
    AES256 aes;
    aes.setKey(key, 32);
    
    // CBC mode: P[i] = D(C[i]) XOR C[i-1], with C[0] = IV
    uint8_t prev_block[16];
    memcpy(prev_block, iv, 16);
    
    for (size_t i = 0; i < len; i += 16) {
        uint8_t temp[16];
        aes.decryptBlock(temp, ciphertext + i);
        xor_block(plaintext + i, temp, prev_block, 16);
        memcpy(prev_block, ciphertext + i, 16);
    }
    
    aes.clear();
    
    // Remove PKCS7 padding
    *out_len = pkcs7_unpad(plaintext, len);
    return true;
}

} // namespace crypto
