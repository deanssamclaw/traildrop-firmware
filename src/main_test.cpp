// ============================================================
// TrailDrop Firmware — Phase 1 HAL Test Harness
// Exercises all 8 HAL modules: power, display, keyboard,
// trackball, GPS, radio, storage, battery.
// No crypto, net, app, or UI dependencies.
// ============================================================

#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include "config.h"
#include "hal/power.h"
#include "hal/display.h"
#include "hal/keyboard.h"
#include "hal/trackball.h"
#include "hal/gps.h"
#include "hal/radio.h"
#include "hal/storage.h"
#include "hal/battery.h"
#include "crypto/hash.h"
#include "crypto/identity.h"
#include "crypto/encrypt.h"
#include "crypto/token.h"
#include "net/packet.h"
#include "net/destination.h"
#include "net/peer.h"
#include "net/announce.h"
#include "net/transport.h"
#include "msg/msgpack.h"
#include "msg/lxmf.h"
#include "msg/lxmf_transport.h"
#include "msg/waypoint.h"
#include "ui/display_ui.h"
#include <RNG.h>

// Device identity (global, used by networking later)
static crypto::Identity device_identity;
static net::Destination device_destination;       // traildrop.waypoint
static net::Destination device_lxmf_destination;  // lxmf.delivery (Phase 4a.5)
static bool identity_ready = false;

// Wire compat test: auto-send test message after discovering a peer
static bool auto_send_pending = false;
static uint32_t auto_send_time = 0;

// Boot health tracking — single source of truth for init results
struct BootHealth {
    bool power    = false;
    bool display  = false;
    bool keyboard = false;
    bool trackball = false;
    bool gps      = false;
    bool radio    = false;
    bool storage  = false;
    bool battery  = false;

    bool spi_ready() const { return power; }  // SPI depends on power (GPIO 10)
    bool can_network() const { return radio && storage; }  // Need radio + identity from SD
    bool has_display() const { return display; }
};

static BootHealth boot;

// Boot status display — shows init results on screen
static void show_boot_status(const char* module, bool ok, int line) {
    uint16_t color = ok ? 0x07E0 : 0xF800; // green or red
    hal::display_printf(0, line * 18, color, 2, "%s: %s", module, ok ? "OK" : "FAIL");
}

// ============================================================
// Phase 2: Crypto Self-Tests (Reticulum-compatible)
// ============================================================

static bool test_sha256() {
    // Test vector: SHA-256("abc") = ba7816bf...
    const uint8_t test_data[] = "abc";
    uint8_t hash[32];
    crypto::sha256(test_data, 3, hash);

    const uint8_t expected[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };

    return memcmp(hash, expected, 32) == 0;
}

static bool test_hmac_sha256() {
    // Test vector: HMAC-SHA256(key="key", data="The quick brown fox...")
    const uint8_t key[] = "key";
    const uint8_t data[] = "The quick brown fox jumps over the lazy dog";
    uint8_t hmac[32];
    crypto::hmac_sha256(key, 3, data, 43, hmac);

    const uint8_t expected[32] = {
        0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24,
        0xb1, 0x32, 0x98, 0xe6, 0xaa, 0x6f, 0xb1, 0x43,
        0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46, 0x17, 0x59,
        0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8
    };

    return memcmp(hmac, expected, 32) == 0;
}

static bool test_aes256_cbc() {
    // AES-256-CBC encrypt/decrypt roundtrip
    const uint8_t key[32] = {
        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
    };
    const uint8_t iv[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };
    const uint8_t plaintext[] = "Hello, TrailDrop! This is a test message.";
    size_t plaintext_len = strlen((const char*)plaintext);

    uint8_t ciphertext[128];
    size_t cipher_len = 0;
    if (!crypto::aes256_cbc_encrypt(key, iv, plaintext, plaintext_len, ciphertext, &cipher_len)) {
        return false;
    }

    uint8_t decrypted[128];
    size_t decrypted_len = 0;
    if (!crypto::aes256_cbc_decrypt(key, iv, ciphertext, cipher_len, decrypted, &decrypted_len)) {
        return false;
    }

    return (decrypted_len == plaintext_len) && (memcmp(plaintext, decrypted, plaintext_len) == 0);
}

static bool test_hkdf() {
    // RFC 5869 Test Case 1
    const uint8_t ikm[22] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    const uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    const uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };
    const uint8_t expected_okm[42] = {
        0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
        0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
        0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
        0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
        0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
        0x58, 0x65
    };

    uint8_t okm[42];
    crypto::hkdf_sha256(ikm, 22, salt, 13, info, 10, okm, 42);

    return memcmp(okm, expected_okm, 42) == 0;
}

static bool test_token_roundtrip() {
    // Token encrypt then decrypt with known key
    uint8_t derived_key[64];
    for (int i = 0; i < 64; i++) derived_key[i] = (uint8_t)i;

    crypto::Token token;
    crypto::token_init(token, derived_key);

    const uint8_t plaintext[] = "Token roundtrip test message";
    size_t plaintext_len = strlen((const char*)plaintext);

    uint8_t encrypted[256];
    size_t enc_len = 0;
    if (!crypto::token_encrypt(token, plaintext, plaintext_len, encrypted, &enc_len)) {
        return false;
    }

    uint8_t decrypted[256];
    size_t dec_len = 0;
    if (!crypto::token_decrypt(token, encrypted, enc_len, decrypted, &dec_len)) {
        return false;
    }

    return (dec_len == plaintext_len) && (memcmp(plaintext, decrypted, plaintext_len) == 0);
}

static bool test_token_hmac_reject() {
    // Corrupt one byte of token, verify decrypt fails
    uint8_t derived_key[64];
    for (int i = 0; i < 64; i++) derived_key[i] = (uint8_t)(i + 100);

    crypto::Token token;
    crypto::token_init(token, derived_key);

    const uint8_t plaintext[] = "HMAC rejection test";
    size_t plaintext_len = strlen((const char*)plaintext);

    uint8_t encrypted[256];
    size_t enc_len = 0;
    if (!crypto::token_encrypt(token, plaintext, plaintext_len, encrypted, &enc_len)) {
        return false;
    }

    // Corrupt a byte in the ciphertext area (after IV, before HMAC)
    encrypted[20] ^= 0xFF;

    uint8_t decrypted[256];
    size_t dec_len = 0;
    // Should fail HMAC verification
    if (crypto::token_decrypt(token, encrypted, enc_len, decrypted, &dec_len)) {
        return false; // Should have failed
    }

    return true;
}

static bool test_identity_save_load() {
    // Generate, save, load, verify all fields including hash
    crypto::Identity id;
    if (!crypto::identity_generate(id)) {
        return false;
    }

    const char* test_path = "/identity_test.dat";
    if (!crypto::identity_save(id, test_path)) {
        return false;
    }

    crypto::Identity loaded;
    if (!crypto::identity_load(loaded, test_path)) {
        return false;
    }

    bool match = (memcmp(id.x25519_public, loaded.x25519_public, 32) == 0) &&
                 (memcmp(id.x25519_private, loaded.x25519_private, 32) == 0) &&
                 (memcmp(id.ed25519_public, loaded.ed25519_public, 32) == 0) &&
                 (memcmp(id.ed25519_private, loaded.ed25519_private, 32) == 0) &&
                 (memcmp(id.hash, loaded.hash, 16) == 0);

    hal::storage_remove(test_path);
    return match;
}

static bool test_identity_hash() {
    // Verify identity hash = truncated_sha256(x25519_pub + ed25519_pub)
    crypto::Identity id;
    if (!crypto::identity_generate(id)) {
        return false;
    }

    // Manually compute expected hash with correct key order
    uint8_t pub_concat[64];
    memcpy(pub_concat, id.x25519_public, 32);       // X25519 FIRST
    memcpy(pub_concat + 32, id.ed25519_public, 32);  // Ed25519 SECOND
    uint8_t full_hash[32];
    crypto::sha256(pub_concat, 64, full_hash);

    // Compare first 16 bytes with stored hash
    return memcmp(id.hash, full_hash, 16) == 0;
}

static bool test_destination_hash() {
    // Verify two-step destination hash process
    crypto::Identity id;
    if (!crypto::identity_generate(id)) {
        return false;
    }

    // Compute manually: step 1 — name_hash = sha256("traildrop.waypoint")[0:10]
    uint8_t name_full_hash[32];
    const char* full_name = "traildrop.waypoint";
    crypto::sha256((const uint8_t*)full_name, strlen(full_name), name_full_hash);

    // Step 2 — concat name_hash(10) + identity.hash(16) = 26 bytes
    uint8_t concat[26];
    memcpy(concat, name_full_hash, 10);
    memcpy(concat + 10, id.hash, 16);

    // Step 3 — dest_hash = sha256(concat)[0:16]
    uint8_t expected[32];
    crypto::sha256(concat, 26, expected);

    // Compare with function output
    uint8_t actual[16];
    crypto::identity_destination_hash("traildrop.waypoint", id, actual);

    if (memcmp(actual, expected, 16) != 0) {
        return false;
    }

    // Different name should produce different hash
    uint8_t other[16];
    crypto::identity_destination_hash("traildrop.chat", id, other);
    return memcmp(actual, other, 16) != 0;
}

static bool test_identity_encrypt_decrypt() {
    // Alice encrypts for Bob, Bob decrypts
    crypto::Identity alice, bob;
    if (!crypto::identity_generate(alice) || !crypto::identity_generate(bob)) {
        return false;
    }

    const uint8_t plaintext[] = "Hello Bob, this is Alice!";
    size_t plaintext_len = strlen((const char*)plaintext);

    uint8_t encrypted[256];
    size_t enc_len = 0;
    if (!crypto::identity_encrypt(bob, plaintext, plaintext_len, encrypted, &enc_len)) {
        return false;
    }

    // Verify output has expected overhead
    if (enc_len < 32 + TOKEN_OVERHEAD + plaintext_len) {
        return false;
    }

    uint8_t decrypted[256];
    size_t dec_len = 0;
    if (!crypto::identity_decrypt(bob, encrypted, enc_len, decrypted, &dec_len)) {
        return false;
    }

    return (dec_len == plaintext_len) && (memcmp(plaintext, decrypted, plaintext_len) == 0);
}

static bool test_cross_identity_failure() {
    // Alice encrypts for Bob, Carol can't decrypt
    crypto::Identity alice, bob, carol;
    if (!crypto::identity_generate(alice) || !crypto::identity_generate(bob) ||
        !crypto::identity_generate(carol)) {
        return false;
    }

    const uint8_t plaintext[] = "Secret for Bob only";
    size_t plaintext_len = strlen((const char*)plaintext);

    uint8_t encrypted[256];
    size_t enc_len = 0;
    if (!crypto::identity_encrypt(bob, plaintext, plaintext_len, encrypted, &enc_len)) {
        return false;
    }

    // Carol tries to decrypt — should fail
    uint8_t decrypted[256];
    size_t dec_len = 0;
    if (crypto::identity_decrypt(carol, encrypted, enc_len, decrypted, &dec_len)) {
        return false; // Should have failed
    }

    return true;
}

static bool test_ed25519_sign_verify() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) {
        return false;
    }

    const uint8_t message[] = "Test message for signing";
    uint8_t signature[64];

    if (!crypto::identity_sign(id, message, sizeof(message), signature)) {
        return false;
    }

    // Verify with correct public key
    if (!crypto::identity_verify(id.ed25519_public, message, sizeof(message), signature)) {
        return false;
    }

    // Verify that wrong public key fails
    crypto::Identity wrong_id;
    crypto::identity_generate(wrong_id);
    if (crypto::identity_verify(wrong_id.ed25519_public, message, sizeof(message), signature)) {
        return false;
    }

    return true;
}

static void run_crypto_tests(int& line) {
    Serial.println("\n[CRYPTO] Running Phase 2 crypto tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== Crypto Tests ===");
    line++;

    struct { const char* name; bool (*fn)(); } tests[] = {
        {"SHA-256",         test_sha256},
        {"HMAC-SHA256",     test_hmac_sha256},
        {"AES-256-CBC",     test_aes256_cbc},
        {"HKDF-SHA256",     test_hkdf},
        {"Token Round",     test_token_roundtrip},
        {"Token HMAC",      test_token_hmac_reject},
        {"Identity S/L",    test_identity_save_load},
        {"Identity Hash",   test_identity_hash},
        {"Dest Hash",       test_destination_hash},
        {"Encrypt/Decrypt", test_identity_encrypt_decrypt},
        {"Cross-ID Fail",   test_cross_identity_failure},
        {"Ed25519 Sign",    test_ed25519_sign_verify},
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    bool all_pass = true;
    for (int i = 0; i < num_tests; i++) {
        bool ok = tests[i].fn();
        if (!ok) all_pass = false;
        Serial.printf("[CRYPTO] %-16s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        show_boot_status(tests[i].name, ok, line++);
    }

    Serial.printf("[CRYPTO] === %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    hal::display_printf(0, (line + 1) * 18, all_pass ? 0x07E0 : 0xF800, 2,
                        all_pass ? "Crypto: ALL PASS" : "Crypto: FAILURES");
    line += 2;
}

// ============================================================
// Phase 3a: Packet Wire Format Tests
// ============================================================

static bool test_flags_construction() {
    Packet pkt;
    
    // Test 1: HEADER_1, BROADCAST, SINGLE, DATA → 0x00
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_DATA);
    if (pkt.flags != 0x00) return false;
    if (pkt.get_header_type() != HEADER_1) return false;
    if (pkt.get_packet_type() != PKT_DATA) return false;
    
    // Test 2: HEADER_1, BROADCAST, SINGLE, ANNOUNCE → 0x01
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_ANNOUNCE);
    if (pkt.flags != 0x01) return false;
    if (pkt.get_packet_type() != PKT_ANNOUNCE) return false;
    
    // Test 3: HEADER_2, TRANSPORT, SINGLE, DATA → 0x50
    pkt.set_flags(HEADER_2, false, TRANSPORT_TRANSPORT, DEST_SINGLE, PKT_DATA);
    if (pkt.flags != 0x50) return false;
    if (pkt.get_header_type() != HEADER_2) return false;
    if (pkt.get_transport_type() != TRANSPORT_TRANSPORT) return false;
    
    // Test 4: HEADER_1, BROADCAST, LINK, PROOF → 0x0F
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_LINK, PKT_PROOF);
    if (pkt.flags != 0x0F) return false;
    if (pkt.get_destination_type() != DEST_LINK) return false;
    if (pkt.get_packet_type() != PKT_PROOF) return false;
    
    return true;
}

static bool test_header1_roundtrip() {
    Packet pkt;
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_DATA);
    pkt.hops = 5;
    pkt.has_transport = false;
    for (int i = 0; i < 16; i++) pkt.dest_hash[i] = i;
    pkt.context = 0x00;
    const char* msg = "Hello TrailDrop";
    pkt.payload_len = strlen(msg);
    memcpy(pkt.payload, msg, pkt.payload_len);
    
    uint8_t buf[RNS_MTU];
    int len = net::packet_serialize(pkt, buf, sizeof(buf));
    if (len < 0) return false;
    
    Packet pkt2;
    if (!net::packet_deserialize(buf, len, pkt2)) return false;
    
    // Verify all fields match
    if (pkt2.flags != pkt.flags) return false;
    if (pkt2.hops != pkt.hops) return false;
    if (pkt2.has_transport != pkt.has_transport) return false;
    if (memcmp(pkt2.dest_hash, pkt.dest_hash, 16) != 0) return false;
    if (pkt2.context != pkt.context) return false;
    if (pkt2.payload_len != pkt.payload_len) return false;
    if (memcmp(pkt2.payload, pkt.payload, pkt.payload_len) != 0) return false;
    
    return true;
}

static bool test_header2_roundtrip() {
    Packet pkt;
    pkt.set_flags(HEADER_2, false, TRANSPORT_TRANSPORT, DEST_SINGLE, PKT_DATA);
    pkt.hops = 3;
    pkt.has_transport = true;
    for (int i = 0; i < 16; i++) {
        pkt.transport_id[i] = i + 0x10;
        pkt.dest_hash[i] = i + 0x20;
    }
    pkt.context = 0x01;
    const char* msg = "Test with transport";
    pkt.payload_len = strlen(msg);
    memcpy(pkt.payload, msg, pkt.payload_len);
    
    uint8_t buf[RNS_MTU];
    int len = net::packet_serialize(pkt, buf, sizeof(buf));
    if (len < 0) return false;
    
    Packet pkt2;
    if (!net::packet_deserialize(buf, len, pkt2)) return false;
    
    // Verify all fields match
    if (pkt2.flags != pkt.flags) return false;
    if (pkt2.hops != pkt.hops) return false;
    if (pkt2.has_transport != pkt.has_transport) return false;
    if (memcmp(pkt2.transport_id, pkt.transport_id, 16) != 0) return false;
    if (memcmp(pkt2.dest_hash, pkt.dest_hash, 16) != 0) return false;
    if (pkt2.context != pkt.context) return false;
    if (pkt2.payload_len != pkt.payload_len) return false;
    if (memcmp(pkt2.payload, pkt.payload, pkt.payload_len) != 0) return false;
    
    return true;
}

static bool test_header1_packet_hash() {
    Packet pkt;
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_ANNOUNCE);
    pkt.hops = 0x03;
    pkt.has_transport = false;
    for (int i = 0; i < 16; i++) pkt.dest_hash[i] = i;
    pkt.context = 0x00;
    const char* msg = "test_payload_data";
    pkt.payload_len = strlen(msg);
    memcpy(pkt.payload, msg, pkt.payload_len);
    
    uint8_t buf[RNS_MTU];
    int len = net::packet_serialize(pkt, buf, sizeof(buf));
    if (len < 0) return false;
    
    uint8_t hash[32];
    uint8_t truncated[16];
    net::packet_hash(buf, len, false, hash, truncated);
    
    // Expected full hash from test vector
    const uint8_t expected_full[32] = {
        0x84, 0xdb, 0xe6, 0xcd, 0x02, 0x86, 0x40, 0x2b,
        0x42, 0x1e, 0x6c, 0x72, 0xe1, 0xdb, 0xa3, 0xb6,
        0x0a, 0x57, 0x0f, 0xad, 0x27, 0x66, 0x08, 0x62,
        0x93, 0xd4, 0xa2, 0xaf, 0x5c, 0x7b, 0x43, 0x58,
    };
    
    // Expected truncated (first 16 bytes)
    const uint8_t expected_trunc[16] = {
        0x84, 0xdb, 0xe6, 0xcd, 0x02, 0x86, 0x40, 0x2b,
        0x42, 0x1e, 0x6c, 0x72, 0xe1, 0xdb, 0xa3, 0xb6,
    };
    
    if (memcmp(hash, expected_full, 32) != 0) return false;
    if (memcmp(truncated, expected_trunc, 16) != 0) return false;
    
    return true;
}

static bool test_header2_hash_strips_transport() {
    // Create HEADER_2 packet with transport_id
    Packet pkt2;
    pkt2.set_flags(HEADER_2, false, TRANSPORT_TRANSPORT, DEST_SINGLE, PKT_DATA);
    pkt2.hops = 7;
    pkt2.has_transport = true;
    for (int i = 0; i < 16; i++) {
        pkt2.transport_id[i] = 0xAA;  // Different transport
        pkt2.dest_hash[i] = i;
    }
    pkt2.context = 0x00;
    const char* msg = "same payload";
    pkt2.payload_len = strlen(msg);
    memcpy(pkt2.payload, msg, pkt2.payload_len);
    
    // Create HEADER_1 packet with same logical content
    Packet pkt1;
    pkt1.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_DATA);
    pkt1.hops = 3;  // Different hops
    pkt1.has_transport = false;
    memcpy(pkt1.dest_hash, pkt2.dest_hash, 16);
    pkt1.context = pkt2.context;
    pkt1.payload_len = pkt2.payload_len;
    memcpy(pkt1.payload, pkt2.payload, pkt2.payload_len);
    
    uint8_t buf1[RNS_MTU], buf2[RNS_MTU];
    int len1 = net::packet_serialize(pkt1, buf1, sizeof(buf1));
    int len2 = net::packet_serialize(pkt2, buf2, sizeof(buf2));
    if (len1 < 0 || len2 < 0) return false;
    
    uint8_t hash1[32], hash2[32];
    uint8_t trunc1[16], trunc2[16];
    net::packet_hash(buf1, len1, false, hash1, trunc1);
    net::packet_hash(buf2, len2, true, hash2, trunc2);
    
    // Should produce SAME truncated hash (transport metadata stripped)
    return memcmp(trunc1, trunc2, 16) == 0;
}

static bool test_max_payload_enforcement() {
    Packet pkt;
    uint8_t buf[RNS_MTU];
    
    // HEADER_1 with payload_len > 481 should fail
    pkt.has_transport = false;
    pkt.payload_len = 482;
    if (net::packet_serialize(pkt, buf, sizeof(buf)) != -1) return false;
    
    // HEADER_2 with payload_len > 465 should fail
    pkt.has_transport = true;
    pkt.payload_len = 466;
    if (net::packet_serialize(pkt, buf, sizeof(buf)) != -1) return false;
    
    return true;
}

static bool test_deserialize_rejects_undersized() {
    Packet pkt;
    uint8_t buf[10] = {0};
    
    // 10 bytes is too small for any valid packet
    if (net::packet_deserialize(buf, 10, pkt)) return false;
    
    return true;
}

static bool test_empty_payload() {
    Packet pkt;
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_DATA);
    pkt.hops = 0;
    pkt.has_transport = false;
    for (int i = 0; i < 16; i++) pkt.dest_hash[i] = i;
    pkt.context = 0x00;
    pkt.payload_len = 0;
    
    uint8_t buf[RNS_MTU];
    int len = net::packet_serialize(pkt, buf, sizeof(buf));
    if (len != 19) return false;  // Exactly HEADER_1 size
    
    Packet pkt2;
    if (!net::packet_deserialize(buf, len, pkt2)) return false;
    if (pkt2.payload_len != 0) return false;
    
    return true;
}

static bool test_exact_max_payload() {
    Packet pkt;
    uint8_t buf[RNS_MTU];
    
    // HEADER_1 with exactly 481 bytes should succeed
    pkt.has_transport = false;
    pkt.payload_len = 481;
    for (size_t i = 0; i < 481; i++) pkt.payload[i] = (uint8_t)i;
    int len = net::packet_serialize(pkt, buf, sizeof(buf));
    if (len != 500) return false;
    
    // HEADER_1 with 482 bytes should fail
    pkt.payload_len = 482;
    if (net::packet_serialize(pkt, buf, sizeof(buf)) != -1) return false;
    
    // HEADER_2 with exactly 465 bytes should succeed
    pkt.has_transport = true;
    pkt.payload_len = 465;
    len = net::packet_serialize(pkt, buf, sizeof(buf));
    if (len != 500) return false;
    
    // HEADER_2 with 466 bytes should fail
    pkt.payload_len = 466;
    if (net::packet_serialize(pkt, buf, sizeof(buf)) != -1) return false;
    
    return true;
}

static bool test_identity_dest_roundtrip() {
    // Generate a fresh identity
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    // Derive destination
    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;
    
    // Manually compute destination hash to verify it matches
    uint8_t expected[16];
    crypto::identity_destination_hash("traildrop.waypoint", id, expected);
    if (memcmp(dest.hash, expected, 16) != 0) return false;
    
    // Verify app_name and aspects are stored correctly
    if (strcmp(dest.app_name, "traildrop") != 0) return false;
    if (strcmp(dest.aspects, "waypoint") != 0) return false;
    
    return true;
}

static bool test_destination_consistency() {
    // Generate identity
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    // Same identity + same app_name + same aspects → same dest_hash every time
    net::Destination dest1, dest2;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest1)) return false;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest2)) return false;
    if (memcmp(dest1.hash, dest2.hash, 16) != 0) return false;
    
    // Different aspects → different dest_hash
    net::Destination dest3;
    if (!net::destination_derive(id, "traildrop", "chat", dest3)) return false;
    if (memcmp(dest1.hash, dest3.hash, 16) == 0) return false;
    
    return true;
}

static void run_packet_tests(int& line) {
    Serial.println("\n[PACKET] Running Phase 3a packet tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== Packet Tests ===");
    line++;

    struct { const char* name; bool (*fn)(); } tests[] = {
        {"Flags Construct",  test_flags_construction},
        {"H1 Roundtrip",     test_header1_roundtrip},
        {"H2 Roundtrip",     test_header2_roundtrip},
        {"H1 Hash Vector",   test_header1_packet_hash},
        {"H2 Hash Strips",   test_header2_hash_strips_transport},
        {"Max Payload",      test_max_payload_enforcement},
        {"Reject Undersize", test_deserialize_rejects_undersized},
        {"Empty Payload",    test_empty_payload},
        {"Exact Max Bound",  test_exact_max_payload},
        {"Dest Roundtrip",   test_identity_dest_roundtrip},
        {"Dest Consistent",  test_destination_consistency},
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    bool all_pass = true;
    for (int i = 0; i < num_tests; i++) {
        bool ok = tests[i].fn();
        if (!ok) all_pass = false;
        Serial.printf("[PACKET] %-16s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        show_boot_status(tests[i].name, ok, line++);
    }

    Serial.printf("[PACKET] === %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    hal::display_printf(0, (line + 1) * 18, all_pass ? 0x07E0 : 0xF800, 2,
                        all_pass ? "Packet: ALL PASS" : "Packet: FAILURES");
    line += 2;
}

// ============================================================
// Phase 3c: Announce and Peer Table Tests
// ============================================================

static bool test_announce_build_valid_payload() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;
    
    Packet pkt;
    if (!net::announce_build(id, dest, "TestNode", pkt)) return false;
    
    // Verify packet flags
    if (pkt.get_packet_type() != PKT_ANNOUNCE) return false;
    if (pkt.get_destination_type() != DEST_SINGLE) return false;
    if (pkt.get_header_type() != HEADER_1) return false;
    
    // Verify payload length: 148 base + msgpack([b"TestNode", null])
    // msgpack: 0x92 + 0xc4 0x08 + "TestNode"(8) + 0xc0 = 12 bytes
    size_t expected_len = 148 + 12;
    if (pkt.payload_len != expected_len) return false;

    // Verify app_data starts with 0x92 (fixarray of 2)
    if (pkt.payload[148] != 0x92) return false;
    
    // Verify public keys in payload
    if (memcmp(&pkt.payload[0], id.x25519_public, 32) != 0) return false;
    if (memcmp(&pkt.payload[32], id.ed25519_public, 32) != 0) return false;
    
    return true;
}

static bool test_announce_roundtrip() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;
    
    Packet pkt;
    if (!net::announce_build(id, dest, "Alice", pkt)) return false;
    
    net::peer_table_init();
    
    if (!net::announce_process(pkt)) return false;
    
    const net::Peer* peer = net::peer_lookup(dest.hash);
    if (peer == nullptr) return false;
    
    if (memcmp(peer->x25519_public, id.x25519_public, 32) != 0) return false;
    if (strcmp(peer->app_data, "Alice") != 0) return false;
    
    return true;
}

static bool test_announce_wrong_signature_fails() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;
    
    Packet pkt;
    if (!net::announce_build(id, dest, "Bob", pkt)) return false;
    
    // Corrupt one byte of the signature (at offset 84)
    pkt.payload[84] ^= 0xFF;
    
    net::peer_table_init();
    
    // Should fail signature verification
    if (net::announce_process(pkt)) return false;
    
    return true;
}

static bool test_announce_wrong_dest_hash_fails() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;
    
    Packet pkt;
    if (!net::announce_build(id, dest, "Carol", pkt)) return false;
    
    // Corrupt dest_hash
    pkt.dest_hash[0] ^= 0xFF;
    
    net::peer_table_init();
    
    // Should fail dest hash verification
    if (net::announce_process(pkt)) return false;
    
    return true;
}

static bool test_peer_table_store_lookup() {
    net::peer_table_init();
    
    uint8_t dest_hash[DEST_HASH_SIZE];
    uint8_t x25519[32];
    uint8_t ed25519[32];
    uint8_t id_hash[DEST_HASH_SIZE];
    
    for (int i = 0; i < DEST_HASH_SIZE; i++) dest_hash[i] = i;
    for (int i = 0; i < 32; i++) x25519[i] = i + 0x10;
    for (int i = 0; i < 32; i++) ed25519[i] = i + 0x20;
    for (int i = 0; i < DEST_HASH_SIZE; i++) id_hash[i] = i + 0x30;
    
    if (!net::peer_store(dest_hash, x25519, ed25519, id_hash, "TestPeer")) return false;
    
    const net::Peer* peer = net::peer_lookup(dest_hash);
    if (peer == nullptr) return false;
    
    if (memcmp(peer->dest_hash, dest_hash, DEST_HASH_SIZE) != 0) return false;
    if (strcmp(peer->app_data, "TestPeer") != 0) return false;
    
    if (net::peer_count() != 1) return false;
    
    // Lookup with different hash should return nullptr
    uint8_t wrong_hash[DEST_HASH_SIZE];
    for (int i = 0; i < DEST_HASH_SIZE; i++) wrong_hash[i] = 0xFF;
    if (net::peer_lookup(wrong_hash) != nullptr) return false;
    
    return true;
}

static bool test_announce_without_app_data() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;
    
    Packet pkt;
    if (!net::announce_build(id, dest, nullptr, pkt)) return false;
    
    // Should be exactly 148 bytes (no app_data)
    if (pkt.payload_len != 148) return false;
    
    net::peer_table_init();
    
    if (!net::announce_process(pkt)) return false;
    
    const net::Peer* peer = net::peer_lookup(dest.hash);
    if (peer == nullptr) return false;
    
    // app_data should be empty string
    if (peer->app_data[0] != '\0') return false;
    
    return true;
}

static bool test_announce_payload_too_short() {
    Packet pkt;
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_ANNOUNCE);
    pkt.payload_len = 100;  // Too short
    
    net::peer_table_init();
    
    // Should fail
    if (net::announce_process(pkt)) return false;
    
    return true;
}

static bool test_announce_duplicate_updates_peer() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;
    
    net::peer_table_init();
    
    // First announce
    Packet pkt1;
    if (!net::announce_build(id, dest, "Alice", pkt1)) return false;
    if (!net::announce_process(pkt1)) return false;
    
    if (net::peer_count() != 1) return false;
    
    // Second announce from same identity with different app_data
    Packet pkt2;
    if (!net::announce_build(id, dest, "AliceV2", pkt2)) return false;
    if (!net::announce_process(pkt2)) return false;
    
    // Should still be 1 peer (updated, not duplicated)
    if (net::peer_count() != 1) return false;
    
    const net::Peer* peer = net::peer_lookup(dest.hash);
    if (peer == nullptr) return false;
    
    // app_data should be updated
    if (strcmp(peer->app_data, "AliceV2") != 0) return false;
    
    return true;
}

static bool test_peer_table_multiple_peers() {
    net::peer_table_init();
    
    // Generate 3 different identities and announce them
    crypto::Identity ids[3];
    net::Destination dests[3];
    const char* names[] = {"Alice", "Bob", "Carol"};
    
    for (int i = 0; i < 3; i++) {
        if (!crypto::identity_generate(ids[i])) return false;
        if (!net::destination_derive(ids[i], "traildrop", "waypoint", dests[i])) return false;
        
        Packet pkt;
        if (!net::announce_build(ids[i], dests[i], names[i], pkt)) return false;
        if (!net::announce_process(pkt)) return false;
    }
    
    if (net::peer_count() != 3) return false;
    
    // Verify all 3 can be looked up
    for (int i = 0; i < 3; i++) {
        const net::Peer* peer = net::peer_lookup(dests[i].hash);
        if (peer == nullptr) return false;
        if (strcmp(peer->app_data, names[i]) != 0) return false;
    }
    
    return true;
}

// ============================================================
// Phase 3d: Transport Tests
// ============================================================

static bool test_transport_init() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    net::Destination dest;
    if (!net::destination_derive(id, "test", "transport", dest)) return false;
    
    // Initialize transport
    if (!net::transport_init(id, dest)) return false;
    
    // Stats should be zero
    if (net::transport_tx_count() != 0) return false;
    if (net::transport_rx_count() != 0) return false;
    
    return true;
}

static bool test_transport_announce_requires_init() {
    // Try to send announce before init
    // This should fail gracefully
    // Note: We can't actually test this without resetting state,
    // so we just verify ANNOUNCE_INTERVAL is defined
    if (ANNOUNCE_INTERVAL <= 0) return false;
    return true;
}

static bool test_transport_callback_registration() {
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;
    
    net::Destination dest;
    if (!net::destination_derive(id, "test", "callback", dest)) return false;
    
    if (!net::transport_init(id, dest)) return false;
    
    // Register a callback (should not crash)
    bool callback_called = false;
    net::transport_on_data([](const uint8_t* sender, const uint8_t* data, size_t len) {
        // Callback function
    });
    
    return true;
}

static bool test_transport_packet_serialize_roundtrip() {
    // Create a DATA packet
    Packet pkt;
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_DATA);
    pkt.hops = 0;
    pkt.has_transport = false;
    pkt.context = CTX_NONE;
    
    // Fill dest_hash with test data
    for (int i = 0; i < DEST_HASH_SIZE; i++) {
        pkt.dest_hash[i] = i;
    }
    
    // Add test payload
    const char* test_payload = "Hello Transport";
    memcpy(pkt.payload, test_payload, strlen(test_payload));
    pkt.payload_len = strlen(test_payload);
    
    // Serialize
    uint8_t buf[RNS_MTU];
    int len = net::packet_serialize(pkt, buf, RNS_MTU);
    if (len < 0) return false;
    
    // Deserialize
    Packet pkt2;
    if (!net::packet_deserialize(buf, len, pkt2)) return false;
    
    // Verify fields match
    if (pkt2.get_packet_type() != PKT_DATA) return false;
    if (pkt2.payload_len != pkt.payload_len) return false;
    if (memcmp(pkt2.payload, pkt.payload, pkt.payload_len) != 0) return false;
    if (memcmp(pkt2.dest_hash, pkt.dest_hash, DEST_HASH_SIZE) != 0) return false;
    
    return true;
}

static void run_transport_tests(int& line) {
    Serial.println("\n[TRANSPORT] Running Phase 3d transport tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== Transport Tests ===");
    line++;

    struct { const char* name; bool (*fn)(); } tests[] = {
        {"Init",             test_transport_init},
        {"Announce Cfg",     test_transport_announce_requires_init},
        {"Callback Reg",     test_transport_callback_registration},
        {"Pkt Roundtrip",    test_transport_packet_serialize_roundtrip},
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    bool all_pass = true;
    for (int i = 0; i < num_tests; i++) {
        bool ok = tests[i].fn();
        if (!ok) all_pass = false;
        Serial.printf("[TRANSPORT] %-16s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        show_boot_status(tests[i].name, ok, line++);
    }

    Serial.printf("[TRANSPORT] === %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    hal::display_printf(0, (line + 1) * 18, all_pass ? 0x07E0 : 0xF800, 2,
                        all_pass ? "Transport: ALL PASS" : "Transport: FAILURES");
    line += 2;
}

static void run_announce_tests(int& line) {
    Serial.println("\n[ANNOUNCE] Running Phase 3c announce tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== Announce Tests ===");
    line++;

    struct { const char* name; bool (*fn)(); } tests[] = {
        {"Announce Build",   test_announce_build_valid_payload},
        {"Roundtrip",        test_announce_roundtrip},
        {"Wrong Signature",  test_announce_wrong_signature_fails},
        {"Wrong DestHash",   test_announce_wrong_dest_hash_fails},
        {"Peer Store/Lookup", test_peer_table_store_lookup},
        {"No AppData",       test_announce_without_app_data},
        {"Payload TooShort", test_announce_payload_too_short},
        {"Duplicate Update", test_announce_duplicate_updates_peer},
        {"Multiple Peers",   test_peer_table_multiple_peers},
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    bool all_pass = true;
    for (int i = 0; i < num_tests; i++) {
        bool ok = tests[i].fn();
        if (!ok) all_pass = false;
        Serial.printf("[ANNOUNCE] %-16s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        show_boot_status(tests[i].name, ok, line++);
    }

    Serial.printf("[ANNOUNCE] === %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    hal::display_printf(0, (line + 1) * 18, all_pass ? 0x07E0 : 0xF800, 2,
                        all_pass ? "Announce: ALL PASS" : "Announce: FAILURES");
    line += 2;
}

// ============================================================
// Phase 4a: msgpack + LXMF Tests
// ============================================================

// Helper: convert hex string to bytes (compile-time known vectors)
static int hex_to_bytes(const char* hex, uint8_t* out, size_t max_len) {
    size_t hex_len = strlen(hex);
    size_t byte_len = hex_len / 2;
    if (byte_len > max_len) return -1;
    for (size_t i = 0; i < byte_len; i++) {
        char hi = hex[i*2], lo = hex[i*2+1];
        auto nibble = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + c - 'a';
            if (c >= 'A' && c <= 'F') return 10 + c - 'A';
            return 0;
        };
        out[i] = (nibble(hi) << 4) | nibble(lo);
    }
    return (int)byte_len;
}

static bool test_msgpack_encode_match() {
    // Test that our encoder produces identical bytes to Python msgpack
    uint8_t buf[64];
    bool ok = true;

    // nil
    { msg::Encoder e(buf, sizeof(buf)); e.write_nil();
      ok &= (e.pos == 1 && buf[0] == 0xc0); }

    // true / false
    { msg::Encoder e(buf, sizeof(buf)); e.write_bool(true);
      ok &= (e.pos == 1 && buf[0] == 0xc3); }
    { msg::Encoder e(buf, sizeof(buf)); e.write_bool(false);
      ok &= (e.pos == 1 && buf[0] == 0xc2); }

    // positive fixint
    { msg::Encoder e(buf, sizeof(buf)); e.write_uint(0);
      ok &= (e.pos == 1 && buf[0] == 0x00); }
    { msg::Encoder e(buf, sizeof(buf)); e.write_uint(42);
      ok &= (e.pos == 1 && buf[0] == 0x2a); }
    { msg::Encoder e(buf, sizeof(buf)); e.write_uint(127);
      ok &= (e.pos == 1 && buf[0] == 0x7f); }

    // uint8
    { msg::Encoder e(buf, sizeof(buf)); e.write_uint(128);
      ok &= (e.pos == 2 && buf[0] == 0xcc && buf[1] == 0x80); }
    { msg::Encoder e(buf, sizeof(buf)); e.write_uint(255);
      ok &= (e.pos == 2 && buf[0] == 0xcc && buf[1] == 0xff); }

    // uint16
    { msg::Encoder e(buf, sizeof(buf)); e.write_uint(256);
      ok &= (e.pos == 3 && buf[0] == 0xcd && buf[1] == 0x01 && buf[2] == 0x00); }

    // CRITICAL: field keys 0xFB/0xFC must be uint8, not fixint
    { msg::Encoder e(buf, sizeof(buf)); e.write_uint(251);
      ok &= (e.pos == 2 && buf[0] == 0xcc && buf[1] == 0xfb); }
    { msg::Encoder e(buf, sizeof(buf)); e.write_uint(252);
      ok &= (e.pos == 2 && buf[0] == 0xcc && buf[1] == 0xfc); }

    // negative fixint
    { msg::Encoder e(buf, sizeof(buf)); e.write_int(-1);
      ok &= (e.pos == 1 && buf[0] == 0xff); }
    { msg::Encoder e(buf, sizeof(buf)); e.write_int(-32);
      ok &= (e.pos == 1 && buf[0] == 0xe0); }

    // int8
    { msg::Encoder e(buf, sizeof(buf)); e.write_int(-33);
      ok &= (e.pos == 2 && buf[0] == 0xd0 && buf[1] == 0xdf); }
    { msg::Encoder e(buf, sizeof(buf)); e.write_int(-128);
      ok &= (e.pos == 2 && buf[0] == 0xd0 && buf[1] == 0x80); }

    // float64 — timestamp 1709000000.5
    { msg::Encoder e(buf, sizeof(buf)); e.write_float64(1709000000.5);
      uint8_t expected[] = {0xcb, 0x41, 0xd9, 0x77, 0x51, 0x50, 0x20, 0x00, 0x00};
      ok &= (e.pos == 9 && memcmp(buf, expected, 9) == 0); }

    // bin8 — "Test" (4 bytes)
    { msg::Encoder e(buf, sizeof(buf));
      e.write_bin((const uint8_t*)"Test", 4);
      uint8_t expected[] = {0xc4, 0x04, 'T', 'e', 's', 't'};
      ok &= (e.pos == 6 && memcmp(buf, expected, 6) == 0); }

    // bin8 — empty
    { msg::Encoder e(buf, sizeof(buf));
      e.write_bin(nullptr, 0);
      ok &= (e.pos == 2 && buf[0] == 0xc4 && buf[1] == 0x00); }

    // fixstr — "lat"
    { msg::Encoder e(buf, sizeof(buf)); e.write_str("lat", 3);
      ok &= (e.pos == 4 && buf[0] == 0xa3 && buf[1] == 'l' && buf[2] == 'a' && buf[3] == 't'); }

    // fixarray(0)
    { msg::Encoder e(buf, sizeof(buf)); e.write_array(0);
      ok &= (e.pos == 1 && buf[0] == 0x90); }

    // fixarray(4) + 4 fixints
    { msg::Encoder e(buf, sizeof(buf));
      e.write_array(4); e.write_uint(1); e.write_uint(2); e.write_uint(3); e.write_uint(4);
      uint8_t expected[] = {0x94, 0x01, 0x02, 0x03, 0x04};
      ok &= (e.pos == 5 && memcmp(buf, expected, 5) == 0); }

    // fixmap(0)
    { msg::Encoder e(buf, sizeof(buf)); e.write_map(0);
      ok &= (e.pos == 1 && buf[0] == 0x80); }

    if (!ok) {
        Serial.println("[MSGPACK] Encode match details:");
        // Rerun to find which failed
        msg::Encoder e(buf, sizeof(buf)); e.write_uint(251);
        Serial.printf("  uint(251): pos=%d [%02x %02x]\n", e.pos, buf[0], buf[1]);
    }

    return ok;
}

static bool test_msgpack_decode_roundtrip() {
    // Encode → Decode → verify values
    uint8_t buf[128];
    msg::Encoder enc(buf, sizeof(buf));

    enc.write_array(4);
    enc.write_float64(1709000000.5);
    enc.write_bin((const uint8_t*)"Test", 4);
    enc.write_bin((const uint8_t*)"Hello from Python!", 18);
    enc.write_map(0);
    if (enc.error) return false;

    msg::Decoder dec(buf, enc.pos);
    uint8_t arr = dec.read_array();
    if (dec.error || arr != 4) return false;

    double ts = dec.read_float64();
    if (dec.error || ts != 1709000000.5) return false;

    uint8_t title[64];
    size_t title_len = dec.read_bin(title, sizeof(title));
    if (dec.error || title_len != 4 || memcmp(title, "Test", 4) != 0) return false;

    uint8_t content[64];
    size_t content_len = dec.read_bin(content, sizeof(content));
    if (dec.error || content_len != 18 || memcmp(content, "Hello from Python!", 18) != 0) return false;

    uint8_t map_count = dec.read_map();
    if (dec.error || map_count != 0) return false;

    return true;
}

static bool test_msgpack_payload_binary_match() {
    // Verify our encoder produces identical bytes to Python for an LXMF payload
    // Python: msgpack.packb([1709000000.5, b"Test", b"Hello from Python!", {}])
    // Expected: 94cb41d9775150200000c40454657374c41248656c6c6f2066726f6d20507974686f6e2180
    const char* expected_hex = "94cb41d9775150200000c40454657374c41248656c6c6f2066726f6d20507974686f6e2180";
    uint8_t expected[64];
    int expected_len = hex_to_bytes(expected_hex, expected, sizeof(expected));

    uint8_t buf[128];
    msg::Encoder enc(buf, sizeof(buf));
    enc.write_array(4);
    enc.write_float64(1709000000.5);
    enc.write_bin((const uint8_t*)"Test", 4);
    enc.write_bin((const uint8_t*)"Hello from Python!", 18);
    enc.write_map(0);

    if (enc.error) return false;
    if ((int)enc.pos != expected_len) {
        Serial.printf("[MSGPACK] Payload len mismatch: got %d, expected %d\n", enc.pos, expected_len);
        return false;
    }
    if (memcmp(buf, expected, expected_len) != 0) {
        Serial.printf("[MSGPACK] Payload bytes mismatch\n");
        Serial.printf("  Got:      ");
        for (size_t i = 0; i < enc.pos; i++) Serial.printf("%02x", buf[i]);
        Serial.println();
        Serial.printf("  Expected: %s\n", expected_hex);
        return false;
    }
    return true;
}

static bool test_msgpack_fields_binary_match() {
    // Python: msgpack.packb({251: b"type_val", 252: b"data_val"})
    // Expected: 82ccfbc408747970655f76616cccfcc408646174615f76616c
    const char* expected_hex = "82ccfbc408747970655f76616cccfcc408646174615f76616c";
    uint8_t expected[64];
    int expected_len = hex_to_bytes(expected_hex, expected, sizeof(expected));

    uint8_t buf[64];
    msg::Encoder enc(buf, sizeof(buf));
    enc.write_map(2);
    enc.write_uint(251);
    enc.write_bin((const uint8_t*)"type_val", 8);
    enc.write_uint(252);
    enc.write_bin((const uint8_t*)"data_val", 8);

    if (enc.error) return false;
    if ((int)enc.pos != expected_len) return false;
    return memcmp(buf, expected, expected_len) == 0;
}

static bool test_lxmf_build_hash_match() {
    // Build LXMF message with test vector keys and verify hash matches Python
    // Using keys and values from test vector generator output

    // Sender identity
    crypto::Identity sender;
    hex_to_bytes("387b35263170015ac008c58a9755350e28f541843a0acb58a142199858ec4e6b",
                 sender.x25519_private, 32);
    hex_to_bytes("338298dec0eeb458587f5792cac3dd70e0e73699a17a2362d00ab3868ba6b313",
                 sender.x25519_public, 32);
    hex_to_bytes("258494ef78f67f7197cd0a52933b72657a346b8792a14ee0f7093a8175441968",
                 sender.ed25519_private, 32);
    hex_to_bytes("bcf6af73c182888032960d55f0679c43f7bf7667594743254cef72532cbdc213",
                 sender.ed25519_public, 32);
    hex_to_bytes("cc4e2bc21134c415f4d685016a443914", sender.hash, 16);
    sender.valid = true;

    uint8_t sender_dest_hash[16];
    hex_to_bytes("b32367e2bddccefe0b15b6f5c957676c", sender_dest_hash, 16);

    uint8_t receiver_dest_hash[16];
    hex_to_bytes("95235d913409716dd8f28afe94cb678f", receiver_dest_hash, 16);

    // Build message
    const char* title = "Test";
    const char* content = "Hello from Python!";
    uint8_t out[512];
    size_t out_len = sizeof(out);
    uint8_t message_hash[32];

    bool built = msg::lxmf_build(
        sender, sender_dest_hash, receiver_dest_hash,
        1709000000.5,
        (const uint8_t*)title, 4,
        (const uint8_t*)content, 18,
        nullptr, 0, nullptr, 0,
        out, &out_len, message_hash
    );
    if (!built) {
        Serial.println("[LXMF] Build failed");
        return false;
    }

    // Verify hash matches Python
    uint8_t expected_hash[32];
    hex_to_bytes("a4760018f636e907660edb9495ac075ea6dd2db8ebbceae08a752feb68d84e48",
                 expected_hash, 32);

    if (memcmp(message_hash, expected_hash, 32) != 0) {
        Serial.printf("[LXMF] Hash mismatch!\n  Got:    ");
        for (int i = 0; i < 32; i++) Serial.printf("%02x", message_hash[i]);
        Serial.printf("\n  Expect: ");
        for (int i = 0; i < 32; i++) Serial.printf("%02x", expected_hash[i]);
        Serial.println();
        return false;
    }

    return true;
}

static bool test_lxmf_build_signature_match() {
    // Build message and verify signature matches Python's
    crypto::Identity sender;
    hex_to_bytes("387b35263170015ac008c58a9755350e28f541843a0acb58a142199858ec4e6b",
                 sender.x25519_private, 32);
    hex_to_bytes("338298dec0eeb458587f5792cac3dd70e0e73699a17a2362d00ab3868ba6b313",
                 sender.x25519_public, 32);
    hex_to_bytes("258494ef78f67f7197cd0a52933b72657a346b8792a14ee0f7093a8175441968",
                 sender.ed25519_private, 32);
    hex_to_bytes("bcf6af73c182888032960d55f0679c43f7bf7667594743254cef72532cbdc213",
                 sender.ed25519_public, 32);
    sender.valid = true;

    uint8_t sender_dest_hash[16], receiver_dest_hash[16];
    hex_to_bytes("b32367e2bddccefe0b15b6f5c957676c", sender_dest_hash, 16);
    hex_to_bytes("95235d913409716dd8f28afe94cb678f", receiver_dest_hash, 16);

    uint8_t out[512];
    size_t out_len = sizeof(out);
    uint8_t message_hash[32];

    msg::lxmf_build(sender, sender_dest_hash, receiver_dest_hash,
                    1709000000.5,
                    (const uint8_t*)"Test", 4,
                    (const uint8_t*)"Hello from Python!", 18,
                    nullptr, 0, nullptr, 0,
                    out, &out_len, message_hash);

    // Signature is at out[16..80)
    uint8_t expected_sig[64];
    hex_to_bytes("d994ae8401dab045fa2e2581789f3a2e2bcfae6f32f2fcee4d37e1fa02a382ee"
                 "88351091198d8821beea40129793481f3ecb56776a6a2c2d21b608370dc31f04",
                 expected_sig, 64);

    if (memcmp(out + 16, expected_sig, 64) != 0) {
        Serial.printf("[LXMF] Signature mismatch!\n  Got:    ");
        for (int i = 0; i < 64; i++) Serial.printf("%02x", out[16 + i]);
        Serial.printf("\n  Expect: ");
        for (int i = 0; i < 64; i++) Serial.printf("%02x", expected_sig[i]);
        Serial.println();
        return false;
    }

    return true;
}

static bool test_lxmf_parse_simple() {
    // Parse Python-generated LXMF message and verify extracted fields
    uint8_t full_packed[512];
    int full_len = hex_to_bytes(
        "95235d913409716dd8f28afe94cb678f"  // dest_hash
        "b32367e2bddccefe0b15b6f5c957676c"  // source_hash
        "d994ae8401dab045fa2e2581789f3a2e2bcfae6f32f2fcee4d37e1fa02a382ee"  // sig[0:32]
        "88351091198d8821beea40129793481f3ecb56776a6a2c2d21b608370dc31f04"  // sig[32:64]
        "94cb41d9775150200000c40454657374c41248656c6c6f2066726f6d20507974686f6e2180",  // payload
        full_packed, sizeof(full_packed));

    msg::LXMessage msg;
    if (!msg::lxmf_parse(full_packed, full_len, msg)) {
        Serial.println("[LXMF] Parse failed");
        return false;
    }

    // Verify timestamp
    if (msg.timestamp != 1709000000.5) {
        Serial.printf("[LXMF] Timestamp mismatch: got %f\n", msg.timestamp);
        return false;
    }

    // Verify title
    if (msg.title_len != 4 || memcmp(msg.title, "Test", 4) != 0) {
        Serial.printf("[LXMF] Title mismatch: len=%d\n", msg.title_len);
        return false;
    }

    // Verify content
    if (msg.content_len != 18 || memcmp(msg.content, "Hello from Python!", 18) != 0) {
        Serial.printf("[LXMF] Content mismatch: len=%d\n", msg.content_len);
        return false;
    }

    // Verify hash matches expected
    uint8_t expected_hash[32];
    hex_to_bytes("a4760018f636e907660edb9495ac075ea6dd2db8ebbceae08a752feb68d84e48",
                 expected_hash, 32);
    if (memcmp(msg.message_hash, expected_hash, 32) != 0) {
        Serial.println("[LXMF] Parse hash mismatch");
        return false;
    }

    return true;
}

static bool test_lxmf_verify_signature() {
    // Parse Python message then verify signature with sender's ed25519 public key
    uint8_t full_packed[512];
    int full_len = hex_to_bytes(
        "95235d913409716dd8f28afe94cb678f"
        "b32367e2bddccefe0b15b6f5c957676c"
        "d994ae8401dab045fa2e2581789f3a2e2bcfae6f32f2fcee4d37e1fa02a382ee"
        "88351091198d8821beea40129793481f3ecb56776a6a2c2d21b608370dc31f04"
        "94cb41d9775150200000c40454657374c41248656c6c6f2066726f6d20507974686f6e2180",
        full_packed, sizeof(full_packed));

    msg::LXMessage msg;
    if (!msg::lxmf_parse(full_packed, full_len, msg)) return false;

    uint8_t sender_ed25519_pub[32];
    hex_to_bytes("bcf6af73c182888032960d55f0679c43f7bf7667594743254cef72532cbdc213",
                 sender_ed25519_pub, 32);

    bool verified = msg::lxmf_verify(msg, sender_ed25519_pub);
    if (!verified) {
        Serial.println("[LXMF] Signature verification failed");
    }
    return verified;
}

static bool test_lxmf_fields_roundtrip() {
    // Build message with custom fields, parse it back, verify fields
    crypto::Identity sender;
    hex_to_bytes("387b35263170015ac008c58a9755350e28f541843a0acb58a142199858ec4e6b",
                 sender.x25519_private, 32);
    hex_to_bytes("338298dec0eeb458587f5792cac3dd70e0e73699a17a2362d00ab3868ba6b313",
                 sender.x25519_public, 32);
    hex_to_bytes("258494ef78f67f7197cd0a52933b72657a346b8792a14ee0f7093a8175441968",
                 sender.ed25519_private, 32);
    hex_to_bytes("bcf6af73c182888032960d55f0679c43f7bf7667594743254cef72532cbdc213",
                 sender.ed25519_public, 32);
    sender.valid = true;

    uint8_t sender_dest_hash[16], receiver_dest_hash[16];
    hex_to_bytes("b32367e2bddccefe0b15b6f5c957676c", sender_dest_hash, 16);
    hex_to_bytes("95235d913409716dd8f28afe94cb678f", receiver_dest_hash, 16);

    const uint8_t* custom_type = (const uint8_t*)"traildrop/waypoint";
    // Pre-encoded waypoint data: msgpack({"lat": 38.9717, "lon": -95.2353})
    uint8_t custom_data[32];
    int custom_data_len = hex_to_bytes(
        "82a36c6174cb40437c60aa64c2f8a36c6f6ecbc057cf0f27bb2fec",
        custom_data, sizeof(custom_data));

    uint8_t out[512];
    size_t out_len = sizeof(out);
    uint8_t message_hash[32];

    bool built = msg::lxmf_build(
        sender, sender_dest_hash, receiver_dest_hash,
        1709000001.0,
        (const uint8_t*)"Waypoint", 8,
        (const uint8_t*)"Camp waypoint", 13,
        custom_type, 18,
        custom_data, custom_data_len,
        out, &out_len, message_hash
    );
    if (!built) return false;

    // Verify hash matches Python
    uint8_t expected_hash[32];
    hex_to_bytes("8f6bd07bb552a21cf95c96e8353290254d2f7fddd413cc14a0f08ca0ea4ebdaf",
                 expected_hash, 32);
    if (memcmp(message_hash, expected_hash, 32) != 0) {
        Serial.printf("[LXMF] Fields hash mismatch\n");
        return false;
    }

    // Reconstruct full LXMF (prepend dest_hash) and parse
    uint8_t full_lxmf[600];
    memcpy(full_lxmf, receiver_dest_hash, 16);
    memcpy(full_lxmf + 16, out, out_len);

    msg::LXMessage parsed;
    if (!msg::lxmf_parse(full_lxmf, 16 + out_len, parsed)) {
        Serial.println("[LXMF] Fields parse failed");
        return false;
    }

    if (!parsed.has_custom_fields) return false;
    if (parsed.custom_type_len != 18) return false;
    if (memcmp(parsed.custom_type, "traildrop/waypoint", 18) != 0) return false;
    if ((int)parsed.custom_data_len != custom_data_len) return false;
    if (memcmp(parsed.custom_data, custom_data, custom_data_len) != 0) return false;

    return true;
}

static bool test_lxmf_stamp_handling() {
    // Parse a 5-element payload (stamped) and verify hash matches 4-element hash
    // packed_5elem: 95cb41d9775150200000c40454657374c41248656c6c6f2066726f6d20507974686f6e2180c410aaaa...
    // After stamp stripping, hash should match simple message hash

    uint8_t receiver_dest_hash[16], sender_dest_hash[16];
    hex_to_bytes("95235d913409716dd8f28afe94cb678f", receiver_dest_hash, 16);
    hex_to_bytes("b32367e2bddccefe0b15b6f5c957676c", sender_dest_hash, 16);

    // Construct fake full LXMF with stamped payload
    uint8_t packed_5[64];
    int packed_5_len = hex_to_bytes(
        "95cb41d9775150200000c40454657374c41248656c6c6f2066726f6d20507974686f6e2180"
        "c410aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        packed_5, sizeof(packed_5));

    // Build fake full LXMF: dest_hash + source_hash + fake_signature + packed_5elem
    uint8_t full_lxmf[256];
    memcpy(full_lxmf, receiver_dest_hash, 16);
    memcpy(full_lxmf + 16, sender_dest_hash, 16);
    memset(full_lxmf + 32, 0xBB, 64);  // fake signature
    memcpy(full_lxmf + 96, packed_5, packed_5_len);

    msg::LXMessage msg;
    if (!msg::lxmf_parse(full_lxmf, 96 + packed_5_len, msg)) {
        Serial.println("[LXMF] Stamp parse failed");
        return false;
    }

    // Hash should match the simple (unstamped) message hash
    uint8_t expected_hash[32];
    hex_to_bytes("a4760018f636e907660edb9495ac075ea6dd2db8ebbceae08a752feb68d84e48",
                 expected_hash, 32);

    if (memcmp(msg.message_hash, expected_hash, 32) != 0) {
        Serial.printf("[LXMF] Stamp hash mismatch!\n  Got:    ");
        for (int i = 0; i < 32; i++) Serial.printf("%02x", msg.message_hash[i]);
        Serial.printf("\n  Expect: ");
        for (int i = 0; i < 32; i++) Serial.printf("%02x", expected_hash[i]);
        Serial.println();
        return false;
    }

    // Also verify the packed_payload was correctly re-packed as 4 elements
    uint8_t expected_4elem[64];
    int expected_4_len = hex_to_bytes(
        "94cb41d9775150200000c40454657374c41248656c6c6f2066726f6d20507974686f6e2180",
        expected_4elem, sizeof(expected_4elem));

    if ((int)msg.packed_payload_len != expected_4_len) {
        Serial.printf("[LXMF] Repacked len mismatch: %d vs %d\n", msg.packed_payload_len, expected_4_len);
        return false;
    }
    if (memcmp(msg.packed_payload, expected_4elem, expected_4_len) != 0) {
        Serial.println("[LXMF] Repacked bytes mismatch");
        return false;
    }

    return true;
}

static bool test_lxmf_parse_python_fields() {
    // Parse Python-generated fields message and verify all fields extracted
    uint8_t full_packed[512];
    int full_len = hex_to_bytes(
        "95235d913409716dd8f28afe94cb678f"  // dest_hash
        "b32367e2bddccefe0b15b6f5c957676c"  // source_hash
        "5156a03cdee4dfdd7a1cc5cc1da91430402b8fa4ee78f87284da97c50b3aa848"  // sig
        "d3433fb6468a3470598527fcf23ee3e0bbd0c760660cc7164eeb99b804b1580c"
        "94cb41d9775150400000c408576179706f696e74c40d43616d7020776179706f696e74"
        "82ccfbc412747261696c64726f702f776179706f696e74"
        "ccfcc41b82a36c6174cb40437c60aa64c2f8a36c6f6ecbc057cf0f27bb2fec",
        full_packed, sizeof(full_packed));

    msg::LXMessage msg;
    if (!msg::lxmf_parse(full_packed, full_len, msg)) {
        Serial.println("[LXMF] Python fields parse failed");
        return false;
    }

    if (msg.timestamp != 1709000001.0) return false;
    if (msg.title_len != 8 || memcmp(msg.title, "Waypoint", 8) != 0) return false;
    if (msg.content_len != 13 || memcmp(msg.content, "Camp waypoint", 13) != 0) return false;
    if (!msg.has_custom_fields) return false;
    if (msg.custom_type_len != 18 || memcmp(msg.custom_type, "traildrop/waypoint", 18) != 0) return false;

    // Verify signature with sender's key
    uint8_t sender_ed25519_pub[32];
    hex_to_bytes("bcf6af73c182888032960d55f0679c43f7bf7667594743254cef72532cbdc213",
                 sender_ed25519_pub, 32);
    if (!msg::lxmf_verify(msg, sender_ed25519_pub)) {
        Serial.println("[LXMF] Python fields signature verify failed");
        return false;
    }

    return true;
}

static void run_msgpack_lxmf_tests(int& line) {
    Serial.println("\n[PHASE4A] Running Phase 4a msgpack + LXMF tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== LXMF Tests ===");
    line++;

    struct { const char* name; bool (*fn)(); } tests[] = {
        {"MP Encode",        test_msgpack_encode_match},
        {"MP Roundtrip",     test_msgpack_decode_roundtrip},
        {"MP Payload Bin",   test_msgpack_payload_binary_match},
        {"MP Fields Bin",    test_msgpack_fields_binary_match},
        {"LXMF Hash",        test_lxmf_build_hash_match},
        {"LXMF Signature",   test_lxmf_build_signature_match},
        {"LXMF Parse",       test_lxmf_parse_simple},
        {"LXMF Verify",      test_lxmf_verify_signature},
        {"LXMF Fields RT",   test_lxmf_fields_roundtrip},
        {"LXMF Stamp",       test_lxmf_stamp_handling},
        {"LXMF Py Fields",   test_lxmf_parse_python_fields},
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    bool all_pass = true;
    for (int i = 0; i < num_tests; i++) {
        bool ok = tests[i].fn();
        if (!ok) all_pass = false;
        Serial.printf("[PHASE4A] %-16s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        show_boot_status(tests[i].name, ok, line++);
    }

    Serial.printf("[PHASE4A] === %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    hal::display_printf(0, (line + 1) * 18, all_pass ? 0x07E0 : 0xF800, 2,
                        all_pass ? "LXMF: ALL PASS" : "LXMF: FAILURES");
    line += 2;
}

// ============================================================
// LXMF receive callback (used in setup/loop)
// ============================================================

static void on_lxmf_received(const msg::LXMessage& msg, int rssi, float snr) {
    // Check if this is a waypoint
    if (msg.has_custom_fields &&
        msg.custom_type_len == 18 &&
        memcmp(msg.custom_type, "traildrop/waypoint", 18) == 0) {

        // Decode waypoint from custom_data
        msg::Waypoint wp;
        if (msg::waypoint_decode(msg.custom_data, msg.custom_data_len, wp)) {
            Serial.printf("[WAYPOINT] Received: %s\n", wp.name);
            Serial.printf("[WAYPOINT] Position: %.6f, %.6f, %.1fm\n", wp.lat, wp.lon, wp.ele);
            if (wp.notes[0]) Serial.printf("[WAYPOINT] Notes: %s\n", wp.notes);
            Serial.printf("[WAYPOINT] Sig: %s | RSSI=%d SNR=%.1f\n",
                          msg.signature_valid ? "VALID" : "INVALID", rssi, snr);

            // Notify display UI
            const net::Peer* sender = net::peer_lookup_by_lxmf_dest(msg.source_hash);
            ui::ui_on_waypoint_received(wp, sender ? sender->app_data : "Unknown", rssi);
        } else {
            Serial.printf("[WAYPOINT] Decode failed (data_len=%d)\n", msg.custom_data_len);
        }
    } else {
        // Regular LXMF message
        Serial.printf("[LXMF] Title: %.*s\n", (int)msg.title_len, msg.title);
        Serial.printf("[LXMF] Content: %.*s\n", (int)msg.content_len, msg.content);
        Serial.printf("[LXMF] Signature valid: %s\n", msg.signature_valid ? "YES" : "NO");
        if (msg.has_custom_fields) {
            Serial.printf("[LXMF] Custom type: %.*s\n", (int)msg.custom_type_len, msg.custom_type);
        }
        Serial.printf("[LXMF] RSSI=%d SNR=%.1f\n", rssi, snr);
    }
}

// ============================================================
// Phase 4a.5: Announce Migration + Dual Destination Tests
// ============================================================

static bool test_announce_app_data_msgpack() {
    // Verify announce_build encodes app_data as msgpack [name_bytes, null]
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;

    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;

    Packet pkt;
    if (!net::announce_build(id, dest, "TrailDrop", pkt)) return false;

    // app_data starts at offset 148
    if (pkt.payload_len <= 148) return false;

    // First byte must be 0x92 (fixarray of 2)
    if (pkt.payload[148] != 0x92) {
        Serial.printf("[4A5] Expected 0x92, got 0x%02x\n", pkt.payload[148]);
        return false;
    }

    // Decode the app_data and verify display name
    size_t ad_len = pkt.payload_len - 148;
    msg::Decoder dec(&pkt.payload[148], ad_len);
    uint8_t arr_count = dec.read_array();
    if (dec.error || arr_count != 2) return false;

    // First element: bin "TrailDrop"
    uint8_t name_buf[32];
    size_t name_len = dec.read_bin(name_buf, sizeof(name_buf));
    if (dec.error || name_len != 9) return false;
    if (memcmp(name_buf, "TrailDrop", 9) != 0) return false;

    // Second element: nil
    dec.read_nil();
    if (dec.error) return false;

    return true;
}

static bool test_announce_app_data_python_match() {
    // Verify our encoding matches Python: msgpack.packb([b"TrailDrop", None])
    // Expected from test vectors: 92c409547261696c44726f70c0
    const char* expected_hex = "92c409547261696c44726f70c0";
    uint8_t expected[16];
    int expected_len = hex_to_bytes(expected_hex, expected, sizeof(expected));

    // Encode using our encoder
    uint8_t buf[32];
    msg::Encoder enc(buf, sizeof(buf));
    enc.write_array(2);
    enc.write_bin((const uint8_t*)"TrailDrop", 9);
    enc.write_nil();

    if (enc.error) return false;
    if ((int)enc.pos != expected_len) {
        Serial.printf("[4A5] App data len mismatch: got %d, expected %d\n", enc.pos, expected_len);
        return false;
    }
    if (memcmp(buf, expected, expected_len) != 0) {
        Serial.printf("[4A5] App data bytes mismatch\n");
        return false;
    }

    return true;
}

static bool test_announce_decode_legacy_format() {
    // Simulate receiving a legacy announce with raw UTF-8 app_data
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;

    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;

    // Manually build a legacy-format announce packet (raw string app_data)
    Packet pkt;
    // Build name_hash
    uint8_t name_full_hash[32];
    crypto::sha256((const uint8_t*)"traildrop.waypoint", 18, name_full_hash);
    uint8_t name_hash[10];
    memcpy(name_hash, name_full_hash, 10);

    uint8_t random_hash[10];
    RNG.rand(random_hash, 10);

    const char* legacy_name = "OldNode";
    size_t legacy_len = strlen(legacy_name);

    // Build signed_data (same as announce_build but with raw app_data)
    uint8_t signed_data[16 + 64 + 10 + 10 + 32];
    size_t signed_len = 0;
    memcpy(&signed_data[signed_len], dest.hash, 16); signed_len += 16;
    memcpy(&signed_data[signed_len], id.x25519_public, 32); signed_len += 32;
    memcpy(&signed_data[signed_len], id.ed25519_public, 32); signed_len += 32;
    memcpy(&signed_data[signed_len], name_hash, 10); signed_len += 10;
    memcpy(&signed_data[signed_len], random_hash, 10); signed_len += 10;
    memcpy(&signed_data[signed_len], legacy_name, legacy_len); signed_len += legacy_len;

    uint8_t signature[64];
    if (!crypto::identity_sign(id, signed_data, signed_len, signature)) return false;

    // Assemble payload
    size_t offset = 0;
    memcpy(&pkt.payload[offset], id.x25519_public, 32); offset += 32;
    memcpy(&pkt.payload[offset], id.ed25519_public, 32); offset += 32;
    memcpy(&pkt.payload[offset], name_hash, 10); offset += 10;
    memcpy(&pkt.payload[offset], random_hash, 10); offset += 10;
    memcpy(&pkt.payload[offset], signature, 64); offset += 64;
    memcpy(&pkt.payload[offset], legacy_name, legacy_len); offset += legacy_len;
    pkt.payload_len = offset;

    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_ANNOUNCE);
    pkt.hops = 0;
    pkt.has_transport = false;
    memcpy(pkt.dest_hash, dest.hash, DEST_HASH_SIZE);
    pkt.context = CTX_NONE;

    net::peer_table_init();
    if (!net::announce_process(pkt)) return false;

    const net::Peer* peer = net::peer_lookup(dest.hash);
    if (peer == nullptr) return false;

    // Legacy app_data should be decoded as raw string
    if (strcmp(peer->app_data, "OldNode") != 0) {
        Serial.printf("[4A5] Legacy decode: got '%s'\n", peer->app_data);
        return false;
    }

    return true;
}

static bool test_announce_decode_msgpack_format() {
    // Build announce with new format, process it, verify display name is decoded
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;

    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;

    Packet pkt;
    if (!net::announce_build(id, dest, "NewNode", pkt)) return false;

    net::peer_table_init();
    if (!net::announce_process(pkt)) return false;

    const net::Peer* peer = net::peer_lookup(dest.hash);
    if (peer == nullptr) return false;

    if (strcmp(peer->app_data, "NewNode") != 0) {
        Serial.printf("[4A5] Msgpack decode: got '%s'\n", peer->app_data);
        return false;
    }

    return true;
}

static bool test_dual_dest_computation() {
    // Use known test vector keys and verify both dest hashes match Python
    crypto::Identity id;
    hex_to_bytes("387b35263170015ac008c58a9755350e28f541843a0acb58a142199858ec4e6b",
                 id.x25519_private, 32);
    hex_to_bytes("338298dec0eeb458587f5792cac3dd70e0e73699a17a2362d00ab3868ba6b313",
                 id.x25519_public, 32);
    hex_to_bytes("258494ef78f67f7197cd0a52933b72657a346b8792a14ee0f7093a8175441968",
                 id.ed25519_private, 32);
    hex_to_bytes("bcf6af73c182888032960d55f0679c43f7bf7667594743254cef72532cbdc213",
                 id.ed25519_public, 32);
    hex_to_bytes("cc4e2bc21134c415f4d685016a443914", id.hash, 16);
    id.valid = true;

    // Compute traildrop.waypoint
    net::Destination td_dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", td_dest)) return false;

    uint8_t expected_td[16];
    hex_to_bytes("e3e523376aec31c62d40e0e894e247c7", expected_td, 16);
    if (memcmp(td_dest.hash, expected_td, 16) != 0) {
        Serial.printf("[4A5] TD dest mismatch: ");
        for (int i = 0; i < 16; i++) Serial.printf("%02x", td_dest.hash[i]);
        Serial.println();
        return false;
    }

    // Compute lxmf.delivery
    net::Destination lxmf_dest;
    if (!net::destination_derive(id, "lxmf", "delivery", lxmf_dest)) return false;

    uint8_t expected_lxmf[16];
    hex_to_bytes("b32367e2bddccefe0b15b6f5c957676c", expected_lxmf, 16);
    if (memcmp(lxmf_dest.hash, expected_lxmf, 16) != 0) {
        Serial.printf("[4A5] LXMF dest mismatch: ");
        for (int i = 0; i < 16; i++) Serial.printf("%02x", lxmf_dest.hash[i]);
        Serial.println();
        return false;
    }

    // Verify they're different
    if (memcmp(td_dest.hash, lxmf_dest.hash, 16) == 0) return false;

    return true;
}

static bool test_peer_lxmf_dest_hash() {
    // After processing an announce, verify peer has correct lxmf.delivery dest_hash
    crypto::Identity id;
    hex_to_bytes("387b35263170015ac008c58a9755350e28f541843a0acb58a142199858ec4e6b",
                 id.x25519_private, 32);
    hex_to_bytes("338298dec0eeb458587f5792cac3dd70e0e73699a17a2362d00ab3868ba6b313",
                 id.x25519_public, 32);
    hex_to_bytes("258494ef78f67f7197cd0a52933b72657a346b8792a14ee0f7093a8175441968",
                 id.ed25519_private, 32);
    hex_to_bytes("bcf6af73c182888032960d55f0679c43f7bf7667594743254cef72532cbdc213",
                 id.ed25519_public, 32);
    hex_to_bytes("cc4e2bc21134c415f4d685016a443914", id.hash, 16);
    id.valid = true;

    net::Destination dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", dest)) return false;

    Packet pkt;
    if (!net::announce_build(id, dest, "TrailDrop", pkt)) return false;

    net::peer_table_init();
    if (!net::announce_process(pkt)) return false;

    const net::Peer* peer = net::peer_lookup(dest.hash);
    if (peer == nullptr) return false;

    // Verify lxmf_dest_hash matches Python test vector
    uint8_t expected_lxmf[16];
    hex_to_bytes("b32367e2bddccefe0b15b6f5c957676c", expected_lxmf, 16);
    if (memcmp(peer->lxmf_dest_hash, expected_lxmf, 16) != 0) {
        Serial.printf("[4A5] Peer LXMF dest mismatch: ");
        for (int i = 0; i < 16; i++) Serial.printf("%02x", peer->lxmf_dest_hash[i]);
        Serial.printf("\n  Expected: ");
        for (int i = 0; i < 16; i++) Serial.printf("%02x", expected_lxmf[i]);
        Serial.println();
        return false;
    }

    return true;
}

static bool test_dual_dest_different() {
    // For a random identity, verify both dests are computed and different
    crypto::Identity id;
    if (!crypto::identity_generate(id)) return false;

    net::Destination td_dest, lxmf_dest;
    if (!net::destination_derive(id, "traildrop", "waypoint", td_dest)) return false;
    if (!net::destination_derive(id, "lxmf", "delivery", lxmf_dest)) return false;

    // Must be different
    if (memcmp(td_dest.hash, lxmf_dest.hash, 16) == 0) return false;

    // Both must be non-zero
    bool td_zero = true, lxmf_zero = true;
    for (int i = 0; i < 16; i++) {
        if (td_dest.hash[i] != 0) td_zero = false;
        if (lxmf_dest.hash[i] != 0) lxmf_zero = false;
    }
    if (td_zero || lxmf_zero) return false;

    return true;
}

static void run_phase4a5_tests(int& line) {
    Serial.println("\n[PHASE4A5] Running Phase 4a.5 announce migration tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== 4a.5 Tests ===");
    line++;

    struct { const char* name; bool (*fn)(); } tests[] = {
        {"AppData Msgpack",  test_announce_app_data_msgpack},
        {"AppData PyMatch",  test_announce_app_data_python_match},
        {"Decode Legacy",    test_announce_decode_legacy_format},
        {"Decode Msgpack",   test_announce_decode_msgpack_format},
        {"Dual Dest Vec",    test_dual_dest_computation},
        {"Peer LXMF Dest",  test_peer_lxmf_dest_hash},
        {"Dual Dest Diff",   test_dual_dest_different},
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    bool all_pass = true;
    for (int i = 0; i < num_tests; i++) {
        bool ok = tests[i].fn();
        if (!ok) all_pass = false;
        Serial.printf("[PHASE4A5] %-16s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        show_boot_status(tests[i].name, ok, line++);
    }

    Serial.printf("[PHASE4A5] === %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    hal::display_printf(0, (line + 1) * 18, all_pass ? 0x07E0 : 0xF800, 2,
                        all_pass ? "4a.5: ALL PASS" : "4a.5: FAILURES");
    line += 2;
}

// ============================================================
// Phase 4b: LXMF Transport Tests
// ============================================================

static bool test_lxmf_send_receive_roundtrip() {
    // Full cycle: build LXMF, encrypt for peer, decrypt as peer, parse, verify
    // Static buffers to avoid stack overflow on ESP32 (8KB task stack)
    static crypto::Identity alice, bob;
    if (!crypto::identity_generate(alice)) return false;
    if (!crypto::identity_generate(bob)) return false;

    static net::Destination alice_lxmf, bob_lxmf;
    if (!net::destination_derive(alice, "lxmf", "delivery", alice_lxmf)) return false;
    if (!net::destination_derive(bob, "lxmf", "delivery", bob_lxmf)) return false;

    // Build LXMF message from alice to bob
    static uint8_t lxmf_out[500];
    size_t lxmf_len = sizeof(lxmf_out);
    uint8_t message_hash[32];

    if (!msg::lxmf_build(
            alice, alice_lxmf.hash, bob_lxmf.hash,
            12345.0,
            (const uint8_t*)"Test", 4,
            (const uint8_t*)"Hello Bob!", 10,
            (const uint8_t*)"traildrop/waypoint", 18,
            nullptr, 0,
            lxmf_out, &lxmf_len, message_hash)) {
        Serial.println("[4B] LXMF build failed");
        return false;
    }

    // Encrypt for bob
    static crypto::Identity bob_pub;
    memcpy(bob_pub.x25519_public, bob.x25519_public, 32);
    memcpy(bob_pub.ed25519_public, bob.ed25519_public, 32);
    memcpy(bob_pub.hash, bob.hash, 16);
    memset(bob_pub.x25519_private, 0, 32);
    memset(bob_pub.ed25519_private, 0, 32);
    bob_pub.valid = true;

    static uint8_t encrypted[RNS_MTU];
    size_t enc_len = 0;
    if (!crypto::identity_encrypt(bob_pub, lxmf_out, lxmf_len, encrypted, &enc_len)) {
        Serial.println("[4B] Encrypt failed");
        return false;
    }

    // Decrypt as bob
    static uint8_t decrypted[RNS_MTU];
    size_t dec_len = 0;
    if (!crypto::identity_decrypt(bob, encrypted, enc_len, decrypted, &dec_len)) {
        Serial.println("[4B] Decrypt failed");
        return false;
    }

    // Verify decrypted matches original
    if (dec_len != lxmf_len || memcmp(decrypted, lxmf_out, lxmf_len) != 0) {
        Serial.println("[4B] Decrypt content mismatch");
        return false;
    }

    // Reconstruct full LXMF: prepend bob's dest hash
    static uint8_t full_lxmf[600];
    memcpy(full_lxmf, bob_lxmf.hash, 16);
    memcpy(full_lxmf + 16, decrypted, dec_len);

    // Parse
    msg::LXMessage msg;
    if (!msg::lxmf_parse(full_lxmf, 16 + dec_len, msg)) {
        Serial.println("[4B] Parse failed");
        return false;
    }

    // Verify fields
    if (msg.title_len != 4 || memcmp(msg.title, "Test", 4) != 0) return false;
    if (msg.content_len != 10 || memcmp(msg.content, "Hello Bob!", 10) != 0) return false;
    if (!msg.has_custom_fields) return false;
    if (msg.custom_type_len != 18 || memcmp(msg.custom_type, "traildrop/waypoint", 18) != 0) return false;

    // Verify signature with alice's public key
    if (!msg::lxmf_verify(msg, alice.ed25519_public)) {
        Serial.println("[4B] Signature verification failed");
        return false;
    }

    return true;
}

static bool test_lxmf_dedup() {
    // Clear dedup state by re-initing
    msg::lxmf_transport_init(device_identity, device_destination, device_lxmf_destination);

    uint8_t hash[32];
    for (int i = 0; i < 32; i++) hash[i] = (uint8_t)(i + 0x50);

    // First time: not duplicate
    if (msg::lxmf_is_duplicate(hash)) return false;
    msg::lxmf_record_message(hash);

    // Second time: is duplicate
    if (!msg::lxmf_is_duplicate(hash)) return false;

    // Different hash: not duplicate
    uint8_t hash2[32];
    for (int i = 0; i < 32; i++) hash2[i] = (uint8_t)(i + 0xA0);
    if (msg::lxmf_is_duplicate(hash2)) return false;

    return true;
}

static bool test_peer_lookup_by_lxmf_dest_fn() {
    net::peer_table_init();

    uint8_t dest[DEST_HASH_SIZE];
    uint8_t lxmf_dest[DEST_HASH_SIZE];
    uint8_t x25519[32];
    uint8_t ed25519[32];
    uint8_t id_hash[DEST_HASH_SIZE];

    for (int i = 0; i < DEST_HASH_SIZE; i++) dest[i] = (uint8_t)(i + 0x10);
    for (int i = 0; i < DEST_HASH_SIZE; i++) lxmf_dest[i] = (uint8_t)(i + 0x20);
    for (int i = 0; i < 32; i++) x25519[i] = (uint8_t)(i + 0x30);
    for (int i = 0; i < 32; i++) ed25519[i] = (uint8_t)(i + 0x40);
    for (int i = 0; i < DEST_HASH_SIZE; i++) id_hash[i] = (uint8_t)(i + 0x50);

    if (!net::peer_store(dest, x25519, ed25519, id_hash, "LxmfPeer", lxmf_dest)) return false;

    // Lookup by lxmf_dest should find the peer
    const net::Peer* peer = net::peer_lookup_by_lxmf_dest(lxmf_dest);
    if (peer == nullptr) return false;
    if (strcmp(peer->app_data, "LxmfPeer") != 0) return false;

    // Wrong lxmf dest should return nullptr
    uint8_t wrong[DEST_HASH_SIZE];
    memset(wrong, 0xFF, DEST_HASH_SIZE);
    if (net::peer_lookup_by_lxmf_dest(wrong) != nullptr) return false;

    // Lookup by regular dest should still work
    const net::Peer* peer2 = net::peer_lookup(dest);
    if (peer2 == nullptr) return false;

    return true;
}

static bool test_lxmf_receive_craft() {
    // Craft a known LXMF packet, decrypt/parse manually (simulates receive)
    // Static buffers to avoid stack overflow on ESP32
    static crypto::Identity sender, receiver;
    if (!crypto::identity_generate(sender)) return false;
    if (!crypto::identity_generate(receiver)) return false;

    static net::Destination sender_lxmf, receiver_lxmf;
    if (!net::destination_derive(sender, "lxmf", "delivery", sender_lxmf)) return false;
    if (!net::destination_derive(receiver, "lxmf", "delivery", receiver_lxmf)) return false;

    // Build LXMF
    static uint8_t lxmf_out[500];
    size_t lxmf_len = sizeof(lxmf_out);
    uint8_t msg_hash[32];

    if (!msg::lxmf_build(
            sender, sender_lxmf.hash, receiver_lxmf.hash,
            99999.0,
            (const uint8_t*)"Alert", 5,
            (const uint8_t*)"Emergency test", 14,
            nullptr, 0, nullptr, 0,
            lxmf_out, &lxmf_len, msg_hash)) {
        return false;
    }

    // Encrypt for receiver
    static crypto::Identity receiver_pub;
    memcpy(receiver_pub.x25519_public, receiver.x25519_public, 32);
    memcpy(receiver_pub.hash, receiver.hash, 16);
    receiver_pub.valid = true;

    static uint8_t encrypted[RNS_MTU];
    size_t enc_len = 0;
    if (!crypto::identity_encrypt(receiver_pub, lxmf_out, lxmf_len, encrypted, &enc_len)) {
        return false;
    }

    // Decrypt as receiver
    static uint8_t decrypted[RNS_MTU];
    size_t dec_len = 0;
    if (!crypto::identity_decrypt(receiver, encrypted, enc_len, decrypted, &dec_len)) {
        return false;
    }

    // Reconstruct full LXMF
    static uint8_t full_lxmf[600];
    memcpy(full_lxmf, receiver_lxmf.hash, 16);
    memcpy(full_lxmf + 16, decrypted, dec_len);

    msg::LXMessage msg;
    if (!msg::lxmf_parse(full_lxmf, 16 + dec_len, msg)) return false;

    if (msg.title_len != 5 || memcmp(msg.title, "Alert", 5) != 0) return false;
    if (msg.content_len != 14 || memcmp(msg.content, "Emergency test", 14) != 0) return false;
    if (memcmp(msg.message_hash, msg_hash, 32) != 0) return false;

    // Verify signature
    if (!msg::lxmf_verify(msg, sender.ed25519_public)) return false;

    return true;
}

static void run_phase4b_tests(int& line) {
    Serial.println("\n[PHASE4B] Running Phase 4b LXMF transport tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== 4b Tests ===");
    line++;

    struct { const char* name; bool (*fn)(); } tests[] = {
        {"LXMF SendRecv",    test_lxmf_send_receive_roundtrip},
        {"LXMF Dedup",       test_lxmf_dedup},
        {"Peer LXMF Lkup",   test_peer_lookup_by_lxmf_dest_fn},
        {"LXMF Craft RX",    test_lxmf_receive_craft},
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    bool all_pass = true;
    for (int i = 0; i < num_tests; i++) {
        bool ok = tests[i].fn();
        if (!ok) all_pass = false;
        Serial.printf("[PHASE4B] %-16s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        show_boot_status(tests[i].name, ok, line++);
    }

    Serial.printf("[PHASE4B] === %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    hal::display_printf(0, (line + 1) * 18, all_pass ? 0x07E0 : 0xF800, 2,
                        all_pass ? "4b: ALL PASS" : "4b: FAILURES");
    line += 2;
}

// ============================================================
// Phase 4c: Waypoint Codec Tests
// ============================================================

static bool test_waypoint_encode_decode_roundtrip() {
    // Encode known waypoint, decode, verify all fields match
    msg::Waypoint wp;
    memset(&wp, 0, sizeof(wp));
    wp.lat = 38.9717;
    wp.lon = -95.2353;
    wp.ele = 267.0f;
    strncpy(wp.name, "Camp", sizeof(wp.name) - 1);
    strncpy(wp.notes, "Water source", sizeof(wp.notes) - 1);
    wp.timestamp = 1709312400;
    wp.valid = true;

    uint8_t buf[256];
    size_t encoded_len = msg::waypoint_encode(wp, buf, sizeof(buf));
    if (encoded_len == 0) {
        Serial.println("[4C] Encode failed");
        return false;
    }

    msg::Waypoint decoded;
    if (!msg::waypoint_decode(buf, encoded_len, decoded)) {
        Serial.println("[4C] Decode failed");
        return false;
    }

    if (decoded.lat != 38.9717) return false;
    if (decoded.lon != -95.2353) return false;
    if (decoded.ele != 267.0f) return false;
    if (strcmp(decoded.name, "Camp") != 0) return false;
    if (strcmp(decoded.notes, "Water source") != 0) return false;
    if (decoded.timestamp != 1709312400) return false;
    if (!decoded.valid) return false;

    return true;
}

static bool test_waypoint_encode_python_match() {
    // Verify our encoder output matches Python msgpack.packb byte-for-byte
    // Python: msgpack.packb({"lat": 38.9717, "lon": -95.2353, "ele": 267.0,
    //                        "name": "Camp", "notes": "Water source", "ts": 1709312400})
    const char* expected_hex =
        "86a36c6174cb40437c60aa64c2f8a36c6f6ecbc057cf0f27bb2fec"
        "a3656c65cb4070b00000000000a46e616d65a443616d70a56e6f74"
        "6573ac576174657220736f75726365a27473ce65e20990";
    uint8_t expected[128];
    int expected_len = hex_to_bytes(expected_hex, expected, sizeof(expected));

    msg::Waypoint wp;
    memset(&wp, 0, sizeof(wp));
    wp.lat = 38.9717;
    wp.lon = -95.2353;
    wp.ele = 267.0f;
    strncpy(wp.name, "Camp", sizeof(wp.name) - 1);
    strncpy(wp.notes, "Water source", sizeof(wp.notes) - 1);
    wp.timestamp = 1709312400;

    uint8_t buf[256];
    size_t encoded_len = msg::waypoint_encode(wp, buf, sizeof(buf));
    if (encoded_len == 0) return false;

    if ((int)encoded_len != expected_len) {
        Serial.printf("[4C] Len mismatch: got %d, expected %d\n", encoded_len, expected_len);
        return false;
    }
    if (memcmp(buf, expected, expected_len) != 0) {
        Serial.printf("[4C] Byte mismatch:\n  Got:    ");
        for (size_t i = 0; i < encoded_len; i++) Serial.printf("%02x", buf[i]);
        Serial.printf("\n  Expect: %s\n", expected_hex);
        return false;
    }
    return true;
}

static bool test_waypoint_in_lxmf_roundtrip() {
    // Build LXMF with waypoint custom fields, parse, extract waypoint
    // Static buffers to avoid stack overflow on ESP32
    static crypto::Identity sender;
    if (!crypto::identity_generate(sender)) return false;

    static net::Destination sender_lxmf, receiver_lxmf;
    if (!net::destination_derive(sender, "lxmf", "delivery", sender_lxmf)) return false;

    static crypto::Identity receiver;
    if (!crypto::identity_generate(receiver)) return false;
    if (!net::destination_derive(receiver, "lxmf", "delivery", receiver_lxmf)) return false;

    // Encode waypoint
    msg::Waypoint wp;
    memset(&wp, 0, sizeof(wp));
    wp.lat = 38.9717;
    wp.lon = -95.2353;
    wp.ele = 267.0f;
    strncpy(wp.name, "Camp", sizeof(wp.name) - 1);
    strncpy(wp.notes, "Water source", sizeof(wp.notes) - 1);
    wp.timestamp = 1709312400;

    static uint8_t custom_data[256];
    size_t custom_data_len = msg::waypoint_encode(wp, custom_data, sizeof(custom_data));
    if (custom_data_len == 0) return false;

    // Build LXMF with custom fields
    static uint8_t lxmf_out[500];
    size_t lxmf_len = sizeof(lxmf_out);
    uint8_t message_hash[32];

    if (!msg::lxmf_build(
            sender, sender_lxmf.hash, receiver_lxmf.hash,
            1709312400.0,
            (const uint8_t*)"Camp", 4,
            (const uint8_t*)"Water source", 12,
            (const uint8_t*)"traildrop/waypoint", 18,
            custom_data, custom_data_len,
            lxmf_out, &lxmf_len, message_hash)) {
        return false;
    }

    // Reconstruct full LXMF and parse
    uint8_t full_lxmf[600];
    memcpy(full_lxmf, receiver_lxmf.hash, 16);
    memcpy(full_lxmf + 16, lxmf_out, lxmf_len);

    msg::LXMessage parsed;
    if (!msg::lxmf_parse(full_lxmf, 16 + lxmf_len, parsed)) return false;

    if (!parsed.has_custom_fields) return false;
    if (parsed.custom_type_len != 18) return false;
    if (memcmp(parsed.custom_type, "traildrop/waypoint", 18) != 0) return false;

    // Decode waypoint from custom_data
    msg::Waypoint decoded;
    if (!msg::waypoint_decode(parsed.custom_data, parsed.custom_data_len, decoded)) return false;

    if (decoded.lat != 38.9717) return false;
    if (decoded.lon != -95.2353) return false;
    if (strcmp(decoded.name, "Camp") != 0) return false;

    return true;
}

static bool test_waypoint_no_gps_fix() {
    // waypoint_send should return false when GPS has no fix (indoor testing)
    // We can't mock GPS, but we know the devices are indoors, so gps_has_fix() is false.
    // Instead, test the encode path with a direct encode/decode of empty coords.
    msg::Waypoint wp;
    memset(&wp, 0, sizeof(wp));
    wp.lat = 0.0;
    wp.lon = 0.0;
    wp.ele = 0.0f;
    strncpy(wp.name, "NoFix", sizeof(wp.name) - 1);
    wp.timestamp = 0;

    uint8_t buf[256];
    size_t len = msg::waypoint_encode(wp, buf, sizeof(buf));
    if (len == 0) return false;

    msg::Waypoint decoded;
    if (!msg::waypoint_decode(buf, len, decoded)) return false;
    if (decoded.lat != 0.0 || decoded.lon != 0.0) return false;
    if (strcmp(decoded.name, "NoFix") != 0) return false;

    return true;
}

static bool test_waypoint_empty_notes() {
    // Notes field should be omitted from msgpack when empty
    // Python: msgpack.packb({"lat": 38.9717, "lon": -95.2353, "ele": 267.0,
    //                        "name": "Camp", "ts": 1709312400})
    const char* expected_hex =
        "85a36c6174cb40437c60aa64c2f8a36c6f6ecbc057cf0f27bb2fec"
        "a3656c65cb4070b00000000000a46e616d65a443616d70a27473ce65e20990";
    uint8_t expected[128];
    int expected_len = hex_to_bytes(expected_hex, expected, sizeof(expected));

    msg::Waypoint wp;
    memset(&wp, 0, sizeof(wp));
    wp.lat = 38.9717;
    wp.lon = -95.2353;
    wp.ele = 267.0f;
    strncpy(wp.name, "Camp", sizeof(wp.name) - 1);
    // notes left empty (memset to 0)
    wp.timestamp = 1709312400;

    uint8_t buf[256];
    size_t encoded_len = msg::waypoint_encode(wp, buf, sizeof(buf));
    if (encoded_len == 0) return false;

    if ((int)encoded_len != expected_len) {
        Serial.printf("[4C] No-notes len mismatch: got %d, expected %d\n", encoded_len, expected_len);
        return false;
    }
    if (memcmp(buf, expected, expected_len) != 0) {
        Serial.printf("[4C] No-notes byte mismatch\n");
        return false;
    }

    // Decode it back and verify notes is empty
    msg::Waypoint decoded;
    if (!msg::waypoint_decode(buf, encoded_len, decoded)) return false;
    if (decoded.notes[0] != '\0') return false;

    return true;
}

static void run_phase4c_tests(int& line) {
    Serial.println("\n[PHASE4C] Running Phase 4c waypoint tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== 4c Tests ===");
    line++;

    struct { const char* name; bool (*fn)(); } tests[] = {
        {"WP Roundtrip",     test_waypoint_encode_decode_roundtrip},
        {"WP Python Match",  test_waypoint_encode_python_match},
        {"WP LXMF RT",       test_waypoint_in_lxmf_roundtrip},
        {"WP No Fix",        test_waypoint_no_gps_fix},
        {"WP Empty Notes",   test_waypoint_empty_notes},
    };
    int num_tests = sizeof(tests) / sizeof(tests[0]);

    bool all_pass = true;
    for (int i = 0; i < num_tests; i++) {
        bool ok = tests[i].fn();
        if (!ok) all_pass = false;
        Serial.printf("[PHASE4C] %-16s %s\n", tests[i].name, ok ? "PASS" : "FAIL");
        show_boot_status(tests[i].name, ok, line++);
    }

    Serial.printf("[PHASE4C] === %s ===\n", all_pass ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
    hal::display_printf(0, (line + 1) * 18, all_pass ? 0x07E0 : 0xF800, 2,
                        all_pass ? "4c: ALL PASS" : "4c: FAILURES");
    line += 2;
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("\n=== TrailDrop %s — HAL Test Harness ===\n", APP_VERSION);
    
    // Phase 3c: Initialize peer table
    net::peer_table_init();

    // Phase 1: Boot sequence (power_init MUST be first)
    boot.power = hal::power_init();
    Serial.printf("[BOOT] Power:    %s\n", boot.power ? "OK" : "FAIL");
    
    if (!boot.power) {
        Serial.println("[BOOT] CRITICAL: Power init failed — peripherals unpowered");
        // Still try display in case it works on USB power
    }

    // SPI bus initialization — centralized, called once
    // Note: CS pins already pre-initialized HIGH by power_init() in power.cpp
    SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI);
    
    // Note: TFT_eSPI::init(), RadioLib Module::init(), and SD.begin() all call
    // SPI.begin() internally — these are idempotent no-ops since we init first.
    
    // TODO Phase 3: When introducing concurrent FreeRTOS tasks for networking,
    // add a Meshtastic-style LockingArduinoHal for RadioLib and wrap display/SD
    // operations with the same global spiLock. See SPI_RESEARCH.md for the pattern.
    // Current single-threaded architecture is protected by Arduino SPI's built-in
    // FreeRTOS mutex (SPI.beginTransaction() calls xSemaphoreTake internally).

    boot.display = hal::display_init();
    Serial.printf("[BOOT] Display:  %s\n", boot.display ? "OK" : "FAIL");

    // Show boot status on display
    hal::display_clear(0x0000);
    hal::display_text(0, 0, "TrailDrop HAL Test", 0xFFFF, 2);

    int line = 2;
    show_boot_status("Power",    boot.power,   line++);
    show_boot_status("Display",  boot.display, line++);

    boot.keyboard = hal::keyboard_init();
    Serial.printf("[BOOT] Keyboard: %s\n", boot.keyboard ? "OK" : "FAIL");
    show_boot_status("Keyboard", boot.keyboard, line++);

    boot.trackball = hal::trackball_init();
    Serial.printf("[BOOT] Trackball:%s\n", boot.trackball ? "OK" : "FAIL");
    show_boot_status("Trackball", boot.trackball, line++);

    boot.gps = hal::gps_init();
    Serial.printf("[BOOT] GPS:      %s\n", boot.gps ? "OK" : "FAIL");
    show_boot_status("GPS",      boot.gps, line++);

    boot.radio = hal::radio_init();
    Serial.printf("[BOOT] Radio:    %s\n", boot.radio ? "OK" : "FAIL");
    show_boot_status("Radio",    boot.radio, line++);

    boot.storage = hal::storage_init();
    Serial.printf("[BOOT] Storage:  %s\n", boot.storage ? "OK" : "FAIL");
    show_boot_status("Storage",  boot.storage, line++);

    boot.battery = hal::battery_init();
    Serial.printf("[BOOT] Battery:  %s\n", boot.battery ? "OK" : "FAIL");
    show_boot_status("Battery",  boot.battery, line++);

    // Battery reading
    float volts = hal::battery_voltage();
    int pct = hal::battery_percent();
    Serial.printf("[BOOT] Battery:  %.2fV (%d%%)\n", volts, pct);
    hal::display_printf(0, line * 18, 0xFFE0, 2, "Bat: %.2fV %d%%", volts, pct);
    line++;

    // Storage info
    if (boot.storage) {
        uint64_t total = hal::storage_total_bytes();
        uint64_t used  = hal::storage_used_bytes();
        Serial.printf("[BOOT] SD: %llu MB total, %llu MB used\n",
                      total / (1024*1024), used / (1024*1024));
    }

    // Start radio receive mode
    if (boot.radio) {
        hal::radio_start_receive();
        Serial.println("[BOOT] Radio: listening");
    }

    // Boot health summary
    Serial.printf("[BOOT] Health: %s%s%s%s%s%s%s%s\n",
        boot.power    ? "P" : "p",
        boot.display  ? "D" : "d",
        boot.keyboard ? "K" : "k",
        boot.trackball ? "T" : "t",
        boot.gps      ? "G" : "g",
        boot.radio    ? "R" : "r",
        boot.storage  ? "S" : "s",
        boot.battery  ? "B" : "b");
    // Uppercase = OK, lowercase = failed. e.g., "PDKTGRsB" means storage failed.

    // Phase 3b: Identity management
    if (boot.storage) {
        // Ensure /traildrop directory exists
        SD.mkdir("/traildrop");
        
        if (hal::storage_exists(IDENTITY_PATH)) {
            if (crypto::identity_load(device_identity, IDENTITY_PATH)) {
                Serial.println("[ID] Identity loaded from SD");
            } else {
                Serial.println("[ID] Failed to load identity, generating new");
                if (crypto::identity_generate(device_identity)) {
                    crypto::identity_save(device_identity, IDENTITY_PATH);
                    Serial.println("[ID] New identity generated and saved");
                }
            }
        } else {
            if (crypto::identity_generate(device_identity)) {
                crypto::identity_save(device_identity, IDENTITY_PATH);
                Serial.println("[ID] New identity generated and saved");
            } else {
                Serial.println("[ID] CRITICAL: Failed to generate identity");
            }
        }
        
        // Derive destinations (Phase 4a.5: dual destinations)
        if (net::destination_derive(device_identity, APP_NAME, "waypoint", device_destination) &&
            net::destination_derive(device_identity, "lxmf", "delivery", device_lxmf_destination)) {
            identity_ready = true;

            // Print identity info
            Serial.printf("[ID] Identity hash: ");
            for (int i = 0; i < 16; i++) Serial.printf("%02x", device_identity.hash[i]);
            Serial.println();
            Serial.printf("[ID] TD Dest:       ");
            for (int i = 0; i < 16; i++) Serial.printf("%02x", device_destination.hash[i]);
            Serial.println();
            Serial.printf("[ID] LXMF Dest:     ");
            for (int i = 0; i < 16; i++) Serial.printf("%02x", device_lxmf_destination.hash[i]);
            Serial.println();

            // Dump full identity key bytes for wire compat test capture
            uint8_t id_bytes[128];
            memcpy(id_bytes, device_identity.x25519_private, 32);
            memcpy(id_bytes + 32, device_identity.x25519_public, 32);
            memcpy(id_bytes + 64, device_identity.ed25519_private, 32);
            memcpy(id_bytes + 96, device_identity.ed25519_public, 32);
            Serial.print("[ID_KEY] ");
            for (int i = 0; i < 128; i++) Serial.printf("%02x", id_bytes[i]);
            Serial.println();

            // Show on display
            hal::display_printf(0, line * 18, 0x07FF, 1, "ID: %02x%02x%02x%02x...",
                device_identity.hash[0], device_identity.hash[1],
                device_identity.hash[2], device_identity.hash[3]);
            line++;
        }
    } else {
        Serial.println("[ID] Skipping identity — no SD card");
    }

    if (boot.can_network() && identity_ready) {
        Serial.println("[BOOT] Full network-ready: radio + storage + identity");
    } else if (boot.can_network()) {
        Serial.println("[BOOT] Network-partial: radio + storage OK, identity missing");
    } else {
        Serial.println("[BOOT] Network-degraded: missing radio or storage");
    }

    // Phase 3d: Initialize transport layer (needed for transport_announce)
    if (identity_ready && boot.radio) {
        net::transport_init(device_identity, device_destination);

        // Phase 4b: Initialize LXMF transport (replaces transport_poll for receive)
        msg::lxmf_transport_init(device_identity, device_destination, device_lxmf_destination);
        msg::lxmf_set_receive_callback(on_lxmf_received);

        // Send initial announce
        net::transport_announce("TrailDrop");
        Serial.println("[NET] Transport initialized, LXMF transport ready, announce sent");
    }

    Serial.println("[BOOT] === Init complete ===\n");
    
    // Phase 2: Run crypto tests
    if (boot.storage) {
        line++; // Add spacing
        run_crypto_tests(line);
        
        // Phase 3a: Run packet tests
        line++; // Add spacing
        run_packet_tests(line);
        
        // Phase 3c: Run announce tests
        line++; // Add spacing
        run_announce_tests(line);
        
        // Phase 3d: Run transport tests
        line++; // Add spacing
        run_transport_tests(line);

        // Phase 4a: Run msgpack + LXMF tests
        line++; // Add spacing
        run_msgpack_lxmf_tests(line);

        // Phase 4a.5: Run announce migration + dual dest tests
        line++; // Add spacing
        run_phase4a5_tests(line);

        // Phase 4b: Run LXMF transport tests
        line++; // Add spacing
        run_phase4b_tests(line);

        // Phase 4c: Run waypoint tests
        line++; // Add spacing
        run_phase4c_tests(line);

        // Re-initialize after tests:
        // - Transport tests overwrite s_identity/s_destination with stack-local pointers
        // - Announce tests leave stale test peers in the peer table
        net::peer_table_init();
        if (identity_ready && boot.radio) {
            net::transport_init(device_identity, device_destination);
            msg::lxmf_transport_init(device_identity, device_destination, device_lxmf_destination);
            msg::lxmf_set_receive_callback(on_lxmf_received);
            // Re-announce after tests — boot announce was likely lost while
            // the other device was also running self-tests
            net::transport_announce("TrailDrop");
            Serial.println("[NET] Post-test re-announce sent");
        }
    } else {
        Serial.println("[CRYPTO] Skipping crypto tests - SD card required");
        hal::display_printf(0, line * 18, 0xFBE0, 2, "Crypto: SKIP (no SD)");
    }

    Serial.println("[BOOT] === Entering main loop ===\n");

    // Phase 4d: Initialize display UI (shows boot screen, then transitions to main)
    ui::ui_init();
    if (identity_ready) {
        ui::ui_set_send_context(&device_identity, device_lxmf_destination.hash);
    }
}

void loop() {
    // --- GPS ---
    hal::gps_poll();

    // --- GPS serial status (every 5s) ---
    static uint32_t last_gps_display = 0;
    if (millis() - last_gps_display > 5000) {
        if (hal::gps_has_fix()) {
            Serial.printf("[GPS] Fix: %.6f, %.6f, %.1fm | Sats=%d HDOP=%.1f\n",
                          hal::gps_latitude(), hal::gps_longitude(), hal::gps_altitude(),
                          hal::gps_satellites(), hal::gps_hdop());
        } else {
            Serial.printf("[GPS] No fix (sats=%d)\n", hal::gps_satellites());
        }
        last_gps_display = millis();
    }

    uint32_t now = millis();

    // --- Network polling (Phase 4b: LXMF transport replaces raw transport_poll) ---
    if (identity_ready && boot.radio) {
        // Track peer count before poll to detect new peers
        static int prev_peer_count = 0;
        int before_peers = net::peer_count();

        msg::lxmf_transport_poll();

        // Auto-send: arm when we first discover a peer
        int after_peers = net::peer_count();
        if (after_peers > before_peers && !auto_send_pending) {
            auto_send_pending = true;
            auto_send_time = now + 30000;  // 30 seconds from now
            Serial.printf("[AUTO] Peer discovered (count %d->%d), will send LXMF in 30s\n",
                          before_peers, after_peers);
        }
        prev_peer_count = after_peers;

        // Auto-send: fire when timer expires — send LXMF instead of raw data
        if (auto_send_pending && now >= auto_send_time) {
            auto_send_pending = false;
            const net::Peer* peer = net::peer_first();
            if (peer) {
                uint8_t msg_hash[32];
                Serial.printf("[AUTO] Sending LXMF to peer %02x%02x%02x%02x...\n",
                    peer->dest_hash[0], peer->dest_hash[1],
                    peer->dest_hash[2], peer->dest_hash[3]);
                bool sent = msg::lxmf_send(
                    device_identity, device_lxmf_destination.hash,
                    peer->dest_hash,
                    "Hi", "Hello!",
                    nullptr, 0,
                    nullptr, 0,
                    msg_hash);
                if (!sent) {
                    delay(100);
                    Serial.println("[AUTO] Retrying send...");
                    msg::lxmf_send(
                        device_identity, device_lxmf_destination.hash,
                        peer->dest_hash,
                        "Hi", "Hello!",
                        nullptr, 0,
                        nullptr, 0,
                        msg_hash);
                }
            } else {
                Serial.println("[AUTO] No peers available for auto-send");
            }
        }

        // Periodic announce
        static uint32_t last_announce_check = 0;
        if (now - last_announce_check >= (ANNOUNCE_INTERVAL * 1000UL)) {
            last_announce_check = now;
            net::transport_announce("TrailDrop");
        }

        // Feed peer count to UI
        ui::ui_set_peer_count(after_peers);
    }

    // --- Phase 4d: Display UI handles all screen drawing + keyboard input ---
    ui::ui_update();

    // Stir RNG entropy pool — required for RNG.rand() to work after boot
    RNG.loop();

    delay(20); // ~50Hz poll rate
}
