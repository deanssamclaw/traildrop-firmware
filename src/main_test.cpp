// ============================================================
// TrailDrop Firmware — Phase 1 HAL Test Harness
// Exercises all 8 HAL modules: power, display, keyboard,
// trackball, GPS, radio, storage, battery.
// No crypto, net, app, or UI dependencies.
// ============================================================

#include <Arduino.h>
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
#include <RNG.h>

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
    crypto::hmac_sha256(key, 3, data, 44, hmac);

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

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.printf("\n=== TrailDrop %s — HAL Test Harness ===\n", APP_VERSION);

    // Phase 1: Boot sequence (power_init MUST be first)
    bool ok_power = hal::power_init();
    Serial.printf("[BOOT] Power:    %s\n", ok_power ? "OK" : "FAIL");

    bool ok_display = hal::display_init();
    Serial.printf("[BOOT] Display:  %s\n", ok_display ? "OK" : "FAIL");

    // Show boot status on display
    hal::display_clear(0x0000);
    hal::display_text(0, 0, "TrailDrop HAL Test", 0xFFFF, 2);

    int line = 2;
    show_boot_status("Power",    ok_power,   line++);
    show_boot_status("Display",  ok_display, line++);

    bool ok_kb = hal::keyboard_init();
    Serial.printf("[BOOT] Keyboard: %s\n", ok_kb ? "OK" : "FAIL");
    show_boot_status("Keyboard", ok_kb, line++);

    bool ok_tb = hal::trackball_init();
    Serial.printf("[BOOT] Trackball:%s\n", ok_tb ? "OK" : "FAIL");
    show_boot_status("Trackball", ok_tb, line++);

    bool ok_gps = hal::gps_init();
    Serial.printf("[BOOT] GPS:      %s\n", ok_gps ? "OK" : "FAIL");
    show_boot_status("GPS",      ok_gps, line++);

    bool ok_radio = hal::radio_init();
    Serial.printf("[BOOT] Radio:    %s\n", ok_radio ? "OK" : "FAIL");
    show_boot_status("Radio",    ok_radio, line++);

    bool ok_sd = hal::storage_init();
    Serial.printf("[BOOT] Storage:  %s\n", ok_sd ? "OK" : "FAIL");
    show_boot_status("Storage",  ok_sd, line++);

    bool ok_bat = hal::battery_init();
    Serial.printf("[BOOT] Battery:  %s\n", ok_bat ? "OK" : "FAIL");
    show_boot_status("Battery",  ok_bat, line++);

    // Battery reading
    float volts = hal::battery_voltage();
    int pct = hal::battery_percent();
    Serial.printf("[BOOT] Battery:  %.2fV (%d%%)\n", volts, pct);
    hal::display_printf(0, line * 18, 0xFFE0, 2, "Bat: %.2fV %d%%", volts, pct);
    line++;

    // Storage info
    if (ok_sd) {
        uint64_t total = hal::storage_total_bytes();
        uint64_t used  = hal::storage_used_bytes();
        Serial.printf("[BOOT] SD: %llu MB total, %llu MB used\n",
                      total / (1024*1024), used / (1024*1024));
    }

    // Start radio receive mode
    if (ok_radio) {
        hal::radio_start_receive();
        Serial.println("[BOOT] Radio: listening");
    }

    Serial.println("[BOOT] === Init complete ===\n");
    
    // Phase 2: Run crypto tests
    if (ok_sd) {
        line++; // Add spacing
        run_crypto_tests(line);
    } else {
        Serial.println("[CRYPTO] Skipping crypto tests - SD card required");
        hal::display_printf(0, line * 18, 0xFBE0, 2, "Crypto: SKIP (no SD)");
    }

    Serial.println("[BOOT] === Entering main loop ===\n");
    hal::display_printf(0, (line + 1) * 18, 0x07E0, 2, "Ready. Looping...");
}

void loop() {
    static uint32_t last_display_update = 0;
    static int cursor_x = 160, cursor_y = 120;
    static char last_keys[32] = {0};
    static int key_pos = 0;

    // --- Keyboard ---
    char key = hal::keyboard_read();
    if (key) {
        Serial.printf("[KB] Key: 0x%02X '%c'\n", key, (key >= 32 && key < 127) ? key : '.');
        if (key_pos < (int)sizeof(last_keys) - 1) {
            last_keys[key_pos++] = (key >= 32 && key < 127) ? key : '.';
            last_keys[key_pos] = '\0';
        } else {
            // Shift buffer left
            memmove(last_keys, last_keys + 1, sizeof(last_keys) - 1);
            last_keys[sizeof(last_keys) - 2] = (key >= 32 && key < 127) ? key : '.';
        }
    }

    // --- Trackball ---
    int8_t dx = 0, dy = 0;
    bool click = false;
    hal::trackball_read(dx, dy, click);
    if (dx || dy || click) {
        cursor_x += dx * 4;
        cursor_y += dy * 4;
        cursor_x = constrain(cursor_x, 0, DISPLAY_WIDTH - 1);
        cursor_y = constrain(cursor_y, 0, DISPLAY_HEIGHT - 1);
        Serial.printf("[TB] dx=%d dy=%d click=%d pos=(%d,%d)\n", dx, dy, click, cursor_x, cursor_y);
    }

    // --- GPS ---
    hal::gps_poll();

    // --- Radio RX check ---
    uint8_t rx_buf[256];
    int rx_len = hal::radio_receive(rx_buf, sizeof(rx_buf));
    if (rx_len > 0) {
        Serial.printf("[RADIO] Received %d bytes, RSSI=%.1f SNR=%.1f\n",
                      rx_len, hal::radio_rssi(), hal::radio_snr());
    }

    // --- Periodic display update (every 1s) ---
    uint32_t now = millis();
    if (now - last_display_update >= 1000) {
        last_display_update = now;

        // Clear the live data area (bottom half of screen)
        int y_start = 200;

        // GPS line
        if (hal::gps_has_fix()) {
            hal::display_printf(0, y_start - 60, 0x07E0, 1,
                "GPS: %.6f, %.6f  %dm  %dsat  ",
                hal::gps_latitude(), hal::gps_longitude(),
                (int)hal::gps_altitude(), hal::gps_satellites());
        } else {
            hal::display_printf(0, y_start - 60, 0xFBE0, 1,
                "GPS: no fix  %d sat       ",
                hal::gps_satellites());
        }

        // Battery
        hal::display_printf(0, y_start - 48, 0xFFE0, 1,
            "Bat: %.2fV %d%% %s    ",
            hal::battery_voltage(), hal::battery_percent(),
            hal::battery_is_low() ? "LOW!" : "");

        // Trackball cursor
        hal::display_printf(0, y_start - 36, 0xBDF7, 1,
            "Cursor: %d, %d          ", cursor_x, cursor_y);

        // Keyboard buffer
        hal::display_printf(0, y_start - 24, 0xFFFF, 1,
            "Keys: %s              ", last_keys);

        // Uptime
        hal::display_printf(0, y_start - 12, 0x7BEF, 1,
            "Up: %lus               ", now / 1000);
    }

    delay(20); // ~50Hz poll rate
}
