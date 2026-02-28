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
#include <RNG.h>

// Boot status display — shows init results on screen
static void show_boot_status(const char* module, bool ok, int line) {
    uint16_t color = ok ? 0x07E0 : 0xF800; // green or red
    hal::display_printf(0, line * 18, color, 2, "%s: %s", module, ok ? "OK" : "FAIL");
}

// ============================================================
// Phase 2: Crypto Self-Tests
// ============================================================

static bool test_sha256() {
    // Test vector: SHA-256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
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
    // Test vector: HMAC-SHA256(key="key", data="The quick brown fox jumps over the lazy dog")
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
    // Test AES-256-CBC encrypt/decrypt roundtrip
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

static bool test_identity() {
    // Generate identity
    crypto::Identity id;
    if (!crypto::identity_generate(id)) {
        return false;
    }
    
    // Save to SD card
    const char* test_path = "/identity_test.dat";
    if (!crypto::identity_save(id, test_path)) {
        return false;
    }
    
    // Load back
    crypto::Identity loaded;
    if (!crypto::identity_load(loaded, test_path)) {
        return false;
    }
    
    // Verify match (ed25519_private is now 32 bytes, not 64)
    bool match = (memcmp(id.x25519_public, loaded.x25519_public, 32) == 0) &&
                 (memcmp(id.x25519_private, loaded.x25519_private, 32) == 0) &&
                 (memcmp(id.ed25519_public, loaded.ed25519_public, 32) == 0) &&
                 (memcmp(id.ed25519_private, loaded.ed25519_private, 32) == 0);
    
    // Clean up
    hal::storage_remove(test_path);
    
    return match;
}

static bool test_ecdh() {
    // Generate two identities and perform ECDH key exchange
    crypto::Identity alice, bob;
    if (!crypto::identity_generate(alice) || !crypto::identity_generate(bob)) {
        return false;
    }
    
    // Alice derives shared secret using Bob's public key
    uint8_t shared_alice[32];
    if (!crypto::identity_derive_shared_key(bob.x25519_public, alice.x25519_private, shared_alice)) {
        return false;
    }
    
    // Bob derives shared secret using Alice's public key
    uint8_t shared_bob[32];
    if (!crypto::identity_derive_shared_key(alice.x25519_public, bob.x25519_private, shared_bob)) {
        return false;
    }
    
    // Both should match
    return memcmp(shared_alice, shared_bob, 32) == 0;
}

static bool test_ed25519_sign_verify() {
    // Generate identity and test signing/verification
    crypto::Identity id;
    if (!crypto::identity_generate(id)) {
        return false;
    }
    
    const uint8_t message[] = "Test message for signing";
    uint8_t signature[64];
    
    // Sign
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
        return false; // Should have failed verification
    }
    
    return true;
}

static bool test_destination_hash() {
    // Test destination hash derivation
    crypto::Identity id;
    if (!crypto::identity_generate(id)) {
        return false;
    }
    
    uint8_t hash1[16];
    uint8_t hash2[16];
    
    // Same identity and aspects should produce same hash
    crypto::identity_destination_hash(id, "traildrop", "waypoints", hash1);
    crypto::identity_destination_hash(id, "traildrop", "waypoints", hash2);
    
    if (memcmp(hash1, hash2, 16) != 0) {
        return false;
    }
    
    // Different aspects should produce different hash
    uint8_t hash3[16];
    crypto::identity_destination_hash(id, "traildrop", "chat", hash3);
    
    return memcmp(hash1, hash3, 16) != 0;
}

static void run_crypto_tests(int& line) {
    Serial.println("\n[CRYPTO] Running Phase 2 crypto tests...");
    hal::display_printf(0, line * 18, 0xFFFF, 2, "=== Crypto Tests ===");
    line++;
    
    // Test 1: SHA-256
    bool sha_ok = test_sha256();
    Serial.printf("[CRYPTO] SHA-256:        %s\n", sha_ok ? "PASS" : "FAIL");
    show_boot_status("SHA-256", sha_ok, line++);
    
    // Test 2: HMAC-SHA256
    bool hmac_ok = test_hmac_sha256();
    Serial.printf("[CRYPTO] HMAC-SHA256:    %s\n", hmac_ok ? "PASS" : "FAIL");
    show_boot_status("HMAC-SHA256", hmac_ok, line++);
    
    // Test 3: AES-256-CBC
    bool aes_ok = test_aes256_cbc();
    Serial.printf("[CRYPTO] AES-256-CBC:    %s\n", aes_ok ? "PASS" : "FAIL");
    show_boot_status("AES-256-CBC", aes_ok, line++);
    
    // Test 4: Identity save/load
    bool id_ok = test_identity();
    Serial.printf("[CRYPTO] Identity:       %s\n", id_ok ? "PASS" : "FAIL");
    show_boot_status("Identity", id_ok, line++);
    
    // Test 5: X25519 ECDH
    bool ecdh_ok = test_ecdh();
    Serial.printf("[CRYPTO] X25519 ECDH:    %s\n", ecdh_ok ? "PASS" : "FAIL");
    show_boot_status("X25519 ECDH", ecdh_ok, line++);
    
    // Test 6: Ed25519 sign/verify
    bool sign_ok = test_ed25519_sign_verify();
    Serial.printf("[CRYPTO] Ed25519 Sign:   %s\n", sign_ok ? "PASS" : "FAIL");
    show_boot_status("Ed25519 Sign", sign_ok, line++);
    
    // Test 7: Destination hash
    bool dest_ok = test_destination_hash();
    Serial.printf("[CRYPTO] Dest Hash:      %s\n", dest_ok ? "PASS" : "FAIL");
    show_boot_status("Dest Hash", dest_ok, line++);
    
    // Summary
    bool all_pass = sha_ok && hmac_ok && aes_ok && id_ok && ecdh_ok && sign_ok && dest_ok;
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
