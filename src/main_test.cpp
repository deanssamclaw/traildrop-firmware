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

// Boot status display — shows init results on screen
static void show_boot_status(const char* module, bool ok, int line) {
    uint16_t color = ok ? 0x07E0 : 0xF800; // green or red
    hal::display_printf(0, line * 18, color, 2, "%s: %s", module, ok ? "OK" : "FAIL");
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

    Serial.println("[BOOT] === Init complete, entering main loop ===\n");
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
