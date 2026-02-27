/**
 * TrailDrop Firmware — Main Entry Point
 * Target: LilyGO T-Deck Plus (ESP32-S3 + SX1262)
 *
 * Standalone backcountry waypoint sharing over LoRa/Reticulum.
 */

#include "config.h"

// Hardware abstraction
#include "hal/power.h"
#include "hal/display.h"
#include "hal/keyboard.h"
#include "hal/trackball.h"
#include "hal/gps.h"
#include "hal/radio.h"
#include "hal/storage.h"
#include "hal/battery.h"

// Crypto
#include "crypto/identity.h"

// Network
#include "net/transport.h"
#include "net/announce.h"

// Application
#include "app/waypoint.h"
#include "app/peers.h"

// UI
#include "ui/ui.h"

static crypto::Identity device_identity;

void setup() {
    Serial.begin(115200);
    Serial.printf("\n🦉 TrailDrop %s\n", APP_VERSION);
    Serial.println("Initializing...");

    // Phase 1: Hardware bringup (power_init MUST be first — enables peripherals + deselects SPI CS)
    bool ok = true;
    ok &= hal::power_init();
    ok &= hal::display_init();

    // Display errors on screen — backcountry user won't have serial monitor
    auto check = [&](const char* name, bool result) {
        if (!result) {
            Serial.printf("[BOOT] %s: FAIL\n", name);
            hal::display_printf(0, 0, 0xF800, 2, "FAIL: %s", name);
        } else {
            Serial.printf("[BOOT] %s: OK\n", name);
        }
        ok &= result;
    };

    check("Power", ok);
    check("Display", ok);
    check("Keyboard", hal::keyboard_init());
    check("Trackball", hal::trackball_init());
    check("GPS", hal::gps_init());
    check("Radio", hal::radio_init());
    check("Storage", hal::storage_init());
    check("Battery", hal::battery_init());

    // Phase 2: Load or generate identity
    if (!crypto::identity_load(device_identity, "/identity.key")) {
        Serial.println("Generating new identity...");
        crypto::identity_generate(device_identity);
        if (!crypto::identity_save(device_identity, "/identity.key")) {
            Serial.println("[BOOT] WARNING: Failed to save identity to SD");
        }
    }

    // Phase 3: Initialize networking
    if (!net::transport_init()) {
        Serial.println("[BOOT] WARNING: Transport init failed");
    }

    // Phase 5-6: Initialize app and UI
    app::waypoint_db_init("/waypoints.db");
    app::peers_init();
    ui::ui_init();
    ui::ui_show(ui::SCREEN_MAIN);

    Serial.println("Ready.");
}

void loop() {
    // Poll radio for incoming packets
    net::transport_poll();

    // Update GPS
    hal::gps_poll();

    // Update UI
    ui::ui_update();

    // Periodic announce
    // TODO: announce on interval (ANNOUNCE_INTERVAL seconds)
}
