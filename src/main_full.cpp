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

    // Phase 1: Hardware bringup
    hal::power_init();
    hal::display_init();
    hal::keyboard_init();
    hal::trackball_init();
    hal::gps_init();
    hal::radio_init();
    hal::storage_init();
    hal::battery_init();

    // Phase 2: Load or generate identity
    if (!crypto::identity_load(device_identity, "/identity.key")) {
        Serial.println("Generating new identity...");
        crypto::identity_generate(device_identity);
        crypto::identity_save(device_identity, "/identity.key");
    }

    // Phase 3: Initialize networking
    net::transport_init();

    // Phase 5-6: Initialize app and UI
    app::waypoint_db_init("/waypoints.db");
    app::peers_init();
    ui::ui_init();
    ui::ui_show(ui::SCREEN_MAIN);

    // Announce ourselves on the network
    // net::Destination dest;
    // net::destination_derive(device_identity, "lxmf", "delivery", dest);
    // net::announce_send(device_identity, dest);

    Serial.println("Ready.");
}

void loop() {
    // Poll radio for incoming packets
    net::transport_poll();

    // Update GPS
    // hal::gps_poll();

    // Update UI
    ui::ui_update();

    // Periodic announce
    // TODO: announce on interval (ANNOUNCE_INTERVAL seconds)
}
