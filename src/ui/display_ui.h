#pragma once
// TrailDrop display UI — text-based TFT interface
// Uses hal::display_* primitives directly (no LVGL dependency).
// Phase 4d: Boot, Main, Share, and Detail screens.

#include <cstdint>
#include <cstddef>
#include "msg/waypoint.h"
#include "crypto/identity.h"

namespace ui {

enum class Screen {
    BOOT,
    MAIN,
    SHARE,
    DETAIL,
    CONFIRM
};

void ui_init();
void ui_update();          // Call from loop() — handles drawing + input
Screen ui_current_screen();

// Notify UI of a received waypoint (call from LXMF receive callback).
void ui_on_waypoint_received(const msg::Waypoint& wp, const char* sender_name, int rssi);

// Provide identity context so the UI can send waypoints.
void ui_set_send_context(const crypto::Identity* id, const uint8_t* our_lxmf_dest);

// Set peer count (called from main loop after transport poll).
void ui_set_peer_count(int count);

} // namespace ui
