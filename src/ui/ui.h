#pragma once
// TrailDrop LVGL UI manager
// Phase 5: Touch UI with dark theme

#include <stdint.h>
#include "config.h"
#include "app/waypoint.h"
#include "crypto/identity.h"

namespace ui {

enum Screen {
    SCREEN_BOOT,
    SCREEN_MAIN,
    SCREEN_DROP,
    SCREEN_PEERS,
    SCREEN_DETAIL,
    SCREEN_SETTINGS,
    SCREEN_EMERGENCY,
    SCREEN_COUNT
};

// --- UI data model (runtime, not persisted) ---

struct UiWaypoint {
    bool valid;
    char sender[DISPLAY_NAME_MAX];
    char name[64];
    double lat, lon;
    float altitude;
    app::WaypointCategory category;
    int16_t rssi;
    uint32_t received_at;  // millis()
};

struct UiPeer {
    bool valid;
    char name[DISPLAY_NAME_MAX];
    int16_t rssi;
    uint32_t last_seen;  // millis()
};

static constexpr int MAX_UI_WAYPOINTS = 32;
static constexpr int MAX_UI_PEERS = MAX_PEERS;

// --- Lifecycle ---

bool ui_init();                 // LVGL init, display/touch drivers, show boot screen
void ui_update();               // Call from main loop (~20ms interval)
void ui_show(Screen screen);    // Navigate to screen
void ui_back();                 // Navigate back

// --- Input forwarding ---

void ui_feed_key(char key);     // Forward keyboard input to LVGL

// --- Callbacks from app/net layers ---

void ui_on_waypoint_received(const char* sender, const char* name,
                             double lat, double lon, float alt,
                             app::WaypointCategory cat, int16_t rssi);

void ui_on_peer_discovered(const char* name, int16_t rssi);

// --- Send context (identity + LXMF dest for outbound waypoints) ---

void ui_set_send_context(const crypto::Identity* id, const uint8_t* our_lxmf_dest);
const crypto::Identity* ui_get_identity();
const uint8_t* ui_get_lxmf_dest();

// --- Accessors for screen implementations ---

UiWaypoint* ui_get_waypoints();
int ui_get_waypoint_count();
UiPeer* ui_get_peers();
int ui_get_peer_count();
void ui_set_selected_waypoint(int idx);
int ui_get_selected_waypoint();
Screen ui_get_current_screen();

// --- Boot progress ---

void ui_boot_progress(int percent, const char* phase);

} // namespace ui
