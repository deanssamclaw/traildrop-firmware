// TrailDrop display UI — Phase 4d
// Text-based TFT interface using hal::display_* primitives.
// Screens: Boot → Main → Share / Detail

#include "display_ui.h"
#include "hal/display.h"
#include "hal/keyboard.h"
#include "hal/gps.h"
#include "net/peer.h"
#include "msg/waypoint.h"
#include <Arduino.h>
#include <cmath>
#include <cstring>
#include <cstdio>

namespace ui {

// --- Colors (RGB565) ---
static const uint16_t COL_WHITE  = 0xFFFF;
static const uint16_t COL_GREEN  = 0x07E0;
static const uint16_t COL_CYAN   = 0x07FF;
static const uint16_t COL_GRAY   = 0x7BEF;
static const uint16_t COL_DKGRAY = 0x4208;
static const uint16_t COL_RED    = 0xF800;

// --- Key codes ---
static const char KEY_ENTER = '\n';
static const char KEY_CR    = '\r';
static const char KEY_BS    = '\b';
static const char KEY_ESC   = 0x1B;

// --- Screen state ---
static Screen s_screen = Screen::BOOT;
static uint32_t s_boot_start = 0;
static uint32_t s_last_refresh = 0;
static bool s_needs_clear = true;  // Full redraw needed

// --- Send context ---
static const crypto::Identity* s_identity = nullptr;
static const uint8_t* s_our_lxmf_dest = nullptr;
static int s_peer_count = 0;

// --- Received waypoints (peer list) ---
static const size_t MAX_DISP_WP = 16;

struct DisplayWaypoint {
    msg::Waypoint wp;
    char sender[32];
    int rssi;
    uint32_t received_at;  // millis()
    uint8_t peer_dest[16]; // announce dest hash (for sending back)
    bool valid;
};

static DisplayWaypoint s_waypoints[MAX_DISP_WP];

// --- Main screen ---
static int s_selected = 0;     // Selected peer index in sorted list
static int s_wp_count = 0;     // Number of valid waypoints

// --- Share screen ---
static char s_share_name[21];  // Max 20 chars + null
static int s_share_len = 0;

// --- Confirmation overlay ---
static uint32_t s_confirm_start = 0;

// --- Detail screen ---
static int s_detail_idx = -1;  // Index into sorted list

// ============================================================
// Helpers
// ============================================================

// Haversine distance in miles
static float distance_miles(double lat1, double lon1, double lat2, double lon2) {
    const double R = 3958.8; // Earth radius in miles
    double dlat = (lat2 - lat1) * M_PI / 180.0;
    double dlon = (lon2 - lon1) * M_PI / 180.0;
    double a = sin(dlat / 2) * sin(dlat / 2) +
               cos(lat1 * M_PI / 180.0) * cos(lat2 * M_PI / 180.0) *
               sin(dlon / 2) * sin(dlon / 2);
    double c = 2 * atan2(sqrt(a), sqrt(1 - a));
    return (float)(R * c);
}

static const char* signal_label(int rssi) {
    if (rssi > -70)  return "Strong";
    if (rssi > -90)  return "Good";
    if (rssi > -110) return "Weak";
    return "Faint";
}

// Format elapsed millis as human-readable "Ns" / "Nm" / "Nh" / ">1d"
static void format_time_ago(uint32_t elapsed_ms, char* buf, size_t cap) {
    uint32_t s = elapsed_ms / 1000;
    if (s < 60)        snprintf(buf, cap, "%lus", (unsigned long)s);
    else if (s < 3600) snprintf(buf, cap, "%lum", (unsigned long)(s / 60));
    else if (s < 86400) snprintf(buf, cap, "%luh", (unsigned long)(s / 3600));
    else               snprintf(buf, cap, ">1d");
}

// Format latitude as "38.8814 N" (4 decimal places)
static void format_lat(double lat, char* buf, size_t cap) {
    char hem = lat >= 0 ? 'N' : 'S';
    if (lat < 0) lat = -lat;
    snprintf(buf, cap, "%.4f %c", lat, hem);
}

// Format longitude as "94.8191 W"
static void format_lon(double lon, char* buf, size_t cap) {
    char hem = lon >= 0 ? 'E' : 'W';
    if (lon < 0) lon = -lon;
    snprintf(buf, cap, "%.4f %c", lon, hem);
}

// Get sorted indices of valid waypoints (most recent first).
// Returns count written to out_idx.
static int sorted_waypoints(int* out_idx, int max) {
    int count = 0;
    for (int i = 0; i < (int)MAX_DISP_WP && count < max; i++) {
        if (s_waypoints[i].valid) out_idx[count++] = i;
    }
    // Insertion sort by received_at descending (most recent first)
    for (int i = 1; i < count; i++) {
        int key = out_idx[i];
        uint32_t key_time = s_waypoints[key].received_at;
        int j = i - 1;
        while (j >= 0 && s_waypoints[out_idx[j]].received_at < key_time) {
            out_idx[j + 1] = out_idx[j];
            j--;
        }
        out_idx[j + 1] = key;
    }
    return count;
}

// Transition to a new screen
static void go_to(Screen scr) {
    s_screen = scr;
    s_needs_clear = true;
}

// Draw a full-width padded line (prevents ghost text from previous content).
// size 2 = ~26 chars wide, size 1 = ~53 chars wide
static void draw_line(int y, uint16_t color, uint8_t size, const char* text) {
    int max_chars = (size == 1) ? 53 : 26;
    char padded[60];
    int len = (int)strlen(text);
    if (len > max_chars) len = max_chars;
    memcpy(padded, text, len);
    // Pad with spaces to clear the rest of the line
    for (int i = len; i < max_chars && i < (int)sizeof(padded) - 1; i++)
        padded[i] = ' ';
    padded[(max_chars < (int)sizeof(padded) - 1) ? max_chars : (int)sizeof(padded) - 1] = '\0';
    hal::display_text(0, y, padded, color, size);
}

// ============================================================
// Screen: Boot
// ============================================================
static void draw_boot() {
    if (!s_needs_clear) return;
    hal::display_clear();
    hal::display_text(80, 96, "TrailDrop", COL_WHITE, 3);
    hal::display_text(100, 140, "Starting...", COL_GRAY, 2);
    s_needs_clear = false;
}

// ============================================================
// Screen: Main
// ============================================================
static void draw_main() {
    if (s_needs_clear) {
        hal::display_clear();
        s_needs_clear = false;
    }

    uint32_t now = millis();
    char buf[60];

    // --- Top bar: "TrailDrop" + peer count ---
    snprintf(buf, sizeof(buf), "TrailDrop          * %d", s_peer_count);
    draw_line(2, COL_WHITE, 2, buf);

    // --- GPS position ---
    if (hal::gps_has_fix()) {
        char lat_s[20], lon_s[20];
        format_lat(hal::gps_latitude(), lat_s, sizeof(lat_s));
        format_lon(hal::gps_longitude(), lon_s, sizeof(lon_s));
        snprintf(buf, sizeof(buf), "%s  %s", lat_s, lon_s);
        draw_line(36, COL_GREEN, 2, buf);

        snprintf(buf, sizeof(buf), "%dm  %d sats",
                 (int)hal::gps_altitude(), (int)hal::gps_satellites());
        draw_line(56, COL_GREEN, 2, buf);
    } else {
        snprintf(buf, sizeof(buf), "Searching...  %d sats", (int)hal::gps_satellites());
        draw_line(36, COL_CYAN, 2, buf);
        draw_line(56, COL_CYAN, 2, " ");
    }

    // --- Divider ---
    draw_line(78, COL_DKGRAY, 1, "------------------------------------------------");

    // --- Peer waypoints ---
    int sorted[MAX_DISP_WP];
    s_wp_count = sorted_waypoints(sorted, MAX_DISP_WP);

    // Clamp selection
    if (s_wp_count == 0) s_selected = 0;
    else if (s_selected >= s_wp_count) s_selected = s_wp_count - 1;

    // Show up to 5 peers
    int visible = (s_wp_count < 5) ? s_wp_count : 5;
    // Scroll offset: keep selected visible
    int scroll = 0;
    if (s_selected >= 5) scroll = s_selected - 4;

    for (int row = 0; row < 5; row++) {
        int y = 92 + row * 20;
        int idx = row + scroll;
        if (idx < s_wp_count) {
            const DisplayWaypoint& dw = s_waypoints[sorted[idx]];
            char dist_s[12] = "--";
            if (hal::gps_has_fix()) {
                float d = distance_miles(hal::gps_latitude(), hal::gps_longitude(),
                                         dw.wp.lat, dw.wp.lon);
                if (d < 100.0f) snprintf(dist_s, sizeof(dist_s), "%.1fmi", d);
                else snprintf(dist_s, sizeof(dist_s), "%dmi", (int)d);
            }
            char ago[8];
            format_time_ago(now - dw.received_at, ago, sizeof(ago));

            char prefix = (idx == s_selected) ? '>' : ' ';
            uint16_t color = (idx == s_selected) ? COL_CYAN : COL_WHITE;

            // "  Name      0.3mi  2m"
            snprintf(buf, sizeof(buf), "%c %-10.10s %6s %4s", prefix, dw.sender, dist_s, ago);
            draw_line(y, color, 2, buf);
        } else {
            draw_line(y, COL_WHITE, 2, " ");
        }
    }

    // --- Bottom hint ---
    draw_line(226, COL_GRAY, 1, "[S] Share spot");
}

// ============================================================
// Screen: Share
// ============================================================
static void draw_share() {
    if (s_needs_clear) {
        hal::display_clear();
        s_needs_clear = false;
    }

    char buf[60];

    draw_line(2, COL_WHITE, 2, "Share Your Spot");

    // No GPS fix: show warning
    if (!hal::gps_has_fix()) {
        draw_line(60, COL_RED, 2, "No GPS fix");
        draw_line(80, COL_GRAY, 2, "Can't share yet");
        draw_line(226, COL_GRAY, 1, "Press any key to go back");
        return;
    }

    // Name input with cursor
    snprintf(buf, sizeof(buf), "Name: %s_", s_share_name);
    draw_line(50, COL_WHITE, 2, buf);

    // Current position
    char lat_s[20], lon_s[20];
    format_lat(hal::gps_latitude(), lat_s, sizeof(lat_s));
    format_lon(hal::gps_longitude(), lon_s, sizeof(lon_s));
    snprintf(buf, sizeof(buf), "%s  %s", lat_s, lon_s);
    draw_line(90, COL_GREEN, 2, buf);

    draw_line(226, COL_GRAY, 1, "[Enter] Send   [Bksp] Back");
}

// ============================================================
// Screen: Confirmation (brief flash after sending)
// ============================================================
static void draw_confirm() {
    if (s_needs_clear) {
        hal::display_clear();
        hal::display_text(100, 100, "Shared!", COL_GREEN, 3);
        s_needs_clear = false;
    }
}

// ============================================================
// Screen: Detail
// ============================================================
static void draw_detail() {
    if (s_needs_clear) {
        hal::display_clear();
        s_needs_clear = false;
    }

    if (s_detail_idx < 0 || s_detail_idx >= (int)MAX_DISP_WP ||
        !s_waypoints[s_detail_idx].valid) {
        go_to(Screen::MAIN);
        return;
    }

    const DisplayWaypoint& dw = s_waypoints[s_detail_idx];
    char buf[60];

    draw_line(2, COL_GRAY, 1, "< Back");

    // Title: "Riley's Spot"
    snprintf(buf, sizeof(buf), "%s's Spot", dw.sender);
    draw_line(24, COL_WHITE, 2, buf);

    // Position
    char lat_s[20], lon_s[20];
    format_lat(dw.wp.lat, lat_s, sizeof(lat_s));
    format_lon(dw.wp.lon, lon_s, sizeof(lon_s));
    snprintf(buf, sizeof(buf), "%s  %s", lat_s, lon_s);
    draw_line(52, COL_GREEN, 2, buf);

    // Elevation
    snprintf(buf, sizeof(buf), "%dm elevation", (int)dw.wp.ele);
    draw_line(72, COL_WHITE, 2, buf);

    // Distance
    if (hal::gps_has_fix()) {
        float d = distance_miles(hal::gps_latitude(), hal::gps_longitude(),
                                 dw.wp.lat, dw.wp.lon);
        snprintf(buf, sizeof(buf), "%.1f miles away", d);
    } else {
        snprintf(buf, sizeof(buf), "-- miles away");
    }
    draw_line(92, COL_WHITE, 2, buf);

    // Time ago
    char ago[16];
    format_time_ago(millis() - dw.received_at, ago, sizeof(ago));
    snprintf(buf, sizeof(buf), "Received %s ago", ago);
    draw_line(120, COL_GRAY, 2, buf);

    // Signal
    snprintf(buf, sizeof(buf), "Signal: %s", signal_label(dw.rssi));
    draw_line(140, COL_GRAY, 2, buf);

    draw_line(226, COL_GRAY, 1, "[Bksp] Back");
}

// ============================================================
// Input handlers
// ============================================================

static void handle_main(char key) {
    if (key == 's' || key == 'S') {
        // Open share screen
        memset(s_share_name, 0, sizeof(s_share_name));
        s_share_len = 0;
        go_to(Screen::SHARE);
    } else if (key == KEY_ENTER || key == KEY_CR) {
        // View selected waypoint detail
        if (s_wp_count > 0) {
            int sorted_idx[MAX_DISP_WP];
            int cnt = sorted_waypoints(sorted_idx, MAX_DISP_WP);
            if (s_selected < cnt) {
                s_detail_idx = sorted_idx[s_selected];
                go_to(Screen::DETAIL);
            }
        }
    } else if (key == 'j' || key == 'J') {
        if (s_selected < s_wp_count - 1) s_selected++;
    } else if (key == 'k' || key == 'K') {
        if (s_selected > 0) s_selected--;
    }
}

static void handle_share(char key) {
    // If no GPS, any key goes back
    if (!hal::gps_has_fix()) {
        go_to(Screen::MAIN);
        return;
    }

    if (key == KEY_ENTER || key == KEY_CR) {
        // Send waypoint
        if (s_share_len == 0) return; // Need a name

        bool sent = false;
        if (s_identity && s_our_lxmf_dest) {
            const net::Peer* peer = net::peer_first();
            if (peer) {
                sent = msg::waypoint_send(*s_identity, s_our_lxmf_dest,
                                          peer->dest_hash, s_share_name, "");
                Serial.printf("[UI] Waypoint sent: %s\n", s_share_name);
            } else {
                Serial.println("[UI] No peers to send to");
            }
        }

        if (sent) {
            s_confirm_start = millis();
            go_to(Screen::CONFIRM);
        } else {
            go_to(Screen::MAIN);
        }
    } else if (key == KEY_BS || key == KEY_ESC) {
        if (key == KEY_BS && s_share_len > 0) {
            // Delete last character
            s_share_name[--s_share_len] = '\0';
        } else {
            // Back to main (Esc, or Backspace when empty)
            go_to(Screen::MAIN);
        }
    } else if (key >= 32 && key < 127 && s_share_len < 20) {
        // Printable character → append
        s_share_name[s_share_len++] = key;
        s_share_name[s_share_len] = '\0';
    }
}

static void handle_detail(char key) {
    if (key == KEY_BS || key == KEY_ESC || key == KEY_ENTER || key == KEY_CR) {
        go_to(Screen::MAIN);
    }
}

// ============================================================
// Public API
// ============================================================

void ui_init() {
    memset(s_waypoints, 0, sizeof(s_waypoints));
    s_boot_start = millis();
    s_screen = Screen::BOOT;
    s_needs_clear = true;
    s_selected = 0;
    s_wp_count = 0;
    s_share_len = 0;
    s_peer_count = 0;
    Serial.println("[UI] Display UI initialized");
}

void ui_update() {
    uint32_t now = millis();

    // --- Boot screen auto-transition (2.5 seconds) ---
    if (s_screen == Screen::BOOT && (now - s_boot_start) >= 2500) {
        go_to(Screen::MAIN);
    }

    // --- Confirmation auto-dismiss (1 second) ---
    if (s_screen == Screen::CONFIRM && (now - s_confirm_start) >= 1000) {
        go_to(Screen::MAIN);
    }

    // --- Handle keyboard input ---
    char key = hal::keyboard_read();
    if (key) {
        switch (s_screen) {
            case Screen::MAIN:    handle_main(key);   break;
            case Screen::SHARE:   handle_share(key);  break;
            case Screen::DETAIL:  handle_detail(key);  break;
            case Screen::CONFIRM: /* ignore keys during confirmation */ break;
            case Screen::BOOT:    /* ignore keys during boot */ break;
        }
    }

    // --- Refresh rate limiting ---
    uint32_t interval = 0;
    switch (s_screen) {
        case Screen::BOOT:    interval = 0; break;     // Draw once
        case Screen::MAIN:    interval = 1000; break;   // 1 Hz
        case Screen::SHARE:   interval = 0; break;      // Redraw on input only handled via needs_clear
        case Screen::DETAIL:  interval = 5000; break;   // 0.2 Hz
        case Screen::CONFIRM: interval = 0; break;      // Draw once
    }

    // Redraw if dirty (screen change) or periodic refresh
    bool should_draw = s_needs_clear;
    if (!should_draw && interval > 0 && (now - s_last_refresh) >= interval) {
        should_draw = true;
    }
    // Share screen: also redraw on keypress
    if (!should_draw && s_screen == Screen::SHARE && key) {
        should_draw = true;
    }

    if (!should_draw) return;
    s_last_refresh = now;

    switch (s_screen) {
        case Screen::BOOT:    draw_boot();    break;
        case Screen::MAIN:    draw_main();    break;
        case Screen::SHARE:   draw_share();   break;
        case Screen::DETAIL:  draw_detail();  break;
        case Screen::CONFIRM: draw_confirm(); break;
    }
}

Screen ui_current_screen() {
    return s_screen;
}

void ui_on_waypoint_received(const msg::Waypoint& wp, const char* sender_name, int rssi) {
    // Find existing slot for this sender, or oldest slot
    int target = -1;
    uint32_t oldest_time = UINT32_MAX;
    int oldest_idx = 0;

    for (int i = 0; i < (int)MAX_DISP_WP; i++) {
        if (!s_waypoints[i].valid) {
            if (target < 0) target = i; // First empty slot
            continue;
        }
        // Update existing sender
        if (strncmp(s_waypoints[i].sender, sender_name, 31) == 0) {
            target = i;
            break;
        }
        // Track oldest for eviction
        if (s_waypoints[i].received_at < oldest_time) {
            oldest_time = s_waypoints[i].received_at;
            oldest_idx = i;
        }
    }

    if (target < 0) target = oldest_idx; // Evict oldest

    s_waypoints[target].wp = wp;
    strncpy(s_waypoints[target].sender, sender_name, 31);
    s_waypoints[target].sender[31] = '\0';
    s_waypoints[target].rssi = rssi;
    s_waypoints[target].received_at = millis();
    s_waypoints[target].valid = true;

    // Zero peer dest — LXMF source hash not available in this callback context
    memset(s_waypoints[target].peer_dest, 0, 16);

    Serial.printf("[UI] Waypoint stored: %s from %s (RSSI %d)\n",
                  wp.name, sender_name, rssi);
}

void ui_set_send_context(const crypto::Identity* id, const uint8_t* our_lxmf_dest) {
    s_identity = id;
    s_our_lxmf_dest = our_lxmf_dest;
}

void ui_set_peer_count(int count) {
    s_peer_count = count;
}

} // namespace ui
