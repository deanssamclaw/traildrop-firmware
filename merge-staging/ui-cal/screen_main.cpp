#include "ui.h"
#include "theme.h"
#include "hal/gps.h"
#include "hal/battery.h"
#include "config.h"
#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>
#include <cmath>

namespace ui {

// Persistent widget references for dynamic updates
static lv_obj_t* main_gps_label = nullptr;
static lv_obj_t* main_status_sats = nullptr;
static lv_obj_t* main_status_peers = nullptr;
static lv_obj_t* main_status_batt = nullptr;
static lv_obj_t* main_wp_container = nullptr;

// Forward declarations
void screen_main_update();

// Back callback (used by sub-screens to navigate here)
static void nav_drop_cb(lv_event_t* e) { ui_show(SCREEN_DROP); }
static void nav_peers_cb(lv_event_t* e) { ui_show(SCREEN_PEERS); }
static void nav_settings_cb(lv_event_t* e) { ui_show(SCREEN_SETTINGS); }

// Waypoint row tap handler
static void wp_row_cb(lv_event_t* e) {
    int idx = (int)(intptr_t)lv_event_get_user_data(e);
    ui_set_selected_waypoint(idx);
    ui_show(SCREEN_DETAIL);
}

// Format time ago string
static void format_time_ago(uint32_t elapsed_ms, char* buf, size_t len) {
    uint32_t sec = elapsed_ms / 1000;
    if (sec < 60)        snprintf(buf, len, "%lus ago", (unsigned long)sec);
    else if (sec < 3600) snprintf(buf, len, "%lum ago", (unsigned long)(sec / 60));
    else                 snprintf(buf, len, "%luh ago", (unsigned long)(sec / 3600));
}

// Format distance string (placeholder — needs user position)
static void format_distance(double lat1, double lon1, double lat2, double lon2,
                            char* buf, size_t len) {
    if (lat1 == 0.0 && lon1 == 0.0) {
        snprintf(buf, len, "--");
        return;
    }
    // Haversine approximation
    double dlat = (lat2 - lat1) * 0.017453293;
    double dlon = (lon2 - lon1) * 0.017453293;
    double a = sin(dlat/2) * sin(dlat/2) +
               cos(lat1 * 0.017453293) * cos(lat2 * 0.017453293) *
               sin(dlon/2) * sin(dlon/2);
    double c = 2 * atan2(sqrt(a), sqrt(1-a));
    double miles = c * 3958.8;

    if (miles < 0.1)      snprintf(buf, len, "%dft", (int)(miles * 5280));
    else if (miles < 10)  snprintf(buf, len, "%.1fmi", miles);
    else                  snprintf(buf, len, "%dmi", (int)miles);
}

static void build_waypoint_list(lv_obj_t* container) {
    // Clear existing children (except the section label)
    uint32_t child_count = lv_obj_get_child_cnt(container);
    for (int i = child_count - 1; i >= 0; i--) {
        lv_obj_del(lv_obj_get_child(container, i));
    }

    UiWaypoint* wps = ui_get_waypoints();
    uint32_t now = millis();
    int displayed = 0;

    for (int i = 0; i < MAX_UI_WAYPOINTS && displayed < 8; i++) {
        if (!wps[i].valid) continue;

        lv_obj_t* row = lv_obj_create(container);
        lv_obj_set_size(row, lv_pct(100), 28);
        lv_obj_set_style_bg_color(row, CLR_CARD, 0);
        lv_obj_set_style_bg_opa(row, LV_OPA_COVER, 0);
        lv_obj_set_style_border_width(row, 0, 0);
        lv_obj_set_style_pad_all(row, 4, 0);
        lv_obj_set_style_pad_hor(row, 6, 0);
        lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
        lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_add_flag(row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(row, wp_row_cb, LV_EVENT_CLICKED, (void*)(intptr_t)i);

        // Sender name
        lv_obj_t* sender = lv_label_create(row);
        lv_label_set_text(sender, wps[i].sender);
        lv_obj_set_style_text_font(sender, &lv_font_montserrat_12, 0);
        lv_obj_set_width(sender, 65);
        lv_label_set_long_mode(sender, LV_LABEL_LONG_CLIP);

        // Waypoint name
        lv_obj_t* name = lv_label_create(row);
        lv_label_set_text(name, wps[i].name);
        lv_obj_set_style_text_font(name, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(name, CLR_CYAN, 0);
        lv_obj_set_width(name, 80);
        lv_label_set_long_mode(name, LV_LABEL_LONG_CLIP);

        // Distance
        char dist_buf[16];
        double my_lat = hal::gps_has_fix() ? hal::gps_latitude() : 0.0;
        double my_lon = hal::gps_has_fix() ? hal::gps_longitude() : 0.0;
        format_distance(my_lat, my_lon, wps[i].lat, wps[i].lon, dist_buf, sizeof(dist_buf));
        lv_obj_t* dist = lv_label_create(row);
        lv_label_set_text(dist, dist_buf);
        lv_obj_set_style_text_font(dist, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(dist, CLR_DIM, 0);
        lv_obj_set_width(dist, 40);

        // Time ago
        char time_buf[16];
        format_time_ago(now - wps[i].received_at, time_buf, sizeof(time_buf));
        lv_obj_t* tago = lv_label_create(row);
        lv_label_set_text(tago, time_buf);
        lv_obj_set_style_text_font(tago, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(tago, CLR_DIM, 0);

        displayed++;
    }

    if (displayed == 0) {
        lv_obj_t* empty = lv_label_create(container);
        lv_label_set_text(empty, "No waypoints received");
        lv_obj_set_style_text_color(empty, CLR_DIM, 0);
        lv_obj_set_style_text_font(empty, &lv_font_montserrat_12, 0);
    }
}

lv_obj_t* screen_main_create() {
    lv_obj_t* scr = lv_obj_create(NULL);
    theme_apply_screen(scr);

    // === Status bar (top) ===
    lv_obj_t* status = lv_obj_create(scr);
    lv_obj_add_style(status, &style_status_bar, 0);
    lv_obj_set_size(status, 320, 24);
    lv_obj_set_pos(status, 0, 0);
    lv_obj_clear_flag(status, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(status, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(status, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    lv_obj_t* app_name = lv_label_create(status);
    lv_label_set_text(app_name, "TrailDrop");
    lv_obj_set_style_text_font(app_name, &lv_font_montserrat_12, 0);

    main_status_sats = lv_label_create(status);
    lv_obj_set_style_text_font(main_status_sats, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(main_status_sats, CLR_DIM, 0);

    main_status_peers = lv_label_create(status);
    lv_obj_set_style_text_font(main_status_peers, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(main_status_peers, CLR_GREEN, 0);

    main_status_batt = lv_label_create(status);
    lv_obj_set_style_text_font(main_status_batt, &lv_font_montserrat_12, 0);
    lv_obj_set_style_text_color(main_status_batt, CLR_DIM, 0);

    // === GPS card ===
    lv_obj_t* gps_card = theme_card(scr);
    lv_obj_set_pos(gps_card, 6, 28);
    lv_obj_set_width(gps_card, 308);

    main_gps_label = lv_label_create(gps_card);
    lv_obj_set_style_text_font(main_gps_label, &lv_font_montserrat_14, 0);

    // === Waypoint section ===
    lv_obj_t* wp_section = theme_section_label(scr, "WAYPOINTS");
    lv_obj_set_pos(wp_section, 8, 72);

    // Waypoint list container
    main_wp_container = lv_obj_create(scr);
    lv_obj_add_style(main_wp_container, &style_card, 0);
    lv_obj_set_pos(main_wp_container, 6, 86);
    lv_obj_set_size(main_wp_container, 308, 100);
    lv_obj_set_flex_flow(main_wp_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(main_wp_container, 2, 0);
    lv_obj_set_style_pad_all(main_wp_container, 4, 0);
    lv_obj_add_flag(main_wp_container, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(main_wp_container, LV_DIR_VER);

    build_waypoint_list(main_wp_container);

    // === Bottom nav (3 buttons) ===
    int btn_y = 194;
    int btn_w = 96;
    int btn_h = 40;
    int gap = 6;
    int start_x = 6;

    lv_obj_t* drop_btn = theme_btn_green(scr, "+ DROP", btn_w, btn_h);
    lv_obj_set_pos(drop_btn, start_x, btn_y);
    lv_obj_add_event_cb(drop_btn, nav_drop_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t* peers_btn = theme_btn(scr, "PEERS", btn_w, btn_h);
    lv_obj_set_pos(peers_btn, start_x + btn_w + gap, btn_y);
    lv_obj_add_event_cb(peers_btn, nav_peers_cb, LV_EVENT_CLICKED, NULL);

    lv_obj_t* settings_btn = theme_btn(scr, "SETTINGS", btn_w, btn_h);
    lv_obj_set_pos(settings_btn, start_x + 2 * (btn_w + gap), btn_y);
    lv_obj_add_event_cb(settings_btn, nav_settings_cb, LV_EVENT_CLICKED, NULL);

    // Initial data update
    screen_main_update();

    return scr;
}

void screen_main_update() {
    if (!main_gps_label) return;

    // GPS card
    if (hal::gps_has_fix()) {
        char buf[80];
        snprintf(buf, sizeof(buf), "%.4f N  %.4f W     %d ft",
                 fabs(hal::gps_latitude()),
                 fabs(hal::gps_longitude()),
                 (int)(hal::gps_altitude() * 3.281f));
        lv_label_set_text(main_gps_label, buf);
        lv_obj_set_style_text_color(main_gps_label, CLR_GREEN, 0);
    } else {
        lv_label_set_text(main_gps_label, "Searching for GPS...");
        lv_obj_set_style_text_color(main_gps_label, CLR_CYAN, 0);
    }

    // Status bar items
    if (main_status_sats) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%dsat", (int)hal::gps_satellites());
        lv_label_set_text(main_status_sats, buf);
    }

    if (main_status_peers) {
        char buf[16];
        snprintf(buf, sizeof(buf), "*%d peers", ui_get_peer_count());
        lv_label_set_text(main_status_peers, buf);
    }

    if (main_status_batt) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d%%", hal::battery_percent());
        lv_label_set_text(main_status_batt, buf);
    }

    // Rebuild waypoint list
    if (main_wp_container) {
        build_waypoint_list(main_wp_container);
    }
}

} // namespace ui
