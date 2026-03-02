#include "ui.h"
#include "theme.h"
#include "hal/gps.h"
#include "config.h"
#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>
#include <cmath>

namespace ui {

static lv_obj_t* detail_dist_val = nullptr;
static lv_obj_t* detail_time_val = nullptr;

static void back_cb(lv_event_t* e) { ui_back(); }

static const char* signal_label(int16_t rssi) {
    if (rssi > -60)  return "Strong";
    if (rssi > -80)  return "Good";
    if (rssi > -100) return "Weak";
    return "Faint";
}

static lv_color_t signal_color(int16_t rssi) {
    if (rssi > -60)  return CLR_GREEN;
    if (rssi > -80)  return CLR_CYAN;
    if (rssi > -100) return CLR_YELLOW;
    return CLR_RED;
}

lv_obj_t* screen_detail_create() {
    lv_obj_t* scr = lv_obj_create(NULL);
    theme_apply_screen(scr);

    int idx = ui_get_selected_waypoint();
    UiWaypoint* wps = ui_get_waypoints();
    if (idx < 0 || idx >= MAX_UI_WAYPOINTS || !wps[idx].valid) {
        // No waypoint selected — show placeholder
        theme_top_bar(scr, "Detail", back_cb);
        lv_obj_t* lbl = lv_label_create(scr);
        lv_label_set_text(lbl, "No waypoint selected");
        lv_obj_set_style_text_color(lbl, CLR_DIM, 0);
        lv_obj_align(lbl, LV_ALIGN_CENTER, 0, 0);
        detail_dist_val = nullptr;
        detail_time_val = nullptr;
        return scr;
    }

    UiWaypoint& wp = wps[idx];

    // Top bar
    theme_top_bar(scr, "", back_cb);

    // Sender + waypoint name
    lv_obj_t* sender_lbl = lv_label_create(scr);
    char title_buf[96];
    snprintf(title_buf, sizeof(title_buf), "%s's Spot", wp.sender);
    lv_label_set_text(sender_lbl, title_buf);
    lv_obj_set_style_text_font(sender_lbl, &lv_font_montserrat_16, 0);
    lv_obj_set_pos(sender_lbl, 10, 34);

    lv_obj_t* name_lbl = lv_label_create(scr);
    lv_label_set_text(name_lbl, wp.name);
    lv_obj_set_style_text_color(name_lbl, CLR_DIM, 0);
    lv_obj_set_style_text_font(name_lbl, &lv_font_montserrat_14, 0);
    lv_obj_set_pos(name_lbl, 10, 54);

    // Detail card
    lv_obj_t* card = theme_card(scr);
    lv_obj_set_pos(card, 6, 76);
    lv_obj_set_width(card, 308);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(card, 0, 0);

    // Position
    char pos_buf[64];
    snprintf(pos_buf, sizeof(pos_buf), "%.4f %c  %.4f %c",
             fabs(wp.lat), wp.lat >= 0 ? 'N' : 'S',
             fabs(wp.lon), wp.lon >= 0 ? 'E' : 'W');
    theme_detail_row(card, "Position", pos_buf);
    theme_divider(card);

    // Elevation
    char elev_buf[32];
    snprintf(elev_buf, sizeof(elev_buf), "%d ft", (int)(wp.altitude * 3.281f));
    theme_detail_row(card, "Elevation", elev_buf);
    theme_divider(card);

    // Distance
    char dist_buf[32];
    if (hal::gps_has_fix()) {
        double dlat = (wp.lat - hal::gps_latitude()) * 0.017453293;
        double dlon = (wp.lon - hal::gps_longitude()) * 0.017453293;
        double a = sin(dlat/2)*sin(dlat/2) +
                   cos(hal::gps_latitude()*0.017453293)*cos(wp.lat*0.017453293)*
                   sin(dlon/2)*sin(dlon/2);
        double c = 2*atan2(sqrt(a), sqrt(1-a));
        double miles = c * 3958.8;
        if (miles < 0.1) snprintf(dist_buf, sizeof(dist_buf), "%d ft", (int)(miles*5280));
        else snprintf(dist_buf, sizeof(dist_buf), "%.1f miles", miles);
    } else {
        snprintf(dist_buf, sizeof(dist_buf), "-- (no GPS)");
    }
    theme_detail_row(card, "Distance", dist_buf, &detail_dist_val);
    theme_divider(card);

    // Signal
    char sig_buf[32];
    snprintf(sig_buf, sizeof(sig_buf), "%s (%d dBm)", signal_label(wp.rssi), wp.rssi);
    lv_obj_t* sig_val = nullptr;
    theme_detail_row(card, "Signal", sig_buf, &sig_val);
    if (sig_val) lv_obj_set_style_text_color(sig_val, signal_color(wp.rssi), 0);
    theme_divider(card);

    // Received
    char time_buf[32];
    uint32_t elapsed = (millis() - wp.received_at) / 1000;
    if (elapsed < 60)        snprintf(time_buf, sizeof(time_buf), "%lu sec ago", (unsigned long)elapsed);
    else if (elapsed < 3600) snprintf(time_buf, sizeof(time_buf), "%lu min ago", (unsigned long)(elapsed/60));
    else                     snprintf(time_buf, sizeof(time_buf), "%lu hr ago", (unsigned long)(elapsed/3600));
    theme_detail_row(card, "Received", time_buf, &detail_time_val);

    return scr;
}

void screen_detail_update() {
    // Update distance and time dynamically
    int idx = ui_get_selected_waypoint();
    UiWaypoint* wps = ui_get_waypoints();
    if (idx < 0 || idx >= MAX_UI_WAYPOINTS || !wps[idx].valid) return;

    UiWaypoint& wp = wps[idx];

    if (detail_time_val) {
        char time_buf[32];
        uint32_t elapsed = (millis() - wp.received_at) / 1000;
        if (elapsed < 60)        snprintf(time_buf, sizeof(time_buf), "%lu sec ago", (unsigned long)elapsed);
        else if (elapsed < 3600) snprintf(time_buf, sizeof(time_buf), "%lu min ago", (unsigned long)(elapsed/60));
        else                     snprintf(time_buf, sizeof(time_buf), "%lu hr ago", (unsigned long)(elapsed/3600));
        lv_label_set_text(detail_time_val, time_buf);
    }
}

} // namespace ui
