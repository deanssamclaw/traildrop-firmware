#include "ui.h"
#include "theme.h"
#include "hal/gps.h"
#include "config.h"
#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>
#include <cmath>

namespace ui {

static bool sos_active = false;
static lv_obj_t* sos_btn = nullptr;
static lv_obj_t* sos_btn_label = nullptr;
static lv_obj_t* status_val = nullptr;
static lv_obj_t* position_val = nullptr;
static lv_obj_t* interval_val = nullptr;
static uint32_t sos_started = 0;

static void back_cb(lv_event_t* e) { ui_back(); }

static void update_sos_visuals() {
    if (!sos_btn || !sos_btn_label || !status_val) return;

    if (sos_active) {
        lv_obj_set_style_bg_color(sos_btn, CLR_RED, 0);
        lv_obj_set_style_border_color(sos_btn, lv_color_hex(0xFF6666), 0);
        lv_label_set_text(sos_btn_label, "SOS ACTIVE\nTap to cancel");
        lv_label_set_text(status_val, "BROADCASTING");
        lv_obj_set_style_text_color(status_val, CLR_RED, 0);
    } else {
        lv_obj_set_style_bg_color(sos_btn, CLR_RED_BG, 0);
        lv_obj_set_style_border_color(sos_btn, CLR_RED, 0);
        lv_label_set_text(sos_btn_label, "SOS BEACON\nTap to activate");
        lv_label_set_text(status_val, "OFF");
        lv_obj_set_style_text_color(status_val, CLR_DIM, 0);
    }
}

static void sos_cb(lv_event_t* e) {
    sos_active = !sos_active;
    if (sos_active) {
        sos_started = millis();
        Serial.println("[SOS] Emergency beacon ACTIVATED");
    } else {
        Serial.println("[SOS] Emergency beacon deactivated");
    }
    update_sos_visuals();
}

lv_obj_t* screen_emergency_create() {
    lv_obj_t* scr = lv_obj_create(NULL);
    theme_apply_screen(scr);

    // Top bar
    theme_top_bar(scr, "Emergency", back_cb);

    // Large SOS button — centered
    sos_btn = lv_btn_create(scr);
    lv_obj_set_size(sos_btn, 200, 80);
    lv_obj_align(sos_btn, LV_ALIGN_CENTER, 0, -30);
    lv_obj_set_style_bg_color(sos_btn, CLR_RED_BG, 0);
    lv_obj_set_style_bg_opa(sos_btn, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(sos_btn, CLR_RED, 0);
    lv_obj_set_style_border_width(sos_btn, 2, 0);
    lv_obj_set_style_radius(sos_btn, 8, 0);
    lv_obj_set_style_shadow_width(sos_btn, 0, 0);
    lv_obj_add_event_cb(sos_btn, sos_cb, LV_EVENT_CLICKED, NULL);

    sos_btn_label = lv_label_create(sos_btn);
    lv_label_set_text(sos_btn_label, "SOS BEACON\nTap to activate");
    lv_obj_set_style_text_color(sos_btn_label, CLR_RED, 0);
    lv_obj_set_style_text_font(sos_btn_label, &lv_font_montserrat_16, 0);
    lv_obj_set_style_text_align(sos_btn_label, LV_TEXT_ALIGN_CENTER, 0);
    lv_obj_center(sos_btn_label);

    // Status card
    lv_obj_t* card = theme_card(scr);
    lv_obj_set_pos(card, 6, 160);
    lv_obj_set_width(card, 308);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(card, 0, 0);

    theme_detail_row(card, "Status", "OFF", &status_val);
    theme_divider(card);

    theme_detail_row(card, "Position", "--", &position_val);
    theme_divider(card);

    theme_detail_row(card, "Interval", "30 sec", &interval_val);

    // Apply current state
    update_sos_visuals();

    return scr;
}

void screen_emergency_update() {
    // Update position in status card
    if (position_val) {
        if (hal::gps_has_fix()) {
            char buf[48];
            snprintf(buf, sizeof(buf), "%.4f %c  %.4f %c",
                     fabs(hal::gps_latitude()),
                     hal::gps_latitude() >= 0 ? 'N' : 'S',
                     fabs(hal::gps_longitude()),
                     hal::gps_longitude() >= 0 ? 'E' : 'W');
            lv_label_set_text(position_val, buf);
        } else {
            lv_label_set_text(position_val, "No GPS fix");
        }
    }

    // TODO: When active, broadcast SOS via radio at interval
}

} // namespace ui
