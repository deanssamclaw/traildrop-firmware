#include "ui.h"
#include "theme.h"
#include "hal/display.h"
#include "config.h"
#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>

namespace ui {

static lv_obj_t* brightness_slider = nullptr;
static uint8_t current_brightness = BACKLIGHT_DEFAULT;

static void back_cb(lv_event_t* e) { ui_back(); }
static void nav_emergency_cb(lv_event_t* e) { ui_show(SCREEN_EMERGENCY); }

static void brightness_cb(lv_event_t* e) {
    lv_obj_t* slider = lv_event_get_target(e);
    current_brightness = (uint8_t)lv_slider_get_value(slider);
    hal::display_set_backlight(current_brightness);
}

// TX power cycling
static const int tx_power_values[] = {2, 7, 10, 14, 17, 20, 22};
static const int tx_power_count = 7;
static int tx_power_idx = 1;  // Default: 7 dBm
static lv_obj_t* tx_power_val = nullptr;

static void tx_power_cb(lv_event_t* e) {
    tx_power_idx = (tx_power_idx + 1) % tx_power_count;
    if (tx_power_val) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%d dBm", tx_power_values[tx_power_idx]);
        lv_label_set_text(tx_power_val, buf);
    }
    // TODO: Apply to radio when hal supports runtime config
}

// Frequency cycling
static const float freq_values[] = {902.0, 906.0, 910.0, 915.0, 920.0, 925.0, 928.0};
static const int freq_count = 7;
static int freq_idx = 3;  // Default: 915.0 MHz
static lv_obj_t* freq_val = nullptr;

static void freq_cb(lv_event_t* e) {
    freq_idx = (freq_idx + 1) % freq_count;
    if (freq_val) {
        char buf[16];
        snprintf(buf, sizeof(buf), "%.1f MHz", freq_values[freq_idx]);
        lv_label_set_text(freq_val, buf);
    }
    // TODO: Apply to radio when hal supports runtime config
}

lv_obj_t* screen_settings_create() {
    lv_obj_t* scr = lv_obj_create(NULL);
    theme_apply_screen(scr);

    // Top bar
    theme_top_bar(scr, "Settings", back_cb);

    int y = 32;

    // Settings card
    lv_obj_t* card = theme_card(scr);
    lv_obj_set_pos(card, 6, y);
    lv_obj_set_width(card, 308);
    lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(card, 0, 0);

    // Name row (display only for now)
    theme_detail_row(card, "Name", "TrailDrop");
    theme_divider(card);

    // TX Power (tappable to cycle)
    char tx_buf[16];
    snprintf(tx_buf, sizeof(tx_buf), "%d dBm", tx_power_values[tx_power_idx]);
    lv_obj_t* tx_row_val = nullptr;
    theme_detail_row(card, "TX Power", tx_buf, &tx_row_val);
    tx_power_val = tx_row_val;
    // Make the row's parent clickable
    if (tx_power_val) {
        lv_obj_t* tx_row = lv_obj_get_parent(tx_power_val);
        lv_obj_add_flag(tx_row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(tx_row, tx_power_cb, LV_EVENT_CLICKED, NULL);
    }
    theme_divider(card);

    // Frequency (tappable to cycle)
    char freq_buf[16];
    snprintf(freq_buf, sizeof(freq_buf), "%.1f MHz", freq_values[freq_idx]);
    lv_obj_t* freq_row_val = nullptr;
    theme_detail_row(card, "Frequency", freq_buf, &freq_row_val);
    freq_val = freq_row_val;
    if (freq_val) {
        lv_obj_t* freq_row = lv_obj_get_parent(freq_val);
        lv_obj_add_flag(freq_row, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_event_cb(freq_row, freq_cb, LV_EVENT_CLICKED, NULL);
    }
    theme_divider(card);

    // Brightness slider row
    lv_obj_t* br_row = lv_obj_create(card);
    lv_obj_set_size(br_row, lv_pct(100), 30);
    lv_obj_set_style_bg_opa(br_row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(br_row, 0, 0);
    lv_obj_set_style_pad_all(br_row, 2, 0);
    lv_obj_set_flex_flow(br_row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(br_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                          LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(br_row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* br_lbl = lv_label_create(br_row);
    lv_label_set_text(br_lbl, "Brightness");
    lv_obj_set_style_text_color(br_lbl, CLR_DIM, 0);
    lv_obj_set_style_text_font(br_lbl, &lv_font_montserrat_12, 0);

    brightness_slider = lv_slider_create(br_row);
    lv_obj_set_width(brightness_slider, 160);
    lv_slider_set_range(brightness_slider, 10, 255);
    lv_slider_set_value(brightness_slider, current_brightness, LV_ANIM_OFF);
    lv_obj_set_style_bg_color(brightness_slider, CLR_CARD_BORDER, LV_PART_MAIN);
    lv_obj_set_style_bg_color(brightness_slider, CLR_GREEN, LV_PART_INDICATOR);
    lv_obj_set_style_bg_color(brightness_slider, CLR_TEXT, LV_PART_KNOB);
    lv_obj_set_style_pad_all(brightness_slider, 3, LV_PART_KNOB);
    lv_obj_add_event_cb(brightness_slider, brightness_cb, LV_EVENT_VALUE_CHANGED, NULL);

    y += lv_obj_get_height(card) + 8;

    // ABOUT section
    lv_obj_t* about_sec = theme_section_label(scr, "ABOUT");
    lv_obj_set_pos(about_sec, 8, 170);

    lv_obj_t* about_card = theme_card(scr);
    lv_obj_set_pos(about_card, 6, 184);
    lv_obj_set_width(about_card, 308);
    lv_obj_set_flex_flow(about_card, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(about_card, 2, 0);

    char ver_buf[32];
    snprintf(ver_buf, sizeof(ver_buf), "TrailDrop v%s", APP_VERSION);
    lv_obj_t* ver_lbl = lv_label_create(about_card);
    lv_label_set_text(ver_lbl, ver_buf);
    lv_obj_set_style_text_font(ver_lbl, &lv_font_montserrat_12, 0);

    lv_obj_t* hw_lbl = lv_label_create(about_card);
    lv_label_set_text(hw_lbl, "T-Deck Plus / ESP32-S3");
    lv_obj_set_style_text_color(hw_lbl, CLR_DIM, 0);
    lv_obj_set_style_text_font(hw_lbl, &lv_font_montserrat_12, 0);

    // Emergency nav
    lv_obj_t* emer_btn = theme_btn_red(scr, "EMERGENCY", 308, 0);
    // Position below about card — will be at bottom if space allows
    // For now, skip it on this screen and access via MAIN or dedicated button

    return scr;
}

void screen_settings_update() {
    // Settings are mostly static — brightness slider is live via callback
}

} // namespace ui
