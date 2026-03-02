#include "ui.h"
#include "theme.h"
#include "hal/gps.h"
#include "config.h"
#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>
#include <cmath>

namespace ui {

static lv_obj_t* drop_gps_label = nullptr;
static lv_obj_t* drop_name_ta = nullptr;
static lv_obj_t* drop_share_btn = nullptr;
static lv_obj_t* drop_no_gps_label = nullptr;
static int selected_category = -1;
static lv_obj_t* cat_btns[6] = {nullptr};

static const char* category_labels[] = {
    "Campsite", "Water", "Hazard", "Viewpoint", "Trail", "Shelter"
};
static const app::WaypointCategory category_values[] = {
    app::CAMP, app::WATER, app::HAZARD, app::SCENIC, app::INFO, app::EMERGENCY
};

// Forward declarations
void screen_drop_update();

static void back_cb(lv_event_t* e) { ui_back(); }

static void update_share_button_state() {
    if (!drop_share_btn) return;
    bool has_name = drop_name_ta && lv_textarea_get_text(drop_name_ta)[0] != '\0';
    bool has_gps = hal::gps_has_fix();

    if (has_name && has_gps && selected_category >= 0) {
        lv_obj_clear_state(drop_share_btn, LV_STATE_DISABLED);
        lv_obj_set_style_bg_opa(drop_share_btn, LV_OPA_COVER, 0);
    } else {
        lv_obj_add_state(drop_share_btn, LV_STATE_DISABLED);
        lv_obj_set_style_bg_opa(drop_share_btn, LV_OPA_50, 0);
    }
}

static void category_cb(lv_event_t* e) {
    int idx = (int)(intptr_t)lv_event_get_user_data(e);

    // Deselect previous
    if (selected_category >= 0 && selected_category < 6 && cat_btns[selected_category]) {
        lv_obj_add_style(cat_btns[selected_category], &style_btn, 0);
    }

    selected_category = idx;

    // Highlight selected
    if (cat_btns[idx]) {
        lv_obj_add_style(cat_btns[idx], &style_btn_green, 0);
    }

    update_share_button_state();
}

static void ta_event_cb(lv_event_t* e) {
    lv_event_code_t code = lv_event_get_code(e);
    if (code == LV_EVENT_VALUE_CHANGED) {
        update_share_button_state();
    }
}

static void share_cb(lv_event_t* e) {
    if (!drop_name_ta || !hal::gps_has_fix() || selected_category < 0) return;

    const char* name = lv_textarea_get_text(drop_name_ta);
    if (name[0] == '\0') return;

    // TODO: Wire to msg::waypoint_send() when available
    // For now, add to local waypoint list as confirmation
    ui_on_waypoint_received("Me", name,
                            hal::gps_latitude(), hal::gps_longitude(),
                            hal::gps_altitude(),
                            category_values[selected_category], 0);

    Serial.printf("[UI] Shared waypoint: %s (%.4f, %.4f) cat=%d\n",
                  name, hal::gps_latitude(), hal::gps_longitude(), selected_category);

    // Show brief confirmation overlay
    lv_obj_t* mbox = lv_msgbox_create(NULL, NULL, "Shared!", NULL, true);
    lv_obj_set_style_bg_color(mbox, CLR_GREEN_BG, 0);
    lv_obj_set_style_border_color(mbox, CLR_GREEN, 0);
    lv_obj_set_style_border_width(mbox, 1, 0);
    lv_obj_set_style_text_color(mbox, CLR_GREEN, 0);
    lv_obj_center(mbox);

    // Auto-dismiss after 1.5s and navigate back
    lv_timer_create([](lv_timer_t* t) {
        lv_timer_del(t);
        lv_msgbox_close(lv_obj_get_parent(lv_scr_act()));  // Close if still open
        ui_back();
    }, 1500, NULL);
}

lv_obj_t* screen_drop_create() {
    lv_obj_t* scr = lv_obj_create(NULL);
    theme_apply_screen(scr);

    selected_category = -1;

    // Top bar
    theme_top_bar(scr, "Drop Waypoint", back_cb);

    int y = 32;

    // GPS position card (or no-fix warning)
    lv_obj_t* gps_card = theme_card(scr);
    lv_obj_set_pos(gps_card, 6, y);
    lv_obj_set_width(gps_card, 308);
    drop_gps_label = lv_label_create(gps_card);
    lv_obj_set_style_text_font(drop_gps_label, &lv_font_montserrat_12, 0);
    y += 38;

    // No GPS warning (hidden when fix available)
    drop_no_gps_label = nullptr;

    // NAME section
    lv_obj_t* name_sec = theme_section_label(scr, "NAME");
    lv_obj_set_pos(name_sec, 8, y);
    y += 14;

    // Text input
    drop_name_ta = lv_textarea_create(scr);
    lv_obj_set_pos(drop_name_ta, 6, y);
    lv_obj_set_size(drop_name_ta, 308, 32);
    lv_textarea_set_one_line(drop_name_ta, true);
    lv_textarea_set_max_length(drop_name_ta, 60);
    lv_textarea_set_placeholder_text(drop_name_ta, "Waypoint name...");
    // Style the textarea
    lv_obj_set_style_bg_color(drop_name_ta, CLR_CARD, 0);
    lv_obj_set_style_bg_opa(drop_name_ta, LV_OPA_COVER, 0);
    lv_obj_set_style_border_color(drop_name_ta, CLR_CARD_BORDER, 0);
    lv_obj_set_style_border_width(drop_name_ta, 1, 0);
    lv_obj_set_style_text_color(drop_name_ta, CLR_TEXT, 0);
    lv_obj_set_style_text_font(drop_name_ta, &lv_font_montserrat_14, 0);
    lv_obj_set_style_radius(drop_name_ta, 4, 0);
    // Cursor color
    lv_obj_set_style_border_color(drop_name_ta, CLR_CYAN, LV_PART_CURSOR | LV_STATE_FOCUSED);
    lv_obj_add_event_cb(drop_name_ta, ta_event_cb, LV_EVENT_VALUE_CHANGED, NULL);
    y += 38;

    // CATEGORY section
    lv_obj_t* cat_sec = theme_section_label(scr, "CATEGORY");
    lv_obj_set_pos(cat_sec, 8, y);
    y += 14;

    // 2x3 category grid
    int cat_w = 96;
    int cat_h = 30;
    int cat_gap = 6;
    for (int i = 0; i < 6; i++) {
        int col = i % 3;
        int row = i / 3;
        int cx = 6 + col * (cat_w + cat_gap);
        int cy = y + row * (cat_h + cat_gap);

        cat_btns[i] = theme_btn(scr, category_labels[i], cat_w, cat_h);
        lv_obj_set_pos(cat_btns[i], cx, cy);
        lv_obj_add_event_cb(cat_btns[i], category_cb, LV_EVENT_CLICKED, (void*)(intptr_t)i);
    }
    y += 2 * (cat_h + cat_gap) + 4;

    // SHARE button
    drop_share_btn = theme_btn_green(scr, "SHARE WITH PEERS", 308, 40);
    lv_obj_set_pos(drop_share_btn, 6, y);
    lv_obj_add_event_cb(drop_share_btn, share_cb, LV_EVENT_CLICKED, NULL);

    // Initial state check
    screen_drop_update();
    update_share_button_state();

    return scr;
}

void screen_drop_update() {
    if (!drop_gps_label) return;

    if (hal::gps_has_fix()) {
        char buf[80];
        snprintf(buf, sizeof(buf), "%.4f %c  %.4f %c    %d ft",
                 fabs(hal::gps_latitude()),
                 hal::gps_latitude() >= 0 ? 'N' : 'S',
                 fabs(hal::gps_longitude()),
                 hal::gps_longitude() >= 0 ? 'E' : 'W',
                 (int)(hal::gps_altitude() * 3.281f));
        lv_label_set_text(drop_gps_label, buf);
        lv_obj_set_style_text_color(drop_gps_label, CLR_GREEN, 0);
    } else {
        lv_label_set_text(drop_gps_label, "No GPS Fix — waiting...");
        lv_obj_set_style_text_color(drop_gps_label, CLR_YELLOW, 0);
    }

    update_share_button_state();
}

} // namespace ui
