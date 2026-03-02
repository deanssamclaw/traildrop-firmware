#include "ui.h"
#include "theme.h"
#include "config.h"
#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>

namespace ui {

static lv_obj_t* peers_container = nullptr;
static lv_obj_t* peers_title = nullptr;

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

static void build_peer_list(lv_obj_t* container) {
    // Clear existing children
    uint32_t cnt = lv_obj_get_child_cnt(container);
    for (int i = cnt - 1; i >= 0; i--) {
        lv_obj_del(lv_obj_get_child(container, i));
    }

    UiPeer* peers = ui_get_peers();
    uint32_t now = millis();
    int displayed = 0;

    for (int i = 0; i < MAX_UI_PEERS; i++) {
        if (!peers[i].valid) continue;

        lv_obj_t* card = lv_obj_create(container);
        lv_obj_add_style(card, &style_card, 0);
        lv_obj_set_width(card, lv_pct(100));
        lv_obj_set_height(card, LV_SIZE_CONTENT);
        lv_obj_set_flex_flow(card, LV_FLEX_FLOW_COLUMN);
        lv_obj_set_style_pad_all(card, 6, 0);
        lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);

        // Peer name
        lv_obj_t* name = lv_label_create(card);
        lv_label_set_text(name, peers[i].name);
        lv_obj_set_style_text_font(name, &lv_font_montserrat_14, 0);

        // Signal + time row
        lv_obj_t* info_row = lv_obj_create(card);
        lv_obj_set_size(info_row, lv_pct(100), LV_SIZE_CONTENT);
        lv_obj_set_style_bg_opa(info_row, LV_OPA_TRANSP, 0);
        lv_obj_set_style_border_width(info_row, 0, 0);
        lv_obj_set_style_pad_all(info_row, 0, 0);
        lv_obj_set_flex_flow(info_row, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(info_row, LV_FLEX_ALIGN_SPACE_BETWEEN,
                              LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
        lv_obj_clear_flag(info_row, LV_OBJ_FLAG_SCROLLABLE);

        // Signal label
        char sig_buf[32];
        snprintf(sig_buf, sizeof(sig_buf), "Signal: %s (%d)", signal_label(peers[i].rssi), peers[i].rssi);
        lv_obj_t* sig = lv_label_create(info_row);
        lv_label_set_text(sig, sig_buf);
        lv_obj_set_style_text_font(sig, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(sig, signal_color(peers[i].rssi), 0);

        // Time ago
        char time_buf[16];
        uint32_t elapsed = (now - peers[i].last_seen) / 1000;
        if (elapsed < 60)        snprintf(time_buf, sizeof(time_buf), "%lus ago", (unsigned long)elapsed);
        else if (elapsed < 3600) snprintf(time_buf, sizeof(time_buf), "%lum ago", (unsigned long)(elapsed/60));
        else                     snprintf(time_buf, sizeof(time_buf), "%luh ago", (unsigned long)(elapsed/3600));
        lv_obj_t* tago = lv_label_create(info_row);
        lv_label_set_text(tago, time_buf);
        lv_obj_set_style_text_font(tago, &lv_font_montserrat_12, 0);
        lv_obj_set_style_text_color(tago, CLR_DIM, 0);

        displayed++;
    }

    if (displayed == 0) {
        lv_obj_t* empty = lv_label_create(container);
        lv_label_set_text(empty, "No peers discovered");
        lv_obj_set_style_text_color(empty, CLR_DIM, 0);
        lv_obj_set_style_text_font(empty, &lv_font_montserrat_14, 0);
        lv_obj_center(empty);
    }
}

lv_obj_t* screen_peers_create() {
    lv_obj_t* scr = lv_obj_create(NULL);
    theme_apply_screen(scr);

    // Top bar with count
    char title_buf[32];
    snprintf(title_buf, sizeof(title_buf), "Peers (%d)", ui_get_peer_count());
    theme_top_bar(scr, title_buf, back_cb);

    // Peer list container (scrollable)
    peers_container = lv_obj_create(scr);
    lv_obj_set_pos(peers_container, 6, 32);
    lv_obj_set_size(peers_container, 308, 202);
    lv_obj_set_style_bg_opa(peers_container, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(peers_container, 0, 0);
    lv_obj_set_style_pad_all(peers_container, 0, 0);
    lv_obj_set_flex_flow(peers_container, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_style_pad_row(peers_container, 4, 0);
    lv_obj_add_flag(peers_container, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_scroll_dir(peers_container, LV_DIR_VER);

    build_peer_list(peers_container);

    return scr;
}

void screen_peers_update() {
    if (peers_container) {
        build_peer_list(peers_container);
    }
}

} // namespace ui
