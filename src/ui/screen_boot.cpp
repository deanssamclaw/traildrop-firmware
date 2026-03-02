#include "ui.h"
#include "theme.h"
#include "config.h"
#include <Arduino.h>
#include <lvgl.h>
#include <cstdio>

namespace ui {

static lv_obj_t* boot_bar = nullptr;
static lv_obj_t* boot_phase_label = nullptr;
static int boot_progress = 0;

// Boot auto-advance timer
static void boot_advance_cb(lv_timer_t* timer) {
    boot_progress += 5;
    if (boot_progress > 100) boot_progress = 100;

    if (boot_bar) lv_bar_set_value(boot_bar, boot_progress, LV_ANIM_ON);

    // Phase labels
    const char* phase = "Initializing...";
    if (boot_progress < 25)       phase = "Initializing radio...";
    else if (boot_progress < 50)  phase = "Acquiring GPS...";
    else if (boot_progress < 75)  phase = "Loading crypto...";
    else if (boot_progress < 100) phase = "Joining network...";
    else                          phase = "Ready";

    if (boot_phase_label) lv_label_set_text(boot_phase_label, phase);

    if (boot_progress >= 100) {
        lv_timer_del(timer);
        // Transition to main screen after brief delay
        lv_timer_create([](lv_timer_t* t) {
            lv_timer_del(t);
            ui_show(SCREEN_MAIN);
        }, 500, NULL);
    }
}

lv_obj_t* screen_boot_create() {
    lv_obj_t* scr = lv_obj_create(NULL);
    theme_apply_screen(scr);

    // Title: T R A I L D R O P
    lv_obj_t* title = lv_label_create(scr);
    lv_label_set_text(title, "T R A I L D R O P");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_24, 0);
    lv_obj_set_style_text_color(title, CLR_TEXT, 0);
    lv_obj_align(title, LV_ALIGN_CENTER, 0, -50);

    // Version
    lv_obj_t* ver = lv_label_create(scr);
    char ver_str[32];
    snprintf(ver_str, sizeof(ver_str), "v%s", APP_VERSION);
    lv_label_set_text(ver, ver_str);
    lv_obj_set_style_text_color(ver, CLR_DIM, 0);
    lv_obj_set_style_text_font(ver, &lv_font_montserrat_14, 0);
    lv_obj_align(ver, LV_ALIGN_CENTER, 0, -22);

    // Progress bar
    boot_bar = lv_bar_create(scr);
    lv_obj_set_size(boot_bar, 200, 10);
    lv_obj_align(boot_bar, LV_ALIGN_CENTER, 0, 20);
    lv_bar_set_range(boot_bar, 0, 100);
    lv_bar_set_value(boot_bar, 0, LV_ANIM_OFF);
    // Style the bar
    lv_obj_set_style_bg_color(boot_bar, CLR_CARD, LV_PART_MAIN);
    lv_obj_set_style_bg_opa(boot_bar, LV_OPA_COVER, LV_PART_MAIN);
    lv_obj_set_style_border_color(boot_bar, CLR_CARD_BORDER, LV_PART_MAIN);
    lv_obj_set_style_border_width(boot_bar, 1, LV_PART_MAIN);
    lv_obj_set_style_radius(boot_bar, 3, LV_PART_MAIN);
    lv_obj_set_style_bg_color(boot_bar, CLR_GREEN, LV_PART_INDICATOR);
    lv_obj_set_style_bg_opa(boot_bar, LV_OPA_COVER, LV_PART_INDICATOR);
    lv_obj_set_style_radius(boot_bar, 3, LV_PART_INDICATOR);

    // Phase label
    boot_phase_label = lv_label_create(scr);
    lv_label_set_text(boot_phase_label, "Initializing radio...");
    lv_obj_set_style_text_color(boot_phase_label, CLR_DIM, 0);
    lv_obj_set_style_text_font(boot_phase_label, &lv_font_montserrat_12, 0);
    lv_obj_align(boot_phase_label, LV_ALIGN_CENTER, 0, 42);

    // Reset progress
    boot_progress = 0;

    // Start auto-advance timer (every 200ms, reaches 100% in ~4s)
    lv_timer_create(boot_advance_cb, 200, NULL);

    return scr;
}

void screen_boot_update() {
    // Boot screen updates via its own timer
}

} // namespace ui
