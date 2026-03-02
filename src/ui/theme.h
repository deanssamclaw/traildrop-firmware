#pragma once
// TrailDrop dark theme — matches Gremlin Adaptive Mode design language
// Colors defined as RGB565 for direct LVGL use

#include <lvgl.h>

namespace ui {

// --- Color palette (RGB565) ---
static const lv_color_t CLR_BG         = lv_color_hex(0x111111);
static const lv_color_t CLR_CARD       = lv_color_hex(0x1a1a1a);
static const lv_color_t CLR_CARD_BORDER= lv_color_hex(0x333333);
static const lv_color_t CLR_BTN        = lv_color_hex(0x222222);
static const lv_color_t CLR_BTN_BORDER = lv_color_hex(0x444444);
static const lv_color_t CLR_TEXT       = lv_color_hex(0xEEEEEE);
static const lv_color_t CLR_DIM        = lv_color_hex(0x666666);
static const lv_color_t CLR_SECTION    = lv_color_hex(0x555555);
static const lv_color_t CLR_GREEN      = lv_color_hex(0x33AA33);
static const lv_color_t CLR_GREEN_BG   = lv_color_hex(0x0D2B0D);
static const lv_color_t CLR_CYAN       = lv_color_hex(0x07FFFF);
static const lv_color_t CLR_RED        = lv_color_hex(0xCC4444);
static const lv_color_t CLR_RED_BG     = lv_color_hex(0x2B0D0D);
static const lv_color_t CLR_YELLOW     = lv_color_hex(0xAAAA33);
static const lv_color_t CLR_BLUE       = lv_color_hex(0x5555FF);
static const lv_color_t CLR_BLUE_BG    = lv_color_hex(0x0D1B2B);

// --- Shared styles ---
extern lv_style_t style_screen;
extern lv_style_t style_card;
extern lv_style_t style_btn;
extern lv_style_t style_btn_green;
extern lv_style_t style_btn_red;
extern lv_style_t style_status_bar;

// Initialize all theme styles — call once after lv_init()
void theme_init();

// --- Helper functions for common widget patterns ---

// Apply dark background to a screen object
void theme_apply_screen(lv_obj_t* scr);

// Create a card container on parent
lv_obj_t* theme_card(lv_obj_t* parent);

// Create a touch button with label text
lv_obj_t* theme_btn(lv_obj_t* parent, const char* text, lv_coord_t w, lv_coord_t h);

// Create a green-tinted action button
lv_obj_t* theme_btn_green(lv_obj_t* parent, const char* text, lv_coord_t w, lv_coord_t h);

// Create a red-tinted button
lv_obj_t* theme_btn_red(lv_obj_t* parent, const char* text, lv_coord_t w, lv_coord_t h);

// Create a section label ("WAYPOINTS", "ABOUT", etc.)
lv_obj_t* theme_section_label(lv_obj_t* parent, const char* text);

// Create a dim label
lv_obj_t* theme_dim_label(lv_obj_t* parent, const char* text);

// Create a top bar with back button and title, returns the back button
lv_obj_t* theme_top_bar(lv_obj_t* parent, const char* title, lv_event_cb_t back_cb);

// Create a detail row (label + value) inside a card
void theme_detail_row(lv_obj_t* card, const char* label, const char* value,
                      lv_obj_t** value_label_out = nullptr);

// Create a divider line inside a container
void theme_divider(lv_obj_t* parent);

} // namespace ui
