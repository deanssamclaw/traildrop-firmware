#include "theme.h"

namespace ui {

lv_style_t style_screen;
lv_style_t style_card;
lv_style_t style_btn;
lv_style_t style_btn_green;
lv_style_t style_btn_red;
lv_style_t style_status_bar;

void theme_init() {
    // Screen background
    lv_style_init(&style_screen);
    lv_style_set_bg_color(&style_screen, CLR_BG);
    lv_style_set_bg_opa(&style_screen, LV_OPA_COVER);
    lv_style_set_text_color(&style_screen, CLR_TEXT);

    // Card
    lv_style_init(&style_card);
    lv_style_set_bg_color(&style_card, CLR_CARD);
    lv_style_set_bg_opa(&style_card, LV_OPA_COVER);
    lv_style_set_border_color(&style_card, CLR_CARD_BORDER);
    lv_style_set_border_width(&style_card, 1);
    lv_style_set_radius(&style_card, 4);
    lv_style_set_pad_all(&style_card, 8);

    // Button
    lv_style_init(&style_btn);
    lv_style_set_bg_color(&style_btn, CLR_BTN);
    lv_style_set_bg_opa(&style_btn, LV_OPA_COVER);
    lv_style_set_border_color(&style_btn, CLR_BTN_BORDER);
    lv_style_set_border_width(&style_btn, 1);
    lv_style_set_radius(&style_btn, 6);
    lv_style_set_text_color(&style_btn, CLR_TEXT);
    lv_style_set_pad_ver(&style_btn, 8);
    lv_style_set_pad_hor(&style_btn, 12);

    // Green-tinted button
    lv_style_init(&style_btn_green);
    lv_style_set_bg_color(&style_btn_green, CLR_GREEN_BG);
    lv_style_set_bg_opa(&style_btn_green, LV_OPA_COVER);
    lv_style_set_border_color(&style_btn_green, CLR_GREEN);
    lv_style_set_border_width(&style_btn_green, 1);
    lv_style_set_radius(&style_btn_green, 6);
    lv_style_set_text_color(&style_btn_green, CLR_GREEN);
    lv_style_set_pad_ver(&style_btn_green, 8);
    lv_style_set_pad_hor(&style_btn_green, 12);

    // Red-tinted button
    lv_style_init(&style_btn_red);
    lv_style_set_bg_color(&style_btn_red, CLR_RED_BG);
    lv_style_set_bg_opa(&style_btn_red, LV_OPA_COVER);
    lv_style_set_border_color(&style_btn_red, CLR_RED);
    lv_style_set_border_width(&style_btn_red, 1);
    lv_style_set_radius(&style_btn_red, 6);
    lv_style_set_text_color(&style_btn_red, CLR_RED);
    lv_style_set_pad_ver(&style_btn_red, 8);
    lv_style_set_pad_hor(&style_btn_red, 12);

    // Status bar
    lv_style_init(&style_status_bar);
    lv_style_set_bg_color(&style_status_bar, CLR_CARD);
    lv_style_set_bg_opa(&style_status_bar, LV_OPA_COVER);
    lv_style_set_border_color(&style_status_bar, CLR_CARD_BORDER);
    lv_style_set_border_width(&style_status_bar, 1);
    lv_style_set_border_side(&style_status_bar, LV_BORDER_SIDE_BOTTOM);
    lv_style_set_pad_all(&style_status_bar, 4);
    lv_style_set_pad_hor(&style_status_bar, 8);
    lv_style_set_radius(&style_status_bar, 0);
}

void theme_apply_screen(lv_obj_t* scr) {
    lv_obj_add_style(scr, &style_screen, 0);
    lv_obj_clear_flag(scr, LV_OBJ_FLAG_SCROLLABLE);
}

lv_obj_t* theme_card(lv_obj_t* parent) {
    lv_obj_t* card = lv_obj_create(parent);
    lv_obj_add_style(card, &style_card, 0);
    lv_obj_set_width(card, lv_pct(100));
    lv_obj_set_height(card, LV_SIZE_CONTENT);
    lv_obj_set_style_pad_column(card, 2, 0);
    lv_obj_clear_flag(card, LV_OBJ_FLAG_SCROLLABLE);
    return card;
}

lv_obj_t* theme_btn(lv_obj_t* parent, const char* text, lv_coord_t w, lv_coord_t h) {
    lv_obj_t* btn = lv_btn_create(parent);
    lv_obj_add_style(btn, &ui::style_btn, 0);
    lv_obj_set_size(btn, w, h);

    lv_obj_t* lbl = lv_label_create(btn);
    lv_label_set_text(lbl, text);
    lv_obj_center(lbl);

    return btn;
}

lv_obj_t* theme_btn_green(lv_obj_t* parent, const char* text, lv_coord_t w, lv_coord_t h) {
    lv_obj_t* btn = lv_btn_create(parent);
    lv_obj_add_style(btn, &ui::style_btn_green, 0);
    lv_obj_set_size(btn, w, h);

    lv_obj_t* lbl = lv_label_create(btn);
    lv_label_set_text(lbl, text);
    lv_obj_center(lbl);

    return btn;
}

lv_obj_t* theme_btn_red(lv_obj_t* parent, const char* text, lv_coord_t w, lv_coord_t h) {
    lv_obj_t* btn = lv_btn_create(parent);
    lv_obj_add_style(btn, &ui::style_btn_red, 0);
    lv_obj_set_size(btn, w, h);

    lv_obj_t* lbl = lv_label_create(btn);
    lv_label_set_text(lbl, text);
    lv_obj_center(lbl);

    return btn;
}

lv_obj_t* theme_section_label(lv_obj_t* parent, const char* text) {
    lv_obj_t* lbl = lv_label_create(parent);
    lv_label_set_text(lbl, text);
    lv_obj_set_style_text_color(lbl, CLR_SECTION, 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);
    return lbl;
}

lv_obj_t* theme_dim_label(lv_obj_t* parent, const char* text) {
    lv_obj_t* lbl = lv_label_create(parent);
    lv_label_set_text(lbl, text);
    lv_obj_set_style_text_color(lbl, CLR_DIM, 0);
    return lbl;
}

lv_obj_t* theme_top_bar(lv_obj_t* parent, const char* title, lv_event_cb_t back_cb) {
    lv_obj_t* bar = lv_obj_create(parent);
    lv_obj_add_style(bar, &style_status_bar, 0);
    lv_obj_set_size(bar, 320, 28);
    lv_obj_set_pos(bar, 0, 0);
    lv_obj_clear_flag(bar, LV_OBJ_FLAG_SCROLLABLE);
    lv_obj_set_flex_flow(bar, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(bar, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);

    // Back button
    lv_obj_t* back = lv_btn_create(bar);
    lv_obj_set_size(back, 50, 22);
    lv_obj_set_style_bg_opa(back, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(back, 0, 0);
    lv_obj_set_style_pad_all(back, 0, 0);
    lv_obj_set_style_shadow_width(back, 0, 0);
    lv_obj_t* back_lbl = lv_label_create(back);
    lv_label_set_text(back_lbl, LV_SYMBOL_LEFT " Back");
    lv_obj_set_style_text_color(back_lbl, CLR_CYAN, 0);
    lv_obj_set_style_text_font(back_lbl, &lv_font_montserrat_12, 0);
    lv_obj_center(back_lbl);
    if (back_cb) lv_obj_add_event_cb(back, back_cb, LV_EVENT_CLICKED, NULL);

    // Title
    lv_obj_t* lbl = lv_label_create(bar);
    lv_label_set_text(lbl, title);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_14, 0);

    return back;
}

void theme_detail_row(lv_obj_t* card, const char* label, const char* value,
                      lv_obj_t** value_label_out) {
    lv_obj_t* row = lv_obj_create(card);
    lv_obj_set_size(row, lv_pct(100), LV_SIZE_CONTENT);
    lv_obj_set_style_bg_opa(row, LV_OPA_TRANSP, 0);
    lv_obj_set_style_border_width(row, 0, 0);
    lv_obj_set_style_pad_all(row, 2, 0);
    lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(row, LV_FLEX_ALIGN_SPACE_BETWEEN, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_clear_flag(row, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* lbl = lv_label_create(row);
    lv_label_set_text(lbl, label);
    lv_obj_set_style_text_color(lbl, CLR_DIM, 0);
    lv_obj_set_style_text_font(lbl, &lv_font_montserrat_12, 0);

    lv_obj_t* val = lv_label_create(row);
    lv_label_set_text(val, value);
    lv_obj_set_style_text_font(val, &lv_font_montserrat_12, 0);

    if (value_label_out) *value_label_out = val;
}

void theme_divider(lv_obj_t* parent) {
    static lv_point_t line_points[] = {{0, 0}, {280, 0}};
    lv_obj_t* line = lv_line_create(parent);
    lv_line_set_points(line, line_points, 2);
    lv_obj_set_style_line_color(line, CLR_CARD_BORDER, 0);
    lv_obj_set_style_line_width(line, 1, 0);
}

} // namespace ui
