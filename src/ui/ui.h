#pragma once
// LVGL UI manager — Phase 5 (future)
// ui_init() and ui_update() are now in display_ui.h (Phase 4d).

namespace ui {

enum Screen {
    SCREEN_MAIN,
    SCREEN_DROP,
    SCREEN_SEND,
    SCREEN_PEERS,
    SCREEN_DETAIL,
    SCREEN_SETTINGS,
    SCREEN_EMERGENCY,
};

void ui_show(Screen screen);

} // namespace ui
