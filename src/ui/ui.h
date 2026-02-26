#pragma once
// LVGL UI manager
// TODO: Phase 5 implementation

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

bool ui_init();
void ui_show(Screen screen);
void ui_update();  // Called from main loop

} // namespace ui
