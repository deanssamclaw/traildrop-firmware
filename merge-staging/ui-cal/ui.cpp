#include "ui.h"
#include "theme.h"
#include "hal/display.h"
#include "hal/touch.h"
#include <Arduino.h>
#include <TFT_eSPI.h>
#include <lvgl.h>
#include <esp_heap_caps.h>

// Screen create/update functions (defined in screen_*.cpp)
namespace ui {
    lv_obj_t* screen_boot_create();
    void screen_boot_update();

    lv_obj_t* screen_main_create();
    void screen_main_update();

    lv_obj_t* screen_drop_create();
    void screen_drop_update();

    lv_obj_t* screen_peers_create();
    void screen_peers_update();

    lv_obj_t* screen_detail_create();
    void screen_detail_update();

    lv_obj_t* screen_settings_create();
    void screen_settings_update();

    lv_obj_t* screen_emergency_create();
    void screen_emergency_update();
}

namespace ui {

// --- Display driver ---
static TFT_eSPI* tft_ptr = nullptr;
static lv_disp_draw_buf_t draw_buf;
static lv_disp_drv_t disp_drv;
static lv_indev_drv_t touch_drv;
static lv_indev_drv_t keypad_drv;
static lv_indev_t* keypad_indev = nullptr;

#define DRAW_BUF_LINES 40

static void lvgl_flush_cb(lv_disp_drv_t* drv, const lv_area_t* area, lv_color_t* color_p) {
    uint32_t w = area->x2 - area->x1 + 1;
    uint32_t h = area->y2 - area->y1 + 1;
    tft_ptr->startWrite();
    tft_ptr->setAddrWindow(area->x1, area->y1, w, h);
    tft_ptr->pushColors((uint16_t*)&color_p->full, w * h, true);
    tft_ptr->endWrite();
    lv_disp_flush_ready(drv);
}

static void lvgl_touch_cb(lv_indev_drv_t* drv, lv_indev_data_t* data) {
    int16_t x, y;
    if (hal::touch_read(x, y)) {
        data->state = LV_INDEV_STATE_PRESSED;
        data->point.x = x;
        data->point.y = y;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
    }
}

// Keyboard ring buffer for LVGL keypad input
static char key_ring[16];
static volatile uint8_t key_head = 0;
static volatile uint8_t key_tail = 0;

static void lvgl_keypad_cb(lv_indev_drv_t* drv, lv_indev_data_t* data) {
    if (key_head != key_tail) {
        char k = key_ring[key_tail];
        key_tail = (key_tail + 1) % sizeof(key_ring);

        // Map physical keys to LVGL keys
        switch (k) {
            case '\n': case '\r':
                data->key = LV_KEY_ENTER;
                break;
            case '\b': case 0x7F:
                data->key = LV_KEY_BACKSPACE;
                break;
            case 0x1B:  // ESC
                data->key = LV_KEY_ESC;
                break;
            default:
                data->key = k;
                break;
        }
        data->state = LV_INDEV_STATE_PRESSED;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
    }
}

// --- Data model ---
static UiWaypoint waypoints[MAX_UI_WAYPOINTS];
static UiPeer peers_data[MAX_UI_PEERS];
static int selected_wp = -1;
static int wp_count = 0;
static int peer_count = 0;

// --- Screen management ---
static lv_obj_t* screens[SCREEN_COUNT] = {nullptr};
static Screen current_screen = SCREEN_BOOT;
static Screen back_stack[8];
static int back_top = -1;

// Update timer callback — refreshes current screen data every second
static void update_timer_cb(lv_timer_t* timer) {
    switch (current_screen) {
        case SCREEN_MAIN:     screen_main_update();      break;
        case SCREEN_DROP:     screen_drop_update();      break;
        case SCREEN_PEERS:    screen_peers_update();     break;
        case SCREEN_DETAIL:   screen_detail_update();    break;
        case SCREEN_SETTINGS: screen_settings_update();  break;
        case SCREEN_EMERGENCY:screen_emergency_update(); break;
        case SCREEN_BOOT:     screen_boot_update();      break;
        default: break;
    }
}

static lv_obj_t* create_screen(Screen s) {
    switch (s) {
        case SCREEN_BOOT:      return screen_boot_create();
        case SCREEN_MAIN:      return screen_main_create();
        case SCREEN_DROP:      return screen_drop_create();
        case SCREEN_PEERS:     return screen_peers_create();
        case SCREEN_DETAIL:    return screen_detail_create();
        case SCREEN_SETTINGS:  return screen_settings_create();
        case SCREEN_EMERGENCY: return screen_emergency_create();
        default:               return nullptr;
    }
}

// --- Public API ---

bool ui_init() {
    // Get TFT_eSPI instance from HAL
    tft_ptr = static_cast<TFT_eSPI*>(hal::display_driver());
    if (!tft_ptr) {
        Serial.println("[UI] ERROR: No display driver");
        return false;
    }

    // Initialize touch
    hal::touch_init();

    // Initialize LVGL
    lv_init();

    // Allocate draw buffer in PSRAM
    lv_color_t* buf1 = (lv_color_t*)heap_caps_malloc(
        DISPLAY_WIDTH * DRAW_BUF_LINES * sizeof(lv_color_t),
        MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buf1) {
        // Fallback to internal RAM with smaller buffer
        buf1 = (lv_color_t*)malloc(DISPLAY_WIDTH * 20 * sizeof(lv_color_t));
        if (!buf1) {
            Serial.println("[UI] ERROR: Cannot allocate draw buffer");
            return false;
        }
        lv_disp_draw_buf_init(&draw_buf, buf1, NULL, DISPLAY_WIDTH * 20);
    } else {
        lv_disp_draw_buf_init(&draw_buf, buf1, NULL, DISPLAY_WIDTH * DRAW_BUF_LINES);
    }

    // Register display driver
    lv_disp_drv_init(&disp_drv);
    disp_drv.hor_res = DISPLAY_WIDTH;
    disp_drv.ver_res = DISPLAY_HEIGHT;
    disp_drv.flush_cb = lvgl_flush_cb;
    disp_drv.draw_buf = &draw_buf;
    lv_disp_drv_register(&disp_drv);

    // Register touch input
    lv_indev_drv_init(&touch_drv);
    touch_drv.type = LV_INDEV_TYPE_POINTER;
    touch_drv.read_cb = lvgl_touch_cb;
    lv_indev_drv_register(&touch_drv);

    // Register keyboard as keypad input
    lv_indev_drv_init(&keypad_drv);
    keypad_drv.type = LV_INDEV_TYPE_KEYPAD;
    keypad_drv.read_cb = lvgl_keypad_cb;
    keypad_indev = lv_indev_drv_register(&keypad_drv);

    // Initialize theme styles
    theme_init();

    // Clear data
    memset(waypoints, 0, sizeof(waypoints));
    memset(peers_data, 0, sizeof(peers_data));

    // Create and show boot screen
    screens[SCREEN_BOOT] = screen_boot_create();
    lv_scr_load(screens[SCREEN_BOOT]);
    current_screen = SCREEN_BOOT;

    // Create 1-second update timer
    lv_timer_create(update_timer_cb, 1000, NULL);

    Serial.println("[UI] LVGL initialized (320x240, touch + keyboard)");
    return true;
}

void ui_update() {
    lv_timer_handler();
}

void ui_show(Screen screen) {
    if (screen == current_screen) return;
    if (screen >= SCREEN_COUNT) return;

    // Push current to back stack
    if (back_top < 7) {
        back_stack[++back_top] = current_screen;
    }

    // Delete old screen object if it exists (recreate fresh)
    if (screens[screen]) {
        lv_obj_del(screens[screen]);
        screens[screen] = nullptr;
    }

    screens[screen] = create_screen(screen);
    if (!screens[screen]) return;

    lv_scr_load_anim(screens[screen], LV_SCR_LOAD_ANIM_MOVE_LEFT, 150, 0, false);
    current_screen = screen;
}

void ui_back() {
    if (back_top < 0) return;

    Screen prev = back_stack[back_top--];

    if (screens[prev]) {
        lv_obj_del(screens[prev]);
        screens[prev] = nullptr;
    }

    screens[prev] = create_screen(prev);
    if (!screens[prev]) return;

    lv_scr_load_anim(screens[prev], LV_SCR_LOAD_ANIM_MOVE_RIGHT, 150, 0, false);
    current_screen = prev;
}

void ui_feed_key(char key) {
    uint8_t next = (key_head + 1) % sizeof(key_ring);
    if (next != key_tail) {
        key_ring[key_head] = key;
        key_head = next;
    }
}

// --- Data callbacks ---

void ui_on_waypoint_received(const char* sender, const char* name,
                             double lat, double lon, float alt,
                             app::WaypointCategory cat, int16_t rssi) {
    // Find empty slot or overwrite oldest
    int slot = -1;
    uint32_t oldest = UINT32_MAX;
    int oldest_idx = 0;

    for (int i = 0; i < MAX_UI_WAYPOINTS; i++) {
        if (!waypoints[i].valid) { slot = i; break; }
        if (waypoints[i].received_at < oldest) {
            oldest = waypoints[i].received_at;
            oldest_idx = i;
        }
    }
    if (slot < 0) slot = oldest_idx;

    UiWaypoint& wp = waypoints[slot];
    wp.valid = true;
    strncpy(wp.sender, sender, sizeof(wp.sender) - 1);
    strncpy(wp.name, name, sizeof(wp.name) - 1);
    wp.lat = lat;
    wp.lon = lon;
    wp.altitude = alt;
    wp.category = cat;
    wp.rssi = rssi;
    wp.received_at = millis();

    if (slot >= wp_count) wp_count = slot + 1;
}

void ui_on_peer_discovered(const char* name, int16_t rssi) {
    // Update existing or find empty slot
    for (int i = 0; i < MAX_UI_PEERS; i++) {
        if (peers_data[i].valid && strcmp(peers_data[i].name, name) == 0) {
            peers_data[i].rssi = rssi;
            peers_data[i].last_seen = millis();
            return;
        }
    }

    for (int i = 0; i < MAX_UI_PEERS; i++) {
        if (!peers_data[i].valid) {
            peers_data[i].valid = true;
            strncpy(peers_data[i].name, name, sizeof(peers_data[i].name) - 1);
            peers_data[i].rssi = rssi;
            peers_data[i].last_seen = millis();
            if (i >= peer_count) peer_count = i + 1;
            return;
        }
    }
}

// --- Accessors ---

UiWaypoint* ui_get_waypoints() { return waypoints; }

int ui_get_waypoint_count() {
    int n = 0;
    for (int i = 0; i < MAX_UI_WAYPOINTS; i++) {
        if (waypoints[i].valid) n++;
    }
    return n;
}

UiPeer* ui_get_peers() { return peers_data; }

int ui_get_peer_count() {
    int n = 0;
    for (int i = 0; i < MAX_UI_PEERS; i++) {
        if (peers_data[i].valid) n++;
    }
    return n;
}

void ui_set_selected_waypoint(int idx) { selected_wp = idx; }
int ui_get_selected_waypoint() { return selected_wp; }
Screen ui_get_current_screen() { return current_screen; }

void ui_boot_progress(int percent, const char* phase) {
    // Boot screen reads this directly — store for access
    // Implemented in screen_boot.cpp via extern
}

} // namespace ui
