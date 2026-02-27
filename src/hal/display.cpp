#include "display.h"
#include <Arduino.h>
#include <TFT_eSPI.h>
#include <stdarg.h>

static TFT_eSPI tft;

// LEDC API compatibility (IDF5/Arduino 3.x vs IDF4/Arduino 2.x)
static void backlight_init() {
#if ESP_IDF_VERSION_MAJOR >= 5
    ledcAttach(PIN_TFT_BACKLIGHT, 5000, 8);
#else
    ledcSetup(0, 5000, 8);
    ledcAttachPin(PIN_TFT_BACKLIGHT, 0);
#endif
}

static void backlight_write(uint8_t level) {
#if ESP_IDF_VERSION_MAJOR >= 5
    ledcWrite(PIN_TFT_BACKLIGHT, level);
#else
    ledcWrite(0, level);
#endif
}

namespace hal {

bool display_init() {
    tft.init();
    tft.setRotation(1); // Landscape: 320x240
    tft.fillScreen(TFT_BLACK);
    tft.setTextColor(TFT_WHITE, TFT_BLACK);
    tft.setTextSize(2);

    backlight_init();
    display_set_backlight(BACKLIGHT_DEFAULT);

    Serial.println("[TFT] Display initialized (320x240 ST7789)");
    return true;
}

void display_set_backlight(uint8_t level) {
    backlight_write(level);
}

void display_clear(uint16_t color) {
    tft.fillScreen(color);
}

void display_text(int x, int y, const char* text, uint16_t color, uint8_t size) {
    tft.setTextColor(color, TFT_BLACK);
    tft.setTextSize(size);
    tft.setCursor(x, y);
    tft.print(text);
}

void display_printf(int x, int y, uint16_t color, uint8_t size, const char* fmt, ...) {
    char buf[256];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    display_text(x, y, buf, color, size);
}

} // namespace hal
