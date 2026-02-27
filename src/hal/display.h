#pragma once

#include <stdint.h>
#include "config.h"

namespace hal {

bool display_init();
void display_set_backlight(uint8_t level);
void display_clear(uint16_t color = 0x0000);
void display_text(int x, int y, const char* text, uint16_t color = 0xFFFF, uint8_t size = 2);
void display_printf(int x, int y, uint16_t color, uint8_t size, const char* fmt, ...);

} // namespace hal
