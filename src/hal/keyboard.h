#pragma once

#include <stdint.h>
#include "config.h"

namespace hal {

bool keyboard_init();
char keyboard_read();
void keyboard_set_backlight(uint8_t brightness);

} // namespace hal
