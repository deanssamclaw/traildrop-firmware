#pragma once

#include <stdint.h>
#include "config.h"

namespace hal {

bool touch_init();
bool touch_read(int16_t &x, int16_t &y);  // Returns true if touched

} // namespace hal
