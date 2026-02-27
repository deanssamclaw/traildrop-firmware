#pragma once

#include <stdint.h>
#include "config.h"

namespace hal {

// The T-Deck Plus trackball uses GPIO pins (not I2C).
// Each direction pin toggles state when the ball rolls.
bool trackball_init();
void trackball_read(int8_t &dx, int8_t &dy, bool &click);

} // namespace hal
