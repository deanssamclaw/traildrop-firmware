#pragma once

#include "config.h"

namespace hal {

bool battery_init();
float battery_voltage();
int battery_percent();
bool battery_is_low();

} // namespace hal
