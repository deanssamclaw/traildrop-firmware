#pragma once

#include <stdint.h>
#include "config.h"

namespace hal {

bool power_init();
void power_deep_sleep();
void power_deep_sleep_timed(uint64_t us);
void power_shutdown();

} // namespace hal
