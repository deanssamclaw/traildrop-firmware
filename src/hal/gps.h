#pragma once

#include <stdint.h>
#include "config.h"

namespace hal {

bool gps_init();
void gps_poll();
bool gps_has_fix();
double gps_latitude();
double gps_longitude();
float gps_altitude();
float gps_speed_kmh();
uint32_t gps_satellites();
float gps_hdop();

} // namespace hal
