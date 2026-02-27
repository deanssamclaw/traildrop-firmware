#pragma once

#include <stdint.h>
#include <stddef.h>
#include "config.h"

namespace hal {

bool radio_init();
int radio_send(const uint8_t* data, size_t len);
int radio_receive(uint8_t* buf, size_t maxLen);
void radio_start_receive();
float radio_rssi();
float radio_snr();

} // namespace hal
