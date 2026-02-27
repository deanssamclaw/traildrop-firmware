#pragma once

#include <stdint.h>
#include <stddef.h>
#include "config.h"

namespace hal {

bool storage_init();
bool storage_write_file(const char* path, const uint8_t* data, size_t len);
int  storage_read_file(const char* path, uint8_t* buf, size_t maxLen);
bool storage_exists(const char* path);
bool storage_remove(const char* path);
uint64_t storage_total_bytes();
uint64_t storage_used_bytes();

} // namespace hal
