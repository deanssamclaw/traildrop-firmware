#include "storage.h"
#include <Arduino.h>
#include <SPI.h>
#include <SD.h>
#include <FS.h>

namespace hal {

bool storage_init() {
    // Ensure SPI bus is configured
    SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI);

    if (!SD.begin(PIN_SDCARD_CS, SPI, SD_INIT_FREQ)) {
        Serial.println("[SD]  Card mount failed");
        return false;
    }

    uint8_t cardType = SD.cardType();
    if (cardType == CARD_NONE) {
        Serial.println("[SD]  No card detected");
        return false;
    }

    Serial.printf("[SD]  Card mounted: %lluMB total, %lluMB used\n",
                  SD.totalBytes() / (1024 * 1024),
                  SD.usedBytes() / (1024 * 1024));
    return true;
}

bool storage_write_file(const char* path, const uint8_t* data, size_t len) {
    File file = SD.open(path, FILE_WRITE);
    if (!file) return false;
    size_t written = file.write(data, len);
    file.close();
    return (written == len);
}

int storage_read_file(const char* path, uint8_t* buf, size_t maxLen) {
    File file = SD.open(path, FILE_READ);
    if (!file) return -1;
    int bytesRead = (int)file.read(buf, maxLen);
    file.close();
    return bytesRead;
}

bool storage_exists(const char* path) {
    return SD.exists(path);
}

bool storage_remove(const char* path) {
    return SD.remove(path);
}

uint64_t storage_total_bytes() {
    return SD.totalBytes();
}

uint64_t storage_used_bytes() {
    return SD.usedBytes();
}

} // namespace hal
