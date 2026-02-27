#include "power.h"
#include <Arduino.h>
#include <esp_sleep.h>

namespace hal {

bool power_init() {
    // Enable peripheral power (must be first!)
    pinMode(PIN_BOARD_POWER, OUTPUT);
    digitalWrite(PIN_BOARD_POWER, HIGH);
    delay(100); // Allow peripherals to power up

    // Deselect all SPI devices before any SPI init
    pinMode(PIN_TFT_CS, OUTPUT);
    digitalWrite(PIN_TFT_CS, HIGH);
    pinMode(PIN_RADIO_CS, OUTPUT);
    digitalWrite(PIN_RADIO_CS, HIGH);
    pinMode(PIN_SDCARD_CS, OUTPUT);
    digitalWrite(PIN_SDCARD_CS, HIGH);

    // SPI MISO needs pull-up for shared bus
    pinMode(PIN_SPI_MISO, INPUT_PULLUP);

    Serial.println("[PWR] Peripheral power enabled");
    return true;
}

void power_deep_sleep() {
    // Wake on BOOT button (GPIO 0, active LOW)
    esp_sleep_enable_ext0_wakeup((gpio_num_t)PIN_BOOT, 0);
    digitalWrite(PIN_BOARD_POWER, LOW);
    esp_deep_sleep_start();
}

void power_deep_sleep_timed(uint64_t us) {
    esp_sleep_enable_timer_wakeup(us);
    digitalWrite(PIN_BOARD_POWER, LOW);
    esp_deep_sleep_start();
}

void power_shutdown() {
    digitalWrite(PIN_BOARD_POWER, LOW);
}

} // namespace hal
