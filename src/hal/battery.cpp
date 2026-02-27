#include "battery.h"
#include <Arduino.h>

namespace hal {

bool battery_init() {
    pinMode(PIN_BAT_ADC, INPUT);

    float v = battery_voltage();
    Serial.printf("[BAT] Battery: %.2fV (%d%%)\n", v, battery_percent());
    return true;
}

float battery_voltage() {
    uint32_t mv = analogReadMilliVolts(PIN_BAT_ADC);
    return (mv / 1000.0f) * BAT_VOLTAGE_DIVIDER;
}

int battery_percent() {
    float v = battery_voltage();
    if (v >= 4.2f) return 100;
    if (v <= 3.0f) return 0;
    // Linear approximation: 3.0V = 0%, 4.2V = 100%
    return (int)((v - 3.0f) / 1.2f * 100.0f);
}

bool battery_is_low() {
    return battery_voltage() < 3.3f;
}

} // namespace hal
