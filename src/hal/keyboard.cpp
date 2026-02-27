#include "keyboard.h"
#include <Arduino.h>
#include <Wire.h>

namespace hal {

bool keyboard_init() {
    Wire.begin(PIN_I2C_SDA, PIN_I2C_SCL);

    // Configure interrupt pin (active LOW from ESP32-C3 keyboard controller)
    pinMode(PIN_KEYBOARD_INT, INPUT_PULLUP);

    // Test communication with keyboard controller
    Wire.requestFrom((uint8_t)KEYBOARD_I2C_ADDR, (uint8_t)1);
    if (Wire.available()) {
        Wire.read(); // Discard initial byte
        Serial.println("[KBD] Keyboard initialized (I2C 0x55)");
        return true;
    }

    Serial.println("[KBD] WARNING: Keyboard not responding");
    return false;
}

char keyboard_read() {
    Wire.requestFrom((uint8_t)KEYBOARD_I2C_ADDR, (uint8_t)1);
    if (Wire.available()) {
        char c = Wire.read();
        if (c > 0) return c;
    }
    return 0;
}

void keyboard_set_backlight(uint8_t brightness) {
    Wire.beginTransmission(KEYBOARD_I2C_ADDR);
    Wire.write(KB_BRIGHTNESS_CMD);
    Wire.write(brightness);
    Wire.endTransmission();
}

} // namespace hal
