#include "touch.h"
#include <Arduino.h>
#include <Wire.h>

// GT911 capacitive touch controller on T-Deck Plus
// Shares I2C bus with keyboard (Wire on SDA=18, SCL=8)
// INT pin: GPIO 16

#define GT911_ADDR          0x5D
#define GT911_ADDR_ALT      0x14

// GT911 registers (16-bit)
#define GT911_REG_STATUS    0x814E
#define GT911_REG_POINT1    0x8150

static uint8_t gt911_addr = GT911_ADDR;
static bool initialized = false;

static void gt911_write_reg(uint16_t reg, uint8_t val) {
    Wire.beginTransmission(gt911_addr);
    Wire.write((uint8_t)(reg >> 8));
    Wire.write((uint8_t)(reg & 0xFF));
    Wire.write(val);
    Wire.endTransmission();
}

static bool gt911_read_reg(uint16_t reg, uint8_t* buf, uint8_t len) {
    Wire.beginTransmission(gt911_addr);
    Wire.write((uint8_t)(reg >> 8));
    Wire.write((uint8_t)(reg & 0xFF));
    if (Wire.endTransmission(false) != 0) return false;

    Wire.requestFrom(gt911_addr, len);
    if (Wire.available() < len) return false;

    for (uint8_t i = 0; i < len; i++) {
        buf[i] = Wire.read();
    }
    return true;
}

static bool gt911_probe(uint8_t addr) {
    Wire.beginTransmission(addr);
    return Wire.endTransmission() == 0;
}

namespace hal {

bool touch_init() {
    pinMode(PIN_TOUCH_INT, INPUT);

    // Wire already initialized by keyboard_init()
    // Probe for GT911 at both possible addresses
    if (gt911_probe(GT911_ADDR)) {
        gt911_addr = GT911_ADDR;
        initialized = true;
        Serial.println("[TOUCH] GT911 found at 0x5D");
    } else if (gt911_probe(GT911_ADDR_ALT)) {
        gt911_addr = GT911_ADDR_ALT;
        initialized = true;
        Serial.println("[TOUCH] GT911 found at 0x14");
    } else {
        Serial.println("[TOUCH] WARNING: GT911 not found");
        return false;
    }

    return true;
}

bool touch_read(int16_t &x, int16_t &y) {
    if (!initialized) return false;

    uint8_t status;
    if (!gt911_read_reg(GT911_REG_STATUS, &status, 1)) return false;

    // Bit 7: buffer ready, bits 3:0: number of touch points
    bool ready = status & 0x80;
    uint8_t points = status & 0x0F;

    if (!ready || points == 0) {
        // Clear status even if no touch
        if (ready) gt911_write_reg(GT911_REG_STATUS, 0);
        return false;
    }

    // Read first touch point (8 bytes: track_id, x_lo, x_hi, y_lo, y_hi, size_lo, size_hi, reserved)
    uint8_t data[8];
    if (!gt911_read_reg(GT911_REG_POINT1, data, 8)) {
        gt911_write_reg(GT911_REG_STATUS, 0);
        return false;
    }

    int16_t raw_x = (int16_t)(data[1] | (data[2] << 8));
    int16_t raw_y = (int16_t)(data[3] | (data[4] << 8));

    // Map GT911 coordinates to display coordinates (landscape rotation 1)
    // GT911 reports in portrait orientation, display is rotated to landscape
    // Portrait: 240 wide x 320 tall → Landscape: 320 wide x 240 tall
    x = raw_x;
    y = raw_y;

    // Clamp to display bounds
    if (x < 0) x = 0;
    if (x >= DISPLAY_WIDTH) x = DISPLAY_WIDTH - 1;
    if (y < 0) y = 0;
    if (y >= DISPLAY_HEIGHT) y = DISPLAY_HEIGHT - 1;

    // Clear status register
    gt911_write_reg(GT911_REG_STATUS, 0);

    return true;
}

} // namespace hal
