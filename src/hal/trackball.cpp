#include "trackball.h"
#include <Arduino.h>

// The T-Deck Plus trackball uses individual GPIO pins for directional pulses.
// Each direction pin toggles state when the ball rolls in that direction.
// We detect state changes to determine movement delta.

static const uint8_t tb_pins[5] = {
    PIN_TRACKBALL_UP,
    PIN_TRACKBALL_DOWN,
    PIN_TRACKBALL_LEFT,
    PIN_TRACKBALL_RIGHT,
    PIN_TRACKBALL_CLICK
};

static bool last_state[5];

namespace hal {

bool trackball_init() {
    for (int i = 0; i < 5; i++) {
        pinMode(tb_pins[i], INPUT_PULLUP);
        last_state[i] = digitalRead(tb_pins[i]);
    }

    Serial.println("[TB]  Trackball initialized (GPIO)");
    return true;
}

void trackball_read(int8_t &dx, int8_t &dy, bool &click) {
    dx = 0;
    dy = 0;
    click = false;

    for (int i = 0; i < 5; i++) {
        bool current = digitalRead(tb_pins[i]);
        if (current != last_state[i]) {
            last_state[i] = current;
            switch (i) {
                case 0: dy--; break;        // up
                case 1: dy++; break;        // down
                case 2: dx--; break;        // left
                case 3: dx++; break;        // right
                case 4: click = true; break; // center press
            }
        }
    }
}

} // namespace hal
