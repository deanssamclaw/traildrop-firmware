#include "gps.h"
#include <Arduino.h>
#include <TinyGPSPlus.h>

static TinyGPSPlus gps;
static HardwareSerial gpsSerial(1);

namespace hal {

bool gps_init() {
    // PIN_GPS_TX (43) = ESP32 TX → GPS RX
    // PIN_GPS_RX (44) = ESP32 RX ← GPS TX
    gpsSerial.begin(GPS_BAUD, SERIAL_8N1, PIN_GPS_RX, PIN_GPS_TX);

    Serial.printf("[GPS] UART initialized (%d baud, RX=%d TX=%d)\n",
                  GPS_BAUD, PIN_GPS_RX, PIN_GPS_TX);
    return true;
}

void gps_poll() {
    while (gpsSerial.available() > 0) {
        gps.encode(gpsSerial.read());
    }
}

bool gps_has_fix() {
    return gps.location.isValid() && gps.location.age() < 5000;
}

double gps_latitude() {
    return gps.location.lat();
}

double gps_longitude() {
    return gps.location.lng();
}

float gps_altitude() {
    return (float)gps.altitude.meters();
}

float gps_speed_kmh() {
    return (float)gps.speed.kmph();
}

uint32_t gps_satellites() {
    return gps.satellites.value();
}

float gps_hdop() {
    return (float)gps.hdop.hdop();
}

} // namespace hal
