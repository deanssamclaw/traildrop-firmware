#include "radio.h"
#include <Arduino.h>
#include <RadioLib.h>
#include <SPI.h>

static SX1262* radio = nullptr;
static volatile bool rxFlag = false;
static float lastRSSI = 0;
static float lastSNR = 0;

static void IRAM_ATTR radioISR() {
    rxFlag = true;
}

namespace hal {

bool radio_init() {
    // Ensure SPI bus is configured with T-Deck pins
    SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI);

    radio = new SX1262(new Module(PIN_RADIO_CS, PIN_RADIO_DIO1,
                                   PIN_RADIO_RST, PIN_RADIO_BUSY, SPI));

    int state = radio->begin(
        RADIO_FREQ_MHZ,
        RADIO_BW_KHZ,
        RADIO_SF,
        RADIO_CR,
        RADIO_SYNC_WORD,
        RADIO_TX_POWER_DBM,
        RADIO_PREAMBLE_LEN,
        RADIO_TCXO_VOLTAGE,
        false  // DC-DC regulator (not LDO)
    );

    if (state != RADIOLIB_ERR_NONE) {
        Serial.printf("[RADIO] SX1262 init failed: %d\n", state);
        return false;
    }

    // DIO2 controls the RF switch on T-Deck Plus
    radio->setDio2AsRfSwitch(true);

    // Current limit
    radio->setCurrentLimit(RADIO_CURRENT_LIMIT);

    // Disable CRC — Reticulum handles its own integrity
    radio->setCRC(0);

    // Attach receive interrupt on DIO1
    radio->setDio1Action(radioISR);

    // Start listening
    radio->startReceive();

    Serial.printf("[RADIO] SX1262 ready (%.1f MHz, SF%d, BW%.0f kHz)\n",
                  RADIO_FREQ_MHZ, RADIO_SF, RADIO_BW_KHZ);
    return true;
}

int radio_send(const uint8_t* data, size_t len) {
    int state = radio->transmit((uint8_t*)data, len);
    // Return to receive mode after transmit
    radio->startReceive();
    return state;
}

int radio_receive(uint8_t* buf, size_t maxLen) {
    if (!rxFlag) return 0;
    rxFlag = false;

    size_t len = radio->getPacketLength();
    if (len == 0 || len > maxLen) {
        radio->startReceive();
        return -1;
    }

    int state = radio->readData(buf, len);
    lastRSSI = radio->getRSSI();
    lastSNR = radio->getSNR();

    // Re-enter receive mode
    radio->startReceive();

    if (state != RADIOLIB_ERR_NONE) return -1;
    return (int)len;
}

void radio_start_receive() {
    rxFlag = false;
    radio->startReceive();
}

float radio_rssi() {
    return lastRSSI;
}

float radio_snr() {
    return lastSNR;
}

} // namespace hal
