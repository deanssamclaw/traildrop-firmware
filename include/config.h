#pragma once

// ============================================================
// TrailDrop Firmware — Hardware Configuration
// Target: LilyGO T-Deck Plus (ESP32-S3 + SX1262)
// Pin map: https://github.com/Xinyuan-LilyGO/T-Deck
// ============================================================

// --- Power ---
#define PIN_BOARD_POWER     10    // Peripheral power control (set HIGH to enable)

// --- Display (ST7789 via SPI) ---
#define PIN_TFT_CS          12
#define PIN_TFT_DC          11
#define PIN_TFT_BACKLIGHT   42
#define DISPLAY_WIDTH       320
#define DISPLAY_HEIGHT      240

// --- SPI Bus (shared: display, radio, SD) ---
#define PIN_SPI_MOSI        41
#define PIN_SPI_MISO        38
#define PIN_SPI_SCK         40

// --- LoRa Radio (SX1262) ---
#define PIN_RADIO_CS        9
#define PIN_RADIO_BUSY      13
#define PIN_RADIO_RST       17
#define PIN_RADIO_DIO1      45

// Radio defaults (US ISM band)
#define RADIO_FREQ_MHZ      915.0
#define RADIO_BW_KHZ        125.0
#define RADIO_SF            8
#define RADIO_CR            6
#define RADIO_TX_POWER_DBM  7     // Conservative default, max 22
#define RADIO_PREAMBLE_LEN  8
#define RADIO_TCXO_VOLTAGE  1.8f    // DIO3 TCXO reference voltage
#define RADIO_SYNC_WORD     0xAB
#define RADIO_CURRENT_LIMIT 140.0f  // mA

// --- GPS (UART) ---
#define PIN_GPS_TX          43
#define PIN_GPS_RX          44
#define GPS_BAUD            9600

// --- I2C Bus (keyboard, trackball, touch) ---
#define PIN_I2C_SDA         18
#define PIN_I2C_SCL         8

// --- Keyboard ---
#define PIN_KEYBOARD_INT    46
#define KEYBOARD_I2C_ADDR   0x55
#define KB_BRIGHTNESS_CMD   0x01

// --- Trackball (GPIO-based, not I2C) ---
#define PIN_TRACKBALL_UP    3
#define PIN_TRACKBALL_DOWN  15
#define PIN_TRACKBALL_LEFT  1
#define PIN_TRACKBALL_RIGHT 2
#define PIN_TRACKBALL_CLICK 0     // Shared with BOOT button

// --- Touch ---
#define PIN_TOUCH_INT       16

// --- SD Card ---
#define PIN_SDCARD_CS       39
#define SD_INIT_FREQ        800000U // 800 kHz for initialization

// --- Battery ---
#define PIN_BAT_ADC         4
#define BAT_VOLTAGE_DIVIDER 2.11f   // Calibrated voltage divider multiplier

// --- Audio (ES7210) ---
#define PIN_I2S_WS          5
#define PIN_I2S_BCK         7
#define PIN_I2S_DOUT        6
#define PIN_ES7210_MCLK     48
#define PIN_ES7210_LRCK     21
#define PIN_ES7210_SCK      47
#define PIN_ES7210_DIN      14

// --- Boot Button ---
#define PIN_BOOT            0

// --- Backlight ---
#define BACKLIGHT_DEFAULT   100   // 0-255

// ============================================================
// Reticulum Protocol
// ============================================================
#define RNS_MTU             500   // Reticulum max transmission unit
#define IDENTITY_KEY_SIZE   32    // X25519 key size
#define DEST_HASH_SIZE      16    // Truncated SHA-256 destination hash
#define ANNOUNCE_INTERVAL   300   // Seconds between announces (5 min)

// ============================================================
// Application
// ============================================================
#define APP_NAME            "traildrop"
#define APP_VERSION         "0.1.0"
#define MAX_WAYPOINTS       1000
#define MAX_PEERS           50
#define DISPLAY_NAME_MAX    32
