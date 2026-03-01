# SPI Cleanup + Init Health — Build Prompt

## Context

TrailDrop firmware on LilyGO T-Deck Plus (ESP32-S3). Phase 1 (HAL) and Phase 2 (crypto) are hardware-verified. Three SPI devices share the bus: display (TFT_eSPI), radio (SX1262/RadioLib), SD card.

Research findings are in `SPI_RESEARCH.md` — read it for full context. Key discoveries:
- All three libraries already use `SPI.beginTransaction()`/`endTransaction()` internally
- ESP32 Arduino SPI core has a FreeRTOS mutex under the hood
- No custom mutex needed for our single-threaded architecture
- But SPI.begin() is called redundantly, CS pins aren't pre-initialized, and init failures aren't gated

**Your job:** Clean up SPI initialization and add boot health tracking. Small, surgical changes.

## What to Build

### 1. Centralize SPI.begin() in setup()

**Note:** `#include <SPI.h>` goes at the TOP of `src/main_test.cpp` with the other includes (around line 8), NOT inline inside a function.

In `src/main_test.cpp` setup(), add SPI bus initialization AFTER `power_init()` but BEFORE any other HAL init:

```cpp
// After power_init() succeeds:

// Pre-initialize all SPI CS pins HIGH to prevent bus contention during boot
pinMode(PIN_TFT_CS, OUTPUT);     digitalWrite(PIN_TFT_CS, HIGH);
pinMode(PIN_RADIO_CS, OUTPUT);   digitalWrite(PIN_RADIO_CS, HIGH);
pinMode(PIN_SDCARD_CS, OUTPUT);  digitalWrite(PIN_SDCARD_CS, HIGH);

// Single SPI bus initialization — all three libraries will use this bus
SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI);
```

**Important:** Note that `power_init()` in `power.cpp` already pre-initializes CS pins HIGH. The CS pin init above is a defensive redundancy in case power_init changes — the sub-agent should check `power.cpp` and avoid true duplication. If power.cpp already handles CS pins, skip the CS pin lines here and add a comment referencing power_init().

Verify these pin names exist in `include/config.h`. If they're named differently, use the correct names.

### 2. Remove redundant SPI.begin() calls

**In `src/hal/radio.cpp`:** Remove the `SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI);` call. The bus is already initialized. **Do NOT pass `initInterface = false` to ArduinoHal** — the library's internal no-arg `SPI.begin()` is a harmless idempotent no-op. Changing the ArduinoHal constructor would be modifying library integration behavior for no gain.

**In `src/hal/storage.cpp`:** Remove the `SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI);` call. The bus is already initialized.

**Note:** TFT_eSPI and SD.begin() also call SPI.begin() internally — these are idempotent no-ops since we initialized first. Leave those alone (they're inside library code we don't modify). Add a comment in setup() noting this:

```cpp
// Note: TFT_eSPI::init(), RadioLib Module::init(), and SD.begin() all call
// SPI.begin() internally — these are idempotent no-ops since we init first.
```

### 3. Add boot health tracking

Add a simple struct to track init results. In `src/main_test.cpp`:

```cpp
struct BootHealth {
    bool power    = false;
    bool display  = false;
    bool keyboard = false;
    bool trackball = false;
    bool gps      = false;
    bool radio    = false;
    bool storage  = false;
    bool battery  = false;

    bool spi_ready() const { return power; }  // SPI depends on power (GPIO 10)
    bool can_network() const { return radio && storage; }  // Need radio + identity from SD
    bool has_display() const { return display; }
};

static BootHealth boot;
```

Update the existing init calls to use the struct. **Replace all `bool ok_*` local variables with `boot.*` field assignments. Remove the `bool ok_*` declarations entirely. All subsequent references (e.g., `ok_radio` gating `radio_start_receive()`) must use `boot.radio` instead.** Do not leave both coexisting.

The `show_boot_status()` per-module display lines remain unchanged — those are the user-facing boot screen on the LCD, critical for a handheld device with no serial monitor. The compact health summary (step 4) is a Serial.printf *addition*, not a replacement.

```cpp
boot.power = hal::power_init();
if (!boot.power) {
    Serial.println("[BOOT] CRITICAL: Power init failed — peripherals unpowered");
    // Still try display in case it works on USB power
}

// SPI bus init (after power)
// ... CS pre-init and SPI.begin() from step 1 ...

boot.display  = hal::display_init();
boot.keyboard = hal::keyboard_init();
boot.trackball = hal::trackball_init();
boot.gps      = hal::gps_init();
boot.radio    = hal::radio_init();
boot.storage  = hal::storage_init();
boot.battery  = hal::battery_init();
```

### 4. Gate behavior on boot health

Update the existing conditional logic to use the struct, and add gating for Phase 3:

```cpp
// Existing: gate radio receive on radio init
if (boot.radio) {
    hal::radio_start_receive();
    Serial.println("[BOOT] Radio: listening");
}

// Existing: gate crypto tests on storage
if (boot.storage) {
    run_crypto_tests(line);
} else {
    Serial.println("[CRYPTO] Skipping crypto tests - SD card required");
}

// New: overall boot status
Serial.printf("[BOOT] Health: %s%s%s%s%s%s%s%s\n",
    boot.power    ? "P" : "p",
    boot.display  ? "D" : "d",
    boot.keyboard ? "K" : "k",
    boot.trackball ? "T" : "t",
    boot.gps      ? "G" : "g",
    boot.radio    ? "R" : "r",
    boot.storage  ? "S" : "s",
    boot.battery  ? "B" : "b");
// Uppercase = OK, lowercase = failed. e.g., "PDKTGRsB" means storage failed.

if (boot.can_network()) {
    Serial.println("[BOOT] Network-ready: radio + storage OK");
} else {
    Serial.println("[BOOT] Network-degraded: missing radio or storage");
}
```

### 5. Add Phase 3 mutex TODO

Add a comment block in setup() for future reference:

```cpp
// TODO Phase 3: When introducing concurrent FreeRTOS tasks for networking,
// add a Meshtastic-style LockingArduinoHal for RadioLib and wrap display/SD
// operations with the same global spiLock. See SPI_RESEARCH.md for the pattern.
// Current single-threaded architecture is protected by Arduino SPI's built-in
// FreeRTOS mutex (SPI.beginTransaction() calls xSemaphoreTake internally).
```

## Constraints

- **DO NOT modify any file in `src/hal/` except** removing the `SPI.begin()` lines from `radio.cpp` and `storage.cpp`
- **DO NOT modify any crypto code** — Phase 2 is hardware-verified
- **DO NOT add a mutex or locking mechanism** — not needed yet, research confirmed this
- **DO NOT modify library code** in `.pio/libdeps/`
- **Keep `framework = arduino`**
- Must compile clean with `pio run -e t-deck-plus`

## Acceptance Criteria

1. ✅ `SPI.begin()` called exactly once in `setup()`, after power_init(), before other HAL inits
2. ✅ All SPI CS pins (display, radio, SD) pre-initialized HIGH before SPI.begin()
3. ✅ Redundant `SPI.begin()` removed from `radio.cpp` and `storage.cpp`
4. ✅ `BootHealth` struct tracks all init results
5. ✅ Boot health summary printed to Serial (compact format showing pass/fail per module)
6. ✅ `can_network()` helper exists for Phase 3 gating
7. ✅ Existing conditional logic (`ok_radio`, `ok_sd`) migrated to use `boot.*` fields
8. ✅ Phase 3 mutex TODO comment added with reference to SPI_RESEARCH.md
9. ✅ `pio run -e t-deck-plus` compiles clean with no errors
10. ✅ Committed and pushed to `deanssamclaw/traildrop-firmware`

If any criterion is not met, the work is incomplete. Do not declare done.

When completely finished, run:
`openclaw system event --text "Done: SPI cleanup + boot health tracking — ready for Cal to verify" --mode now`
