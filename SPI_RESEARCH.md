# SPI Mutex + Init Return Checks — Research Findings

**Date:** 2026-02-28
**Scope:** Blockers #3 (SPI bus mutex) and #5 (init return checks) from firmware review
**Target:** LilyGO T-Deck Plus (ESP32-S3) — shared SPI bus: display (ST7789/TFT_eSPI), radio (SX1262/RadioLib), SD card

---

## 1. SPI.begin() Findings

### Where SPI.begin() is currently called

| Call Site | File:Line | Actual Call |
|-----------|-----------|-------------|
| TFT_eSPI `init()` | `TFT_eSPI.cpp:647` (inside `tft.init()`) | `spi.begin(TFT_SCLK, TFT_MISO, TFT_MOSI, -1)` |
| radio_init() | `src/hal/radio.cpp:19` | `SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI)` |
| RadioLib Module::init() | `Module.cpp:43` → `ArduinoHal.cpp:9` | `spi->begin()` (no pin args) |
| storage_init() | `src/hal/storage.cpp:11` | `SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI)` |
| SD.begin() internally | `SD.cpp:31` | `spi.begin()` (no pin args) |

### Is multi-call a bug?

**No — it's harmless but messy.** ESP32 Arduino `SPI.begin()` is idempotent:

```cpp
// SPI.cpp line 71
void SPIClass::begin(int8_t sck, int8_t miso, int8_t mosi, int8_t ss) {
    if(_spi) {
        return;  // Already initialized — early return
    }
    // ... actual init only runs once ...
}
```

The first call (from `tft.init()` in `display_init()`) does the real initialization with correct pin args. All subsequent calls return immediately.

### Current init order in setup()

```
1. power_init()       — GPIO only, no SPI
2. display_init()     — calls tft.init() → SPI.begin(40,38,41,-1) ← FIRST SPI INIT
3. keyboard_init()    — I2C, no SPI
4. trackball_init()   — GPIO, no SPI
5. gps_init()         — UART, no SPI
6. radio_init()       — SPI.begin() (no-op), then RadioLib Module::init() → SPI.begin() (no-op)
7. storage_init()     — SPI.begin() (no-op), then SD.begin() → spi.begin() (no-op)
8. battery_init()     — ADC, no SPI
```

Display init runs first, so SPI is already configured when radio and storage init. The explicit `SPI.begin()` calls in `radio.cpp:19` and `storage.cpp:11` are redundant.

### Recommendation

Move `SPI.begin()` to a single explicit call in `setup()` before any HAL init, and remove the redundant calls from `radio.cpp` and `storage.cpp`. This makes the init dependency explicit rather than relying on the library's idempotent behavior. RadioLib's internal `SPI.begin()` call (no pin args) would also be a no-op since the bus is already initialized.

---

## 2. Library SPI Transaction Audit

### Does each library use SPI.beginTransaction() / endTransaction()?

#### TFT_eSPI — YES (mandatory on ESP32-S3)

Every display operation wraps in transactions via `begin_tft_write()` / `end_tft_write()`:

```cpp
// TFT_eSPI.cpp:74-83
inline void TFT_eSPI::begin_tft_write(void) {
    if (locked) {
        locked = false;
        spi.beginTransaction(SPISettings(SPI_FREQUENCY, MSBFIRST, TFT_SPI_MODE));
        CS_L;  // Assert CS after acquiring transaction
    }
}

inline void TFT_eSPI::end_tft_write(void) {
    if (!inTransaction) {
        if (!locked) {
            locked = true;
            CS_H;  // De-assert CS before releasing transaction
            spi.endTransaction();
        }
    }
}
```

From `TFT_eSPI_ESP32_S3.h:41-44`:
```cpp
// SUPPORT_TRANSACTIONS is mandatory for ESP32 so the hal mutex is toggled
#if !defined (SUPPORT_TRANSACTIONS)
  #define SUPPORT_TRANSACTIONS
#endif
```

**SPI frequency:** 40 MHz (from platformio.ini build flag `-DSPI_FREQUENCY=40000000`).

#### RadioLib — YES (every single register access)

Every SPI operation wraps in transactions via the ArduinoHal:

```cpp
// Module.cpp (SPItransferStream, used by SX126x):
this->hal->spiBeginTransaction();
this->hal->digitalWrite(this->csPin, this->hal->GpioLevelLow);
this->hal->spiTransfer(buffOut, buffLen, buffIn);
this->hal->digitalWrite(this->csPin, this->hal->GpioLevelHigh);
this->hal->spiEndTransaction();

// ArduinoHal.cpp:
void ArduinoHal::spiBeginTransaction() {
    spi->beginTransaction(spiSettings);  // Uses Arduino SPI
}
```

RadioLib uses per-transfer transactions. A high-level operation like `readData()` involves ~6 separate SPI transactions (each individually acquiring/releasing the mutex).

#### SD Library — YES (RAII wrapper)

Uses `AcquireSPI` RAII class that calls `beginTransaction()` in constructor and `endTransaction()` in destructor:

```cpp
// sd_diskio.cpp:462-482
struct AcquireSPI {
    explicit AcquireSPI(ardu_sdcard_t* card) : card(card) {
        card->spi->beginTransaction(SPISettings(card->frequency, MSBFIRST, SPI_MODE0));
    }
    ~AcquireSPI() {
        card->spi->endTransaction();
    }
};
```

Each SD sector read/write holds the transaction for its entire duration.

### ESP32 Arduino SPI Core — FreeRTOS Mutex Confirmed

**This is the foundational finding.** The ESP32 Arduino SPI `beginTransaction()` acquires a FreeRTOS mutex:

```cpp
// SPI.cpp:177-197
void SPIClass::beginTransaction(SPISettings settings) {
    SPI_PARAM_LOCK();  // ← xSemaphoreTake(paramLock, portMAX_DELAY)
    spiTransaction(_spi, _div, settings._dataMode, settings._bitOrder);
    _inTransaction = true;
}

void SPIClass::endTransaction() {
    if (_inTransaction) {
        _inTransaction = false;
        spiEndTransaction(_spi);
        SPI_PARAM_UNLOCK();  // ← xSemaphoreGive(paramLock)
    }
}

// Macro definitions:
#define SPI_PARAM_LOCK()   do {} while (xSemaphoreTake(paramLock, portMAX_DELAY) != pdPASS)
#define SPI_PARAM_UNLOCK() xSemaphoreGive(paramLock)
```

There is also a second mutex at the HAL layer (`spi->lock`) protecting hardware register access. So there are **two layers of FreeRTOS mutex protection** in the Arduino SPI stack.

### Transaction Summary

| Library | Uses SPI Transactions? | CS Inside Transaction? | SPI Frequency |
|---------|----------------------|----------------------|---------------|
| TFT_eSPI | YES (mandatory ESP32) | YES (CS_L after begin, CS_H before end) | 40 MHz |
| RadioLib | YES (every access) | YES (CS LOW/HIGH inside) | Default ~8 MHz |
| SD (ESP32) | YES (RAII wrapper) | YES (internally managed) | 800 kHz init, 4 MHz data |

All three libraries correctly bracket their SPI access with `beginTransaction()`/`endTransaction()`, which means each individual SPI operation is protected by the Arduino SPI FreeRTOS mutex. SPI settings (clock, mode) are reconfigured on each transaction, so different devices requesting different frequencies/modes is handled automatically.

---

## 3. Do We Need Our Own Mutex?

### Current architecture (Phase 1/2): NO

**Right now, we don't need one.** Here's why:

1. **Single-threaded execution.** Everything runs in the Arduino `loop()` on one core. There is no concurrent SPI access.
2. **No SPI in ISR.** Our radio ISR (`radioISR()` in `radio.cpp:11`) only sets `rxFlag = true` — zero SPI operations.
3. **All three libraries use SPI transactions.** Each individual bus access acquires the Arduino SPI FreeRTOS mutex.
4. **No DMA active.** Although `ESP32_DMA` is auto-defined for ESP32-S3 in TFT_eSPI, DMA is not activated unless `tft.initDMA()` is explicitly called. Our `display_init()` does not call `initDMA()`.

### Phase 3 (networking with concurrent tasks): YES, probably

When Phase 3 introduces radio packet handling that could be concurrent with display updates, we'll likely need a mutex. Scenarios that create real contention:

**Scenario A — FreeRTOS tasks for display + radio:**
If display rendering runs on a separate task (common pattern), a display transaction could be preempted between TFT_eSPI's `end_tft_write()` and the start of the next graphics call, allowing a radio SPI transaction to slip in. The Arduino SPI mutex handles this correctly at the individual transaction level, but the display could see visual glitching from interleaved transactions.

**Scenario B — DMA display writes:**
If DMA is ever enabled for display performance, `TFT_eSPI` bypasses the Arduino SPI mutex entirely and uses direct ESP-IDF SPI master driver calls. This would create an unguarded race with RadioLib and SD transactions.

**Scenario C — Multi-transaction atomic operations:**
`radio->readData()` does ~6 SPI transactions. If a display update interleaves between transaction 3 and 4, the radio chip's state is still fine (each RadioLib call is independent), but it wastes bus bandwidth and adds latency to packet reception.

### What Meshtastic does (and why)

Meshtastic adds a global `spiLock` FreeRTOS binary semaphore that wraps **higher-level operations**, not individual SPI transactions:

```cpp
// LockingArduinoHal — wraps RadioLib's SPI access
void LockingArduinoHal::spiBeginTransaction() {
    spiLock->lock();                     // Acquire global lock
    ArduinoHal::spiBeginTransaction();   // Then acquire Arduino SPI transaction
}
void LockingArduinoHal::spiEndTransaction() {
    ArduinoHal::spiEndTransaction();     // Release Arduino SPI transaction
    spiLock->unlock();                   // Then release global lock
}

// Display — acquires lock for entire render cycle
void TFTDisplay::display() {
    concurrency::LockGuard g(spiLock);   // Hold lock for full frame render
    // ... all display writes ...
}
```

**Why both locks?** The Arduino SPI mutex protects the hardware peripheral. The `spiLock` provides higher-level coordination:
- Prevents a radio transaction from splitting a display frame in half
- Prevents display DMA from conflicting with radio register access
- Allows priority-based access control

Meshtastic's T-Deck TFT variant even uses `CONFIG_DISABLE_HAL_LOCKS=1` to disable the Arduino SPI mutex entirely, relying solely on their own `spiLock`. Their comment: "feels to be a bit more stable without locks" — suggesting double-locking caused issues.

### Recommendation

**Phase 2 (now):** No mutex needed. Clean up `SPI.begin()` calls, add a `// TODO: Add SPI mutex when Phase 3 introduces concurrent tasks` comment.

**Phase 3 (networking):** Add a Meshtastic-style `spiLock`:
1. Create a `LockingArduinoHal` subclass for RadioLib (exact Meshtastic pattern)
2. Wrap display render operations with the same lock
3. Wrap SD file operations with the same lock
4. If DMA is enabled for display, the lock is critical (not optional)

---

## 4. Concurrency and Interrupt Findings

### Radio Interrupts

**Our ISR is SPI-safe.** From `radio.cpp:11-13`:

```cpp
static void IRAM_ATTR radioISR() {
    rxFlag = true;  // Just sets a volatile flag — no SPI, no mutex
}
```

The DIO1 interrupt fires when a packet is received. The flag is checked in `loop()` by `radio_receive()`, which then calls `radio->readData()` — all SPI access happens in the main loop context, not the ISR.

### Can you take a mutex in an ISR?

**No.** FreeRTOS `xSemaphoreTake()` must not be called from ISR context. The ISR-safe variant is `xSemaphoreTakeFromISR()`, but even that cannot block. Our pattern of setting a flag and deferring to the main loop is the correct ESP32 approach.

### DMA + Mutex Interaction

**Not currently a concern** because we don't call `tft.initDMA()`. However, `ESP32_DMA` IS auto-defined for ESP32-S3 in the TFT_eSPI headers, meaning:
- The DMA code IS compiled into the binary
- `initDMA()` is available to call
- If anyone calls it in the future, DMA SPI transfers will bypass the Arduino SPI mutex

When DMA is active, TFT_eSPI uses `spi_device_queue_trans()` (ESP-IDF direct) instead of `spi.beginTransaction()`. It tracks pending DMA transfers with a `spiBusyCheck` counter and waits via `spi_device_get_trans_result()`. This is completely independent of the Arduino SPI mutex.

### FreeRTOS Task Context

**Currently: none.** All HAL functions are called from `setup()` and `loop()`, which run on the default Arduino task (core 1, priority 1). No FreeRTOS tasks are created.

**Phase 3 risk:** If radio packet handling moves to a FreeRTOS task (e.g., for time-critical receive processing), SPI contention with the main loop's display updates becomes real. The Arduino SPI mutex would prevent hardware corruption, but an application-level mutex would prevent logical issues (interleaved operations, wasted bandwidth).

### Task Priority Considerations

If Phase 3 introduces tasks, follow Meshtastic's model:
- Display rendering: Priority 1 (low — can wait)
- Radio handling: Priority 5+ (high — packet timing matters)
- Main loop: Priority 1 (default Arduino)

Higher-priority tasks should acquire the SPI lock briefly (individual RadioLib transactions), while lower-priority display tasks hold it longer (full frame renders). This naturally prioritizes radio over display.

---

## 5. Meshtastic Comparison

### Architecture Overview

| Aspect | Meshtastic | TrailDrop (Current) |
|--------|------------|---------------------|
| Display library | LovyanGFX | TFT_eSPI |
| Radio library | RadioLib | RadioLib |
| SD library | ESP32 Arduino SD | ESP32 Arduino SD |
| SPI.begin() | Once in setup() | 3 times (redundant) |
| Custom SPI mutex | Yes — `spiLock` | No |
| Threading model | Cooperative OSThread + optional FreeRTOS TFT task | Single Arduino loop |
| DMA | Yes (LovyanGFX) | No (compiled but not activated) |
| CS pre-init | Yes — all HIGH before SPI.begin() | No |

### Key Meshtastic Patterns Worth Adopting

1. **`LockingArduinoHal`** — Subclass of RadioLib's ArduinoHal that wraps `spiBeginTransaction()`/`spiEndTransaction()` with a global lock. This is the cleanest way to add SPI bus coordination to RadioLib without modifying the library.

2. **CS pin pre-initialization** — Drive ALL SPI CS pins HIGH before `SPI.begin()`:
   ```cpp
   // Before SPI.begin():
   pinMode(PIN_TFT_CS, OUTPUT);     digitalWrite(PIN_TFT_CS, HIGH);
   pinMode(PIN_RADIO_CS, OUTPUT);   digitalWrite(PIN_RADIO_CS, HIGH);
   pinMode(PIN_SDCARD_CS, OUTPUT);  digitalWrite(PIN_SDCARD_CS, HIGH);
   SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI);
   ```
   This prevents bus contention during initialization when peripherals might respond to stray clocks.

3. **Display bus_shared flag** — LovyanGFX has `cfg.bus_shared = true` to properly release the SPI bus between operations. TFT_eSPI has an equivalent via its `locked`/`inTransaction` state machine, but it's less explicit.

### What Meshtastic Does Differently (and why)

- **LovyanGFX instead of TFT_eSPI:** Better built-in SPI bus sharing support (`use_lock`, `bus_shared`), DMA that coordinates with the framework's lock system.
- **Cooperative scheduling:** Most "threads" aren't actually concurrent — they're cooperative coroutines running in the main loop. True FreeRTOS tasks are only used for display rendering on newer variants.
- **`CONFIG_DISABLE_HAL_LOCKS=1`:** The T-Deck TFT variant disables ESP-IDF's internal SPI HAL mutex, relying solely on their own `spiLock`. This avoids double-locking overhead and potential deadlock.

---

## 6. Init Sequence Findings

### Current setup() behavior with return values

`setup()` currently captures all return values but does NOT gate subsequent inits:

```cpp
bool ok_power   = hal::power_init();     // Captured, logged, displayed
bool ok_display = hal::display_init();   // Captured, logged, displayed
bool ok_kb      = hal::keyboard_init();  // Captured, logged, displayed
bool ok_tb      = hal::trackball_init(); // Captured, logged, displayed
bool ok_gps     = hal::gps_init();       // Captured, logged, displayed
bool ok_radio   = hal::radio_init();     // Captured, logged, displayed
bool ok_sd      = hal::storage_init();   // Captured, logged, displayed
bool ok_bat     = hal::battery_init();   // Captured, logged, displayed
```

The ONLY conditional behavior is:
- `ok_radio` gates `radio_start_receive()` (line 443)
- `ok_sd` gates storage info display and crypto tests (lines 435, 451)

All init results are logged to Serial and displayed on screen, but no init failure prevents subsequent inits from running, and there's no overall boot status tracking.

### Which init functions return bool?

| Function | Returns | Can Fail? | Failure Mode |
|----------|---------|-----------|-------------|
| `hal::power_init()` | `bool` | In theory | GPIO setup — should always succeed |
| `hal::display_init()` | `bool` | Rarely | Always returns true (TFT_eSPI doesn't report failure) |
| `hal::keyboard_init()` | `bool` | Yes | I2C device not responding |
| `hal::trackball_init()` | `bool` | Rarely | GPIO setup — should always succeed |
| `hal::gps_init()` | `bool` | Rarely | UART setup — always returns true |
| `hal::radio_init()` | `bool` | Yes | SX1262 not responding, wrong wiring, SPI failure |
| `hal::storage_init()` | `bool` | Yes | No SD card inserted, card corrupt, SPI failure |
| `hal::battery_init()` | `bool` | Rarely | ADC setup — should always succeed |

### Dependency graph

```
power_init()  ←── MUST be first (enables peripheral power via GPIO 10)
    │
    ├── display_init()     needs: power, SPI bus
    │       │
    │       └── (calls SPI.begin() internally — first real SPI init)
    │
    ├── keyboard_init()    needs: power, I2C bus (independent of SPI)
    │
    ├── trackball_init()   needs: power (GPIO only)
    │
    ├── gps_init()         needs: power (UART only, independent of SPI)
    │
    ├── radio_init()       needs: power, SPI bus (already initialized by display)
    │
    ├── storage_init()     needs: power, SPI bus (already initialized by display)
    │
    └── battery_init()     needs: power (ADC only, independent of SPI)
```

**Critical dependency:** `power_init()` MUST succeed before anything else — it drives GPIO 10 HIGH to enable peripheral power. Without it, SPI devices won't respond.

**SPI dependency:** Display init happens to call `SPI.begin()` first (since it's earlier in the sequence), but this is implicit. If display init were removed or reordered, radio and storage would still call `SPI.begin()` themselves.

### Failure modes — what's critical vs degraded?

| Module Fails | Can We Still Run? | Impact | Severity |
|--------------|-------------------|--------|----------|
| **Power** | NO | Nothing works — peripherals have no power | CRITICAL |
| **Display** | YES (degraded) | No visual output. Serial still works for debugging. Radio, GPS, storage all functional. | LOW — headless mode is viable for relay/beacon |
| **Keyboard** | YES (degraded) | No user input. Device can still relay, beacon, display GPS. | LOW |
| **Trackball** | YES (degraded) | No cursor. Keyboard still works for text input. | VERY LOW |
| **GPS** | YES (degraded) | No position data. Can still relay packets, chat, share cached waypoints. | MEDIUM |
| **Radio** | YES (degraded) | No networking at all. GPS, display, storage work. Useful only for local diagnostics. | HIGH — but device can record GPS tracks to SD |
| **Storage** | YES (degraded) | No identity persistence (new keys each boot), no waypoint storage, no logs. Crypto tests skip. | HIGH — identity and data loss |
| **Battery** | YES (degraded) | No power monitoring. Everything else works. Risk of unexpected shutdown. | LOW |

### Recommended init failure handling

```
CRITICAL (halt with error display):
  - power_init() fails → halt, display error on Serial (display may not work)

MAJOR (set degraded flag, continue):
  - radio_init() fails → set radioOK = false, skip networking in Phase 3
  - storage_init() fails → set storageOK = false, skip identity persistence, warn user

MINOR (log warning, continue):
  - display_init() fails → headless mode, Serial only
  - gps_init() fails → no position, continue
  - keyboard/trackball/battery → log and continue
```

The existing pattern of capturing return values and using them for conditional behavior (like `ok_radio` gating `radio_start_receive()`) is correct. It just needs to be extended to:
1. Track an overall boot health status (bitmask or struct)
2. Gate Phase 3 networking on `ok_radio && ok_storage` (need identity from SD)
3. Optionally halt on power failure (though if power fails, nothing works anyway)

---

## 7. Risks and Gotchas

### Risk 1: DMA is one function call away from being activated

`ESP32_DMA` is auto-defined for ESP32-S3 in `TFT_eSPI_ESP32_S3.h`. Calling `tft.initDMA()` anywhere would bypass the Arduino SPI mutex for display writes, creating an unguarded race with radio and SD. If DMA is ever enabled for display performance, a Meshtastic-style `spiLock` becomes **mandatory**, not optional.

### Risk 2: TFT_eSPI `inTransaction` batching

TFT_eSPI has an optimization where sequential graphics calls can keep the SPI transaction open (via `startWrite()`/`endWrite()` or internally via `inTransaction`). During this window, the SPI mutex is held, blocking radio and SD access. Currently this isn't a problem (single-threaded), but with concurrent tasks, a long display update could starve radio packet reception.

### Risk 3: SD card operations are slow

SD card writes at 4 MHz are significantly slower than display (40 MHz) or radio operations. An SD write holds the SPI mutex for the entire sector write duration. If identity save or waypoint logging happens while a radio packet arrives, the packet must wait.

### Risk 4: CS pin float during boot

Between power-on and `SPI.begin()`, CS pins may float. If a peripheral sees a LOW CS with stray clock edges, it could enter an undefined state. Meshtastic explicitly initializes all CS pins HIGH before `SPI.begin()`. We should do the same.

### Risk 5: RadioLib initInterface double-init

When constructing `Module(cs, dio1, rst, busy, SPI)`, RadioLib's `ArduinoHal` defaults to `initInterface = true`, which means `Module::init()` calls `SPI.begin()` (with no pin args). Since we've already called `SPI.begin(pins)`, this no-arg call is a no-op. But if the init order ever changes, the no-arg `SPI.begin()` would initialize with default pins, not our T-Deck pins. Consider passing `initInterface = false` to the ArduinoHal or documenting this dependency.

### Risk 6: No CS assertion during init sequence

When `display_init()` calls `tft.init()`, it sends initialization commands to the ST7789 with CS asserted. At this point, the radio and SD CS pins haven't been explicitly configured yet — they're in their post-reset default state. On ESP32-S3, GPIO pins default to input mode after reset, so they float. If the radio or SD card interprets floating CS as selected, it could respond to display init commands and corrupt its state. Pre-initializing CS pins HIGH (Risk 4) addresses this.

### Not a risk: Multiple SPI.begin() calls

Despite being messy, multiple `SPI.begin()` calls with the same pins are definitively safe on ESP32. The function is idempotent. Clean up for clarity, not correctness.

---

## Summary: Action Items for Build Prompt

### SPI Bus Cleanup (do now, Phase 2.5)
1. Add CS pin pre-initialization (all HIGH) before SPI.begin() in setup()
2. Move SPI.begin() to a single explicit call in setup() after CS pre-init
3. Remove redundant SPI.begin() from radio.cpp and storage.cpp
4. Add comment documenting that TFT_eSPI and SD.begin() also call SPI.begin() internally (idempotent)

### Init Return Value Handling (do now, Phase 2.5)
1. Add boot health tracking (bitmask or struct with ok_* fields)
2. Gate future networking on `ok_radio && ok_storage`
3. The existing pattern of capturing and logging is good — extend with gating logic
4. Consider halting on power_init() failure (display a Serial error)

### SPI Mutex (defer to Phase 3)
1. Not needed for current single-threaded architecture
2. When Phase 3 introduces concurrent tasks: add a `LockingArduinoHal` for RadioLib (Meshtastic pattern)
3. Wrap display render cycles and SD operations with the same global lock
4. If DMA is ever enabled: mutex becomes critical, not optional

### Things NOT to do
- Don't add a mutex now — it's unnecessary overhead for single-threaded code
- Don't switch from TFT_eSPI to LovyanGFX — both work fine for our use case
- Don't disable HAL locks (`CONFIG_DISABLE_HAL_LOCKS`) — only Meshtastic needs this due to their double-lock architecture
- Don't add raw `SPI.transfer()` calls to HAL code — continue using libraries exclusively
