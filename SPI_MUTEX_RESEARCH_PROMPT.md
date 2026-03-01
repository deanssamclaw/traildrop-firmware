# SPI Mutex + Init Return Checks — Research Prompt

## Context

TrailDrop firmware runs on a LilyGO T-Deck Plus (ESP32-S3). Three HAL modules share the SPI bus: display (ST7789 via TFT_eSPI), radio (SX1262 via RadioLib), and SD card storage. Currently there's no explicit mutex protecting the bus, and `SPI.begin()` is called redundantly in both radio.cpp and storage.cpp. Additionally, `setup()` ignores init return values from HAL modules.

These are blockers #3 and #5 from a firmware review. Phase 1 (HAL) and Phase 2 (crypto) are hardware-verified and working. We need to fix these before Phase 3 (networking), which will use radio + display concurrently.

**Your job is RESEARCH ONLY.** Do not write implementation code. Produce findings that will be used to write a build prompt.

## What to Research

### 1. SPI Bus Initialization Bug

**Known issue:** Both `radio.cpp` (line 10) and `storage.cpp` (line 11) call `SPI.begin(PIN_SPI_SCK, PIN_SPI_MISO, PIN_SPI_MOSI)`. This is likely wrong — `SPI.begin()` should be called once for a shared bus.

Answer:
a. **Where should `SPI.begin()` be called?** Once in `setup()` before any HAL module inits? Or is it safe to call multiple times on ESP32-S3?
b. **Does `TFT_eSPI::init()` call `SPI.begin()` internally?** Read the actual TFT_eSPI source in `.pio/libdeps/t-deck-plus/TFT_eSPI/` — trace the init path for ESP32-S3.
c. **Init sequence dependency:** Display init currently runs BEFORE radio init. If radio.cpp is what calls `SPI.begin()`, does display actually work? Or does TFT_eSPI handle its own SPI setup? Map the actual init order from `setup()` in `src/main_test.cpp`.

### 2. Library-Level SPI Transaction Handling

**Critical question: Do the libraries already handle SPI bus arbitration?**

Read the ACTUAL library source code in `.pio/libdeps/t-deck-plus/` for each:

a. **TFT_eSPI:**
   - Does it call `SPI.beginTransaction()` / `SPI.endTransaction()` internally?
   - Does it have a `locked` flag or internal mutex?
   - Look specifically at the ESP32-S3 processor-specific code paths.
   - Does it use DMA for display writes? If so, does it hold the SPI bus during DMA transfer, or release and wait on a semaphore?

b. **RadioLib:**
   - Read `Module.cpp` — does it call `spiBeginTransaction()` / `spiEndTransaction()` on every SPI access?
   - Does it have any internal locking beyond SPI transactions?

c. **SD library (ESP32 Arduino):**
   - Does the ESP32 Arduino SD library use `SPI.beginTransaction()` internally?
   - Are file read/write operations protected?

d. **ESP32 Arduino SPI core:**
   - Find the ESP32 Arduino `SPI.cpp` source — does `SPI.beginTransaction()` acquire a FreeRTOS mutex internally?
   - If so, is that mutex sufficient to protect the bus across all three libraries?
   - This is the foundational question: if the Arduino SPI layer already has a mutex, we may not need to add our own.

### 3. Concurrency and Interrupts

a. **Radio interrupts:** Does our radio HAL use DIO1 interrupts? If so, what SPI access happens in the ISR vs deferred to main loop?
b. **DMA + mutex interaction:** If TFT_eSPI uses DMA on ESP32-S3, what happens to the SPI mutex during transfer? Can radio interrupts preempt it?
c. **FreeRTOS task context:** Are any HAL functions called from FreeRTOS tasks (vs the main Arduino loop)? If so, what are the task priorities? Could a display task starve a radio task?
d. **Can you take a mutex in an ISR?** If not, what's the standard ESP32 pattern for deferring SPI access from interrupt context?

### 4. Meshtastic Comparison

Meshtastic is a production ESP32 + SX1262 + display project. Research their specific approach:

a. **SPI.begin() placement:** Does Meshtastic call it once centrally, or per-module?
b. **Custom mutex wrappers:** Do they add locking beyond library transactions? Look for `SPILock.h` or similar.
c. **FreeRTOS tasks:** Do they use separate tasks for display rendering vs radio? What priorities?
d. **Specific files:** Check their `main.cpp`, SPI-related headers, and display/radio init code.

### 5. Init Return Value Handling

Look at `setup()` in `src/main_test.cpp`:

a. **Current behavior:** What does setup() currently do with init return values? Show exactly what the code does (or doesn't do) when an init fails.
b. **Which init functions return bool?** List each `hal::*_init()` call and its return type.
c. **Dependency graph:** Which inits depend on others having succeeded?
   - Does radio need SPI.begin() first?
   - Does storage need SPI.begin() first?
   - Does display need SPI.begin() first (or does TFT_eSPI handle it)?
d. **Failure modes per module:**
   - Display fails → Can we still run? (Serial works, no visual feedback)
   - Radio fails → Can we still run? (No networking, GPS/display still work)
   - Storage fails → Can we still run? (No identity persistence, crypto tests skip)
   - GPS fails → Can we still run? (No position, can still relay)
   - Battery monitor fails → Can we still run? (No power monitoring)
   - What's critical vs degraded-but-functional?

### 6. Other ESP32+LoRa+Display Projects

Beyond Meshtastic, check if any of these handle shared SPI differently:
- LilyGO T-Deck example firmware
- Any PlatformIO examples for ESP32-S3 + SX1262 + TFT_eSPI

## Our Actual Code

Read these files to ground your research in what we have:

- `src/main_test.cpp` — setup() function, init sequence
- `src/hal/display.cpp` — display HAL (uses TFT_eSPI, no direct SPI calls)
- `src/hal/radio.cpp` — radio HAL (uses RadioLib, calls SPI.begin())
- `src/hal/storage.cpp` — storage HAL (uses SD library, calls SPI.begin())
- `src/hal/gps.cpp` — GPS HAL (UART, not SPI — but check)
- `include/config.h` — pin definitions

**Key observation from reviewer:** There are ZERO raw `SPI.transfer()` calls in our HAL code. Everything goes through libraries. This means the question isn't "where do we add mutex locks in our code" but "do the libraries + ESP32 Arduino SPI core already handle it, and is that sufficient?"

## What to Deliver

A research document with:

1. **SPI.begin() findings** — is multi-call a bug? Where should it live?
2. **Library transaction audit** — does each library use SPI transactions? Does the ESP32 SPI core use a FreeRTOS mutex?
3. **Do we need our own mutex?** Clear yes/no with evidence from library source.
4. **Concurrency/interrupt findings** — DMA, ISR, task priority issues
5. **Meshtastic comparison** — how production firmware handles this
6. **Init sequence findings** — dependency graph, failure modes, recommendations
7. **Risks and gotchas** — anything surprising

Save your findings to: `/Users/systems/.openclaw/workspace/traildrop-firmware/SPI_RESEARCH.md`

## Constraints

- **DO NOT modify any source files** — research only
- **Read actual library source** in `.pio/libdeps/t-deck-plus/` — don't guess about internals
- **Read our actual HAL code** — ground every answer in what we have
- If you can't determine something from source, say so explicitly and note what would need testing

When completely finished, run:
`openclaw system event --text "Done: SPI mutex + init research complete — findings in SPI_RESEARCH.md" --mode now`
