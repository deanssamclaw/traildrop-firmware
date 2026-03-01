# Phase 4d Cal Review: Display UI — Boot, Main, Share, Detail Screens

Reviewed: 2026-03-01
Commits: 64865bc, b0cdc3d
Files reviewed: `src/ui/display_ui.h`, `src/ui/display_ui.cpp`, `src/ui/ui.cpp`, `src/ui/ui.h`, `src/main_test.cpp`
Cross-referenced: `src/msg/waypoint.h`, `src/net/peer.h`, `src/net/peer.cpp`, `src/hal/display.h`, `src/hal/keyboard.h`, `include/config.h`

---

## 1. Buffer Overflows in String Formatting

### 1a. draw_line padded buffer (display_ui.cpp:146-157) — SAFE

`char padded[60]` with max_chars of 53 (size 1) or 26 (size 2). The `memcpy` is clamped to `min(strlen(text), max_chars)`. The padding loop is bounded by `i < max_chars && i < sizeof(padded) - 1`. Null terminator placed at `min(max_chars, 59)`. Worst case: size 1, max_chars=53, writes 54 bytes (53 + null) into 60-byte buffer. **No overflow.**

### 1b. Main screen snprintf calls — SAFE

All use `buf[60]` with `sizeof(buf)`:
- Top bar (line 183): `"TrailDrop          * %d"` — 22 chars + max 10-digit int = 32. SAFE.
- Coords (line 191): Two `%.4f %c` strings — max `"180.0000 W  90.0000 S"` = 23 chars. SAFE.
- Alt/sats (line 194): `"%dm  %d sats"` — max ~20 chars. SAFE.
- Peer row (line 239): `"%c %-10.10s %6s %4s"` — exactly 24 chars max (1+1+10+1+6+1+4). Fits within draw_line's size-2 limit of 26. SAFE.

### 1c. format_time_ago (display_ui.cpp:95-101) — SAFE

Called with `ago[8]` (line 232) and `ago[16]` (line 342). Maximum output is `">1d"` (3 chars + null = 4), or `"59m"` / `"23h"` (3+null). All fit within 8 bytes. The elapsed_ms overflow from `millis()` wrapping is handled correctly by unsigned subtraction. **No overflow.**

### 1d. format_lat / format_lon — SAFE

Called with 20-byte buffers. Max output: `"180.0000 W"` = 10 chars + null = 11. Fits in 20. **No overflow.**

### 1e. Detail screen distance (display_ui.cpp:335) — SAFE

`"%.1f miles away"` with max antipodal distance ~12,451 miles → `"12451.0 miles away"` = 18 chars + null. Fits in `buf[60]`. **No overflow.**

### 1f. Share screen name input — COSMETIC CLIP (see section 6a)

`"Name: %s_"` where s_share_name is max 20 chars: total = 6 + 20 + 1 = 27 chars. snprintf to `buf[60]` is fine, but draw_line with size 2 clips to 26 chars. The cursor `_` disappears when name reaches 20 characters. Not a buffer overflow — a display issue (see section 6a).

---

## 2. Input Handling

### 2a. Empty name rejection — CORRECT

`handle_share` (line 390): `if (s_share_len == 0) return;` blocks sending with no name. Pressing Enter on an empty field does nothing. **Good.**

### 2b. Rapid keypresses — SAFE

`keyboard_read()` returns one char per call. `ui_update()` processes at most one key per invocation. All state transitions (screen changes, character append, selection movement) are atomic within a single `ui_update()` call — no intermediate state visible. **No race conditions or hangs.**

### 2c. Keys during BOOT and CONFIRM — CORRECT

Lines 462-463: both cases explicitly fall through with no action. Keys are silently consumed. **Good.**

### 2d. Backspace edge cases on Share screen — CORRECT

- BS with `s_share_len > 0`: decrements len first, then writes null (line 408). No underflow.
- BS with `s_share_len == 0`: transitions to MAIN (line 411). **Clean exit.**
- ESC: always transitions to MAIN (line 411). **Correct.**

### 2e. Navigation on empty peer list — SAFE

- Enter with `s_wp_count == 0`: guarded by `if (s_wp_count > 0)` (line 366). Does nothing. **Correct.**
- 'j' with `s_wp_count == 0`: condition `s_selected < s_wp_count - 1` becomes `0 < -1` → false (both are `int`). Does nothing. **Correct.**
- 'k' with `s_selected == 0`: condition `s_selected > 0` is false. Does nothing. **Correct.**

### 2f. Selection clamping — CORRECT

Lines 211-212: `s_selected` is clamped to `[0, s_wp_count - 1]` before rendering. If a waypoint expires (becomes invalid) between frames, the selection stays in bounds. **No out-of-bounds array access.**

---

## 3. Waypoint Storage Ring

### 3a. Slot allocation strategy — CORRECT

`ui_on_waypoint_received` (lines 503-542) implements LRU eviction, not a ring buffer:
1. Existing sender match (by name) → update in place. **Correct: no duplicate entries per sender.**
2. First empty slot → use it. **Correct: fills sparsely.**
3. All slots full, no sender match → evict oldest (lowest `received_at`). **Correct LRU.**

### 3b. Overflow with 16 slots full — CORRECT

When all 16 slots are valid and a new sender arrives, `target` remains -1 through the loop. Line 526: `if (target < 0) target = oldest_idx;` — evicts the entry with the oldest `received_at` timestamp. The `oldest_idx` tracking (lines 506-523) correctly scans all valid slots. **No buffer overflow, no lost tracking.**

### 3c. Sender name copy — SAFE

Lines 529-530: `strncpy(sender, sender_name, 31)` + explicit null at `sender[31]`. The `sender` field is `char[32]`, so this fills exactly 32 bytes. **No overflow.** The `strncmp` match on line 515 uses 31 as length, matching the strncpy length. **Consistent.**

### 3d. millis() wrapping — SAFE

`received_at` stores `millis()`. Elapsed time calculations use `now - dw.received_at` with unsigned subtraction, which wraps correctly at ~49.7 days. The LRU eviction compares `received_at` values directly; after a millis() wrap, the oldest entry might not be correctly identified. **Severity: VERY LOW** — 49.7 days of continuous uptime without a reboot is unlikely for a handheld trail device, and the consequence is evicting the wrong slot once.

### 3e. **BUG: peer_lookup_by_lxmf_dest(nullptr) — UB (MUST-FIX)**

Line 536:
```cpp
const net::Peer* peer = net::peer_lookup_by_lxmf_dest(nullptr);
```

This passes `nullptr` to `peer_lookup_by_lxmf_dest`, which calls `memcmp(hash, nullptr, 16)` for every valid peer. `memcmp` with a null pointer is **undefined behavior** per C/C++ standard, regardless of the comparison length. On ESP32 this will likely crash with a LoadProhibited exception as soon as the first valid peer exists in the table.

The result is never used — this is dead code. The comment says "We don't have the LXMF source here easily, so zero it," and line 538 zeroes `peer_dest` anyway.

**Fix: Delete lines 536-537 entirely.** The `memset` on line 538 is the intended behavior.

```diff
-    const net::Peer* peer = net::peer_lookup_by_lxmf_dest(nullptr);
-    // We don't have the LXMF source here easily, so zero it
     memset(s_waypoints[target].peer_dest, 0, 16);
```

---

## 4. Integration with waypoint_send

### 4a. Null pointer guards — CORRECT

`handle_share` (lines 392-400) checks `s_identity && s_our_lxmf_dest` before dereferencing. Checks `peer != nullptr` before accessing `peer->dest_hash`. **Three-layer null protection.** If `ui_set_send_context` was never called (identity not ready at boot), the send silently does nothing. **Safe degradation.**

### 4b. Send target — SINGLE PEER ONLY

Line 394: `net::peer_first()` sends to the first valid peer in the table. If multiple peers are visible, the user cannot choose a recipient. For Phase 4d this is acceptable — the UI doesn't present a "send to whom?" picker. **Noted for future phases.**

### 4c. waypoint_send call site — CORRECT

```cpp
msg::waypoint_send(*s_identity, s_our_lxmf_dest, peer->dest_hash, s_share_name, "");
```

- `s_share_name` is always null-terminated: `memset` on screen entry (line 361) + explicit null on each append (line 416) + explicit null on backspace (line 408). **Safe.**
- Empty string `""` for notes. **Valid — Phase 4c handles empty notes correctly (5-field map).**
- `s_our_lxmf_dest` is `const uint8_t*` pointing to `device_lxmf_destination.hash` — a fixed struct member, not heap-allocated. **No lifetime issue.**

### 4d. Confirmation screen timing — CORRECT

Lines 403-404: `s_confirm_start = millis()` set before `go_to(Screen::CONFIRM)`. Line 451: auto-dismiss after 1000ms. The confirm screen always shows, even if waypoint_send failed (no peer, send error). This is arguably wrong — it says "Shared!" even on failure — but the failure cases are: (a) no identity (device broken), (b) no peer (user will see empty peer list). **Cosmetic issue, not a crash risk.**

### 4e. Receive path in main_test.cpp — CORRECT

Lines 1721-1722: `peer_lookup_by_lxmf_dest(msg.source_hash)` properly passes the LXMF source hash (not null). Falls back to `"Unknown"` if peer not found. This is the **correct** call pattern — contrast with the broken nullptr call in display_ui.cpp (section 3e).

---

## 5. Design Compliance — Protocol Internals Audit

**Review criterion**: No screen should show destination hashes, LXMF protocol details, Reticulum internals, or raw RSSI values.

### 5a. Boot screen — CLEAN

"TrailDrop" + "Starting..." — no protocol information.

### 5b. Main screen — CLEAN

- Top bar: "TrailDrop" + peer count as `* N` (star + number). No hash.
- GPS: Latitude/longitude in `"38.8814 N  94.8191 W"` format with N/S/E/W hemisphere. No raw decimals without context.
- Peers: `"> Name      0.3mi  2m"` — name, distance, time ago. **No RSSI, no hashes.**
- Footer: `"[S] Share spot"` — action hint only.

### 5c. Share screen — CLEAN

Name input + GPS position. No protocol information. "No GPS fix" warning when appropriate.

### 5d. Confirm screen — CLEAN

"Shared!" — no details at all.

### 5e. Detail screen — CLEAN

- Title: `"Riley's Spot"` — sender name + human label.
- Position: lat/lon in N/S/E/W format.
- Elevation: `"267m elevation"`.
- Distance: `"0.3 miles away"`.
- Time: `"Received 2m ago"`.
- **Signal: `"Signal: Strong"` — human-readable label, NOT raw RSSI.** The `signal_label()` function (lines 87-92) maps RSSI thresholds to words. **No dBm value visible.**

### 5f. Serial output — ACCEPTABLE

`Serial.printf` calls include `[UI]` tagged debug lines with names and RSSI values. These go to the USB serial console only, not the display. **Standard firmware debug practice — not visible to the trail user.**

**Verdict: All five screens are CLEAN. No protocol internals leak to the display.**

---

## 6. Additional Findings

### 6a. Share screen cursor clips at max name length (COSMETIC)

`"Name: %s_"` at max name (20 chars) = 27 chars, but `draw_line` with size 2 clips at 26. The cursor `_` vanishes when the user types the 20th character. The input still works correctly (can't type more), but the missing cursor doesn't clearly signal "you've reached the limit."

**Recommendation**: Either reduce max name to 19 chars (`s_share_len < 19` on line 413), or display the name input at size 1 (53-char width) for this line.

### 6b. Dual Screen enum in same namespace — LATENT CONFLICT

`ui.h` declares `enum Screen { SCREEN_MAIN, ... }` (unscoped).
`display_ui.h` declares `enum class Screen { BOOT, MAIN, ... }` (scoped).

Both are in `namespace ui`. Currently no translation unit includes both headers (main_test.cpp includes only display_ui.h; ui.cpp includes only ui.h). But if any future file includes both, compilation fails with a redefinition error.

**Recommendation**: Since ui.h/ui.cpp are Phase 5 stubs, either (a) remove the stub Screen enum from ui.h now, or (b) rename it to `LvglScreen` to avoid future conflict.

### 6c. "Shared!" confirmation always shows — COSMETIC

`handle_share` transitions to CONFIRM screen (line 404) regardless of whether `waypoint_send` was actually called or succeeded. If there are no peers (line 398), "Shared!" still flashes. The serial output says `"[UI] No peers to send to"` but the display says "Shared!".

**Recommendation**: Only transition to CONFIRM if the send path was actually entered (peer exists). Otherwise show a brief "No peers" message or return to MAIN.

### 6d. Detail screen validates s_detail_idx against MAX_DISP_WP, not sorted list — CORRECT but fragile

Lines 305-306 check `s_detail_idx < 0 || s_detail_idx >= MAX_DISP_WP || !s_waypoints[s_detail_idx].valid`. The `s_detail_idx` is set from `sorted_idx[s_selected]` in `handle_main` (line 370), which is always a valid array index into `s_waypoints[]`. If the waypoint becomes invalid between frames (evicted by a new reception), the validity check catches it and returns to MAIN. **Correct.**

### 6e. ui.cpp stub after linker fix (commit b0cdc3d) — CLEAN

The second commit removed `ui_init()` and `ui_update()` stubs from `ui.cpp` that were conflicting with the real implementations in `display_ui.cpp`. Only `ui_show()` remains as a Phase 5 placeholder. **Correct fix — no residual issues.**

---

## 7. Summary — Verdict

### Overall: PASS (one must-fix)

Phase 4d delivers a clean, well-structured text UI with proper input handling and correct display buffer management. Every snprintf uses sizeof-bounded buffers, draw_line clips text safely, and input edge cases (empty lists, empty names, rapid keys, boot/confirm key ignoring) are all handled. The waypoint display ring implements correct LRU eviction. The design compliance audit is **fully clean** — no screen exposes hashes, protocol names, or raw radio metrics.

### Must-fix (1)

1. **Delete `peer_lookup_by_lxmf_dest(nullptr)` call** (display_ui.cpp:536-537) — Dead code that triggers undefined behavior (`memcmp` with null pointer) when any valid peer exists. Will crash on ESP32. Remove the two lines; the `memset` on line 538 is the intended behavior.

### Should-fix (2)

2. **False "Shared!" on no-peer send** (section 6c) — Confirmation screen shows even when no peer was available to receive the waypoint. Add a peer-existence check before transitioning to CONFIRM, or show a different message.

3. **Resolve dual Screen enum** (section 6b) — Two types named `Screen` in `namespace ui` across ui.h and display_ui.h. Will cause compilation failure if both are ever included. Remove or rename the Phase 5 stub enum.

### Nice-to-have (2)

4. Fix share screen cursor clipping at 20-char name (section 6a) — reduce max to 19 or use size 1 for the name input line.
5. Add `sender_name` null check in `ui_on_waypoint_received` — current callers always pass non-null, but the function's public API doesn't enforce it.

---

*Reviewed by Cal (firmware reviewer agent), 2026-03-01*
