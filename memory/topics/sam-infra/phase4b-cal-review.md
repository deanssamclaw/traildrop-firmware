# Phase 4b Cal Review: LXMF over Transport

Reviewed: 2026-03-01
Commit: 503c940
Files reviewed: `src/msg/lxmf_transport.h`, `src/msg/lxmf_transport.cpp`, `src/net/peer.h`, `src/net/peer.cpp`, `src/main_test.cpp`
Cross-referenced: Phase 4 Cal review, Phase 4a.5 Cal review, `src/msg/lxmf.h`, `src/msg/lxmf.cpp`, `src/crypto/identity.cpp`, `src/crypto/token.cpp`, `src/net/packet.h`, `src/net/transport.h`, `include/config.h`

---

## 1. Buffer Overflows

### 1a. lxmf_plain[500] in lxmf_send (lxmf_transport.cpp:83) — SAFE

`lxmf_build` has an internal sanity check at lxmf.cpp:71: `if (total > 500) return false;`. The caller's buffer is exactly 500 bytes, matching the check. No overflow possible.

**Note**: `lxmf_build` does NOT accept a buffer capacity parameter — it uses a hardcoded 500-byte check. If the constant and the caller's buffer ever drift apart, silent overflow could occur. Document the coupling.

### 1b. encrypted[RNS_MTU] in lxmf_send (lxmf_transport.cpp:108) — **BUG: OVERFLOW (MEDIUM-HIGH)**

**This is the most serious issue in Phase 4b.**

`encrypted` is declared as `uint8_t encrypted[RNS_MTU]` = 500 bytes. `identity_encrypt` output = `ephemeral_pub(32) + iv(16) + PKCS7_ciphertext + hmac(32)`. PKCS7 always adds at least 1 byte of padding, rounding up to next 16-byte block. Total overhead: 80 bytes fixed + 1-16 bytes padding.

**Overflow calculation:**

```
encrypted_len = 32 + 16 + ceil_to_16(plaintext_len) + 32
              = 80 + ((plaintext_len / 16) + 1) * 16
```

| lxmf_len (plaintext) | AES-CBC output | Encrypted total | Fits in 500? |
|---|---|---|---|
| 200 | 208 | 288 | YES |
| 300 | 304 | 384 | YES |
| 400 | 416 | 496 | YES — barely |
| 415 | 416 | 496 | YES — maximum safe |
| 416 | 432 | 512 | **NO — 12 bytes over** |
| 466 | 480 | 560 | **NO — 60 bytes over** |
| 500 | 512 | 592 | **NO — 92 bytes over** |

`lxmf_build` can output up to 500 bytes (its hardcoded limit). Encryption of 500 bytes needs 592 bytes — a **92-byte stack buffer overflow**.

**Practical impact with current constants:**

With max standard content (`LXMF_MAX_TITLE=64`, `LXMF_MAX_CONTENT=280`, `custom_type=18`):
- packed_payload: `1 + 9 + (2+64) + (3+280) + (1+2+20+2+2)` = 386 bytes
- lxmf_build total: `16 + 64 + 386` = 466 bytes
- Encrypted: 560 bytes → **overflows by 60 bytes**

Even with maximum title+content, the buffer overflows. With today's small test messages (~145 bytes → ~240 encrypted), it's safe. **But Phase 4c will add GPS waypoint data as custom_data, likely pushing into overflow territory.**

**Cascade**: The same overflow propagates to `pkt.payload[RNS_MTU]` at line 123 (`memcpy(pkt.payload, encrypted, enc_len)`).

**Recommendation (must-fix):**
```cpp
// Option A (preferred): Pre-check in lxmf_send after lxmf_build
// 415 = max plaintext where encrypted output fits in 500 bytes
if (lxmf_len > 415) {
    Serial.println("[LXMF-TX] ERROR: Message too large for encrypted transport");
    return false;
}

// Option B (stricter, matches RNS spec): Use ENCRYPTED_MDU
if (lxmf_len > 383) {  // RNS ENCRYPTED_MDU from Python spec
    Serial.println("[LXMF-TX] ERROR: Message exceeds encrypted MDU");
    return false;
}
```

Option A prevents the buffer overflow. Option B also ensures the final packet fits within RNS wire limits (MTU minus header). Option B is recommended for interop correctness.

**Also**: `identity_encrypt` does not accept an output buffer size parameter. It trusts the caller to provide a large enough buffer. This is a latent API hazard.

### 1c. full_lxmf[600] in lxmf_transport_poll (lxmf_transport.cpp:193) — SAFE

Bounded by the explicit check at line 194: `if (16 + dec_len > sizeof(full_lxmf))`. Since `dec_len` comes from decrypting a radio packet payload (max ~481 bytes for H1) minus encryption overhead (~80 bytes), `dec_len` is at most ~400 bytes. `16 + 400 = 416 < 600`. **No issue.**

### 1d. decrypted[RNS_MTU] in lxmf_transport_poll (lines 181, 234) — SAFE

Decryption always shrinks data (removes ephemeral key + IV + HMAC + padding). Input from `pkt.payload` is bounded by `RNS_MTU`. Output is always smaller than input. `identity_decrypt` minimum overhead is 96 bytes (ephemeral_pub + iv + one_block + hmac), so max decrypted output = 500 - 96 = 404 bytes. **No overflow.**

### 1e. rx_buf[RNS_MTU] in lxmf_transport_poll (line 143) — SAFE

Passed to `hal::radio_receive` with `sizeof(rx_buf)` as the limit. **No issue.**

---

## 2. Destination Routing — CORRECT

### Send path: Does lxmf_send use peer->lxmf_dest_hash for DATA packet dest_hash?

**YES.** Verified at three critical points:

1. **Peer lookup** (line 69): `peer_lookup(peer_announce_dest)` — looks up by announce dest. Correct — caller passes the announce dest they know.

2. **LXMF build** (line 88): `lxmf_build(our_identity, our_lxmf_dest, peer->lxmf_dest_hash, ...)` — source = our LXMF dest, destination = peer's LXMF dest. Correct.

3. **DATA packet** (line 121): `memcpy(pkt.dest_hash, peer->lxmf_dest_hash, DEST_HASH_SIZE)` — packet dest = peer's lxmf.delivery hash. **Correct.**

4. **Zero check** (lines 76-80): Guards against sending to pre-4a.5 peers with zeroed `lxmf_dest_hash`. **Good defensive check.**

### Receive path: Does receive correctly prepend our lxmf dest_hash?

**YES.** Verified against Python LXMRouter.py:1822-1824:

```python
# Python (opportunistic receive):
lxmf_data += packet.destination.hash  # prepend dest_hash
lxmf_data += data                     # source_hash + sig + packed_payload
```

Firmware (lines 198-199):
```cpp
memcpy(full_lxmf, s_lxmf_dest->hash, 16);       // prepend our lxmf dest
memcpy(full_lxmf + 16, decrypted, dec_len);       // source_hash + sig + payload
```

**Matches Python behavior exactly.** The dest_hash is `s_lxmf_dest->hash` — the same destination the sender addressed the packet to (validated at line 179).

### Receive dispatch priority

```cpp
if (dest == our_lxmf_dest)       → LXMF DATA path
else if (dest == our_announce_dest) → Legacy DATA path
else                               → Ignore
```

LXMF first, legacy fallback second. **Correct priority order.**

---

## 3. Receive Path: dest_hash Reconstruction Detail

The opportunistic LXMF format omits `dest_hash` from the wire payload (inferred from the RNS packet header). The full LXMF wire format is:

```
dest_hash(16) + source_hash(16) + signature(64) + packed_payload
```

But the encrypted plaintext (after decryption) only contains:

```
source_hash(16) + signature(64) + packed_payload
```

The receive path at lines 193-199 reconstructs the full LXMF by prepending `s_lxmf_dest->hash`. This is then fed to `lxmf_parse` which expects the full format. **Correct reconstruction.**

---

## 4. Dedup Ring Buffer — CORRECT

### Structure (lxmf_transport.cpp:22-24)

```cpp
static const size_t DEDUP_BUFFER_SIZE = 64;
static uint8_t dedup_hashes[64][32];  // 2048 bytes static memory
static size_t dedup_index = 0;
```

### Correctness analysis

1. **Initialization** (line 52): `memset(dedup_hashes, 0, sizeof(dedup_hashes))`, `dedup_index = 0`. All slots zeroed. **Correct.**

2. **Duplicate check** (lines 27-32): Linear scan of ALL 64 entries with 32-byte `memcmp`. O(64) per check = ~2KB of comparisons — negligible on ESP32 at 240MHz. **Correct** — checks all slots including old entries before wrap. This is correct ring buffer behavior.

3. **Record** (lines 35-38): Writes to `dedup_hashes[dedup_index]`, then `dedup_index = (dedup_index + 1) % 64`. No off-by-one: index 0 through 63 are used, wraps to 0 after 63. **Correct.**

4. **Uninitialized memory**: None. `memset(0)` in init. Zero-filled slots match only messages with all-zero SHA-256 hash, probability 1/2^256. **Negligible risk.**

5. **Self-dedup** (line 132): After sending, records our own message hash to prevent processing reflected packets. **Good design.**

6. **Thread safety**: Single-threaded Arduino `loop()`. No race conditions. **Correct.**

7. **Ordering**: Dedup check happens AFTER decryption and parsing (line 209). Necessarily late — the message hash depends on plaintext content. Wastes decrypt/parse work for duplicates, but at LoRa message rates this is negligible.

### Capacity

64 entries at LoRa rates (~seconds per message). Even at 1 message/second, the buffer holds the last 64 seconds. Typical mesh rate is 1 message/minute. **Generous.**

---

## 5. Signature Verification — CORRECT

### Key usage

```cpp
// lxmf_transport.cpp:216-218
const net::Peer* sender = net::peer_lookup_by_lxmf_dest(msg.source_hash);
if (sender) {
    msg.signature_valid = lxmf_verify(msg, sender->ed25519_public);
```

**Uses the SENDER's ed25519 public key.** Not ours. The verification chain:

```
msg.source_hash (sender's lxmf.delivery hash)
  → peer_lookup_by_lxmf_dest → find peer entry
  → peer.ed25519_public (sender's signing key, stored from their announce)
  → lxmf_verify → identity_verify(sender_key, signed_part, sig)
```

`lxmf_verify` (lxmf.cpp:174-197) reconstructs `signed_part = dest_hash + source_hash + packed_payload + message_hash` and calls `identity_verify`. Matches the LXMF spec verified in Phase 4 review. **Correct.**

### Unknown sender handling (lines 222-225)

If the sender isn't in the peer table, `signature_valid = false` and the message is still delivered to the callback. The callback can decide policy (display with warning, reject, etc.). **Correct design** — transport layer annotates, doesn't reject.

### Spoofing resistance

An attacker spoofing `source_hash` (setting it to another peer's lxmf_dest_hash) would be caught by signature verification — the attacker lacks the victim's ed25519 private key. **Robust.**

---

## 6. lxmf_transport_poll() Receive Flow — CORRECT with one null-guard gap

### Packet dispatch (lines 167-260)

```
switch(pkt.get_packet_type()):
  PKT_ANNOUNCE     → announce_process()
  PKT_DATA         → dest check → decrypt → parse → dedup → verify → callback
  PKT_PROOF        → log (not implemented)
  PKT_LINKREQUEST  → log (not implementing)
  default          → log unknown type
```

All four `PacketType` enum values are handled. Default catches any future additions. **No unmatched cases.**

### LXMF DATA flow (lines 178-230)

```
1. Check dest_hash matches our lxmf.delivery  ✓ (line 179)
2. Decrypt with our identity                   ✓ (line 184)
3. Bounds check                                ✓ (line 194)
4. Prepend our dest_hash                       ✓ (line 198)
5. Parse LXMF                                  ✓ (line 203)
6. Dedup check                                 ✓ (line 209)
7. Sender lookup by source_hash                ✓ (line 216)
8. Signature verification (if sender known)    ✓ (line 218)
9. Deliver to callback                         ✓ (line 228)
```

All steps present, in correct order. **Correct.**

### RSSI/SNR capture (lines 149-150)

Captured immediately after `radio_receive`, before any processing. This is correct — `radio_rssi()`/`radio_snr()` return values from the most recent reception, which could be overwritten by another packet during processing. **Good practice.**

### **Missing null guard on s_lxmf_dest (line 179)**

```cpp
if (memcmp(pkt.dest_hash, s_lxmf_dest->hash, DEST_HASH_SIZE) == 0) {
```

If `lxmf_transport_poll()` is called before `lxmf_transport_init()`, `s_lxmf_dest` is nullptr → crash. Compare with the `s_announce_dest` check at line 231 which HAS a null guard:

```cpp
} else if (s_announce_dest && memcmp(pkt.dest_hash, s_announce_dest->hash, ...)) {
```

**Inconsistent.** Should be:
```cpp
if (s_lxmf_dest && memcmp(pkt.dest_hash, s_lxmf_dest->hash, DEST_HASH_SIZE) == 0) {
```

**Severity: LOW** — `setup()` ensures init before first poll. But defensive code is good firmware practice.

### Legacy DATA path (lines 231-242)

Decrypts and prints to Serial. Does NOT deliver through the callback. **Correct** — legacy DATA isn't LXMF-formatted.

### Static pointer lifetime (lines 15-17, 45-47)

`s_identity`, `s_announce_dest`, `s_lxmf_dest` store pointers to caller-owned objects. In main_test.cpp these are file-scope statics (lines 35-37) that live for the entire program. Post-test re-initialization at lines 2458-2470 correctly restores pointers after tests. **No lifetime issue.**

---

## 7. Test Coverage

### Phase 4b test suite (4 tests)

| Test | What it covers | Verdict |
|------|---------------|---------|
| `test_lxmf_send_receive_roundtrip` | Build LXMF → encrypt → decrypt → prepend dest → parse → verify sig → check all fields | Excellent — full pipeline |
| `test_lxmf_dedup` | Init clears state, first msg not dup, record, same hash is dup, different hash not dup | Good — basic dedup |
| `test_peer_lookup_by_lxmf_dest_fn` | Store peer with lxmf_dest → lookup succeeds → wrong dest returns nullptr → regular lookup works | Good |
| `test_lxmf_receive_craft` | Second cycle: build (no custom fields) → encrypt → decrypt → reconstruct → parse → verify hash + sig | Good — exercises empty-fields path |

### Acceptance criteria assessment

The Phase 4 review stated Phase 4b scope: "integration with transport_send_data() and transport_poll() dispatch"

| Criterion | Status |
|-----------|--------|
| Send LXMF over encrypted transport | **Partially met** — encrypt/decrypt roundtrip tested, but `lxmf_send` itself is not called (requires radio mock) |
| Receive LXMF from transport | **Partially met** — manual reconstruction tested, but `lxmf_transport_poll` dispatch has no automated test |
| Signature verification on receive | **Met** — both tests verify with correct sender key |
| Dedup | **Met** — basic test passes |
| Peer LXMF dest lookup | **Met** |
| Sender identification via source_hash | **Met** — roundtrip tests verify source_hash matches |

### Missing tests (ordered by priority)

1. **No near-limit message size test (HIGH)** — Build an LXMF with ~280 bytes content, encrypt, verify. Would surface the `encrypted[]` buffer overflow (section 1b) and validate the fix. **Must-add with the buffer overflow fix.**

2. **No lxmf_transport_poll integration test (MEDIUM)** — The dispatch loop is the primary new code in Phase 4b but has no automated coverage. The wiring (receive → dest match → decrypt → dedup → verify → callback) is only exercised via live radio.

3. **No dedup wraparound test (MEDIUM)** — Insert 65+ hashes, verify the first is evicted. Ring buffer's key property untested.

4. **No send-to-legacy-peer test (LOW)** — Store peer with nullptr lxmf_dest, attempt lxmf_send, verify it returns false (exercises lines 76-80).

5. **No unknown-sender receive test (LOW)** — Verify message from unknown sender delivered with `signature_valid = false`.

6. **No legacy DATA fallback test (LOW)** — Path at lines 231-242 untested.

7. **No decryption failure test (LOW)** — Corrupted encrypted packet should fail gracefully.

---

## 8. Additional Findings

### 8a. custom_type length off-by-one (main_test.cpp:2504, 2578) — BUG

```cpp
// Line 2504 (keyboard 's' send):
(const uint8_t*)"traildrop/waypoint", 19,  // BUG: should be 18

// Line 2578 (auto-send):
(const uint8_t*)"traildrop/waypoint", 19,  // BUG: should be 18
```

`"traildrop/waypoint"` is 18 characters. Length 19 includes the C null terminator, so the field is sent as `b"traildrop/waypoint\x00"` on the wire. The automated test at line 2039 correctly uses 18.

**Severity: LOW.** Cosmetic, but Python receivers would see a trailing null byte in the custom_type field.

### 8b. Incomplete Identity init in test_lxmf_receive_craft (main_test.cpp:2186-2188)

```cpp
crypto::Identity receiver_pub;
memcpy(receiver_pub.x25519_public, receiver.x25519_public, 32);
memcpy(receiver_pub.hash, receiver.hash, 16);
receiver_pub.valid = true;
// Missing: ed25519_public not copied, private keys not zeroed
```

`identity_encrypt` only needs `x25519_public` and `hash` for ECDH + HKDF. So this works. But it's inconsistent with lxmf_send (lines 100-106) which initializes all 6 fields. The uninitialized `ed25519_public` and private key fields contain stack garbage. Not a functional bug (encrypt doesn't use them), but unclean.

### 8c. write_bin(nullptr, 0) — technically UB

When `lxmf_send` passes `custom_data=nullptr, custom_data_len=0`, `lxmf_build` calls `enc.write_bin(nullptr, 0)` → `write_bytes(nullptr, 0)` → `memcpy(buf, nullptr, 0)`. Per C/C++ spec, `memcpy` with null pointer is UB even with size 0. Most implementations handle it, but sanitizers will flag it.

**Severity: LOW.** Fix: guard with `if (len > 0)` in `write_bytes`.

### 8d. Auto-send ignores lxmf_send return value (main_test.cpp:2574)

```cpp
msg::lxmf_send(  // return value ignored
    device_identity, device_lxmf_destination.hash,
    peer->dest_hash, ...);
```

The manual send at line 2500 correctly checks the return. **Minor**: should check and log failure.

### 8e. s_rx_count counts all packets (lxmf_transport.cpp:162)

`s_rx_count` increments for every deserialized packet (announces, legacy DATA, unknown types), not just LXMF messages. The API function `lxmf_rx_count()` is misleading. Consider renaming to `transport_rx_count()` or splitting into LXMF-specific and total counts.

### 8f. peer_lookup_by_lxmf_dest matches zeroed entries

Peers stored without an LXMF dest (nullptr default) have all-zero `lxmf_dest_hash`. If a received message has `source_hash` = all zeros, `peer_lookup_by_lxmf_dest` would match these peers, returning the wrong peer's ed25519 key. Signature verification would then fail (correct outcome), so this isn't exploitable. But logically imprecise.

**Optional fix**: Skip peers with zeroed `lxmf_dest_hash` in the lookup:
```cpp
uint8_t zero[DEST_HASH_SIZE] = {0};
if (memcmp(peer_table[i].lxmf_dest_hash, zero, DEST_HASH_SIZE) == 0) continue;
```

### 8g. Phase 4a.5 should-fix items — ADDRESSED

Both items from my previous review were fixed in commit 86b0557:
1. Bounds check on `app_data_len` in `announce_process` — **FIXED** (announce.cpp:201).
2. `0xdc` (array16) detection in format check — **FIXED** (announce.cpp:217).

---

## 9. Summary — Verdict

### Overall: PASS with one must-fix

The implementation correctly implements LXMF opportunistic delivery over encrypted LoRa. The architecture is clean: sender encrypts LXMF plaintext to the receiver's lxmf.delivery destination, addresses the RNS DATA packet to that same destination, receiver matches on dest_hash, decrypts, prepends dest_hash for full LXMF reconstruction, parses, looks up sender by LXMF source_hash, and verifies the Ed25519 signature with the sender's key. The design matches the Python LXMF source faithfully.

### Must-fix (before Phase 4c)

1. **encrypted[] buffer overflow in lxmf_send** (section 1b) — Add pre-check: `if (lxmf_len > 383) return false;` after lxmf_build, or widen the check in lxmf_build itself. Current code overflows the 500-byte stack buffer for messages with LXMF plaintext > 415 bytes. With max title (64) + max content (280), the overflow is 60 bytes. This is a memory corruption bug that will trigger as message sizes grow.

### Should-fix

2. **Null guard on s_lxmf_dest** (section 6) — Add `s_lxmf_dest &&` before memcmp at line 179.
3. **custom_type length 19 → 18** (section 8a) — Two instances in loop() at lines 2504 and 2578.
4. **Add near-limit size test** (section 7) — Validates the buffer overflow fix.
5. **Add dedup wraparound test** (section 7) — Ring buffer's key property untested.

### Nice-to-have

6. Add lxmf_transport_poll integration test.
7. Fix incomplete Identity init in test_lxmf_receive_craft.
8. Check lxmf_send return value in auto-send path.
9. Guard write_bin(nullptr, 0) against UB.
10. Add send-to-legacy-peer negative test.

---

*Reviewed by Cal (firmware reviewer agent), 2026-03-01*
