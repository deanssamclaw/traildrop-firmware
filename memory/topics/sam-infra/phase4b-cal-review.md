# Phase 4b Cal Review: LXMF Over Transport

Reviewed: 2026-03-01
Commit: 503c940
Files reviewed: `src/msg/lxmf_transport.h`, `src/msg/lxmf_transport.cpp`, `src/net/peer.h`, `src/net/peer.cpp`, `src/main_test.cpp`
Cross-referenced: Phase 4 Cal review, Phase 4a.5 Cal review, `src/msg/lxmf.h`, `src/msg/lxmf.cpp`, `include/config.h`

---

## 1. Buffer Overflows

### 1a. lxmf_plain[500] in lxmf_send (lxmf_transport.cpp:83) — SAFE

`lxmf_build` has an internal sanity check at lxmf.cpp:71: `if (total > 500) return false;`. The caller's buffer is exactly 500 bytes, matching the check. No overflow possible.

**Note**: `lxmf_build` does NOT accept a buffer capacity parameter — it uses a hardcoded 500-byte check. If the constant and the caller's buffer ever drift apart, silent overflow could occur. Document the coupling.

### 1b. encrypted[RNS_MTU] in lxmf_send (lxmf_transport.cpp:108) — **BUG: POTENTIAL OVERFLOW (MEDIUM)**

**This is the most serious issue in Phase 4b.**

`encrypted` is declared as `uint8_t encrypted[RNS_MTU]` = 500 bytes. `identity_encrypt` adds:
- 32 bytes ephemeral X25519 public key
- 16 bytes IV
- PKCS7-padded ciphertext (rounds up to next 16-byte boundary, always adds at least 1 byte)
- 32 bytes HMAC

Total overhead: 80 bytes fixed + 1–16 bytes padding = 81–96 bytes.

**Overflow calculation:**

| lxmf_len (input) | AES-CBC output | Encrypted total | Fits in 500? |
|---|---|---|---|
| 200 | 208 | 288 | YES |
| 300 | 304 | 384 | YES |
| 400 | 416 | 496 | YES |
| 416 | 432 | 512 | **NO — 12 bytes over** |
| 460 | 464 | 544 | **NO — 44 bytes over** |
| 500 | 512 | 592 | **NO — 92 bytes over** |

`lxmf_build` can output up to 500 bytes. Encryption of 500 bytes needs 592 bytes — a **92-byte overflow** of the `encrypted[500]` buffer.

**Practical impact today: LOW.** Waypoint messages are ~200 bytes. But the `LXMF_MAX_CONTENT = 280` and `LXMF_MAX_TITLE = 64` constants in lxmf.h allow content large enough to produce ~460-byte lxmf_build output, which would overflow.

**Additional failure mode**: Even without the buffer overflow, `identity_encrypt` output exceeding 481 bytes (H1 max payload) would fail at `packet_serialize`. But the buffer overflow at `identity_encrypt` happens first, corrupting memory before any transport check.

**Recommendation (must-fix):**
```cpp
// Option A (preferred): Add pre-check in lxmf_send after lxmf_build
if (lxmf_len > 383) {  // RNS ENCRYPTED_MDU from Python spec
    Serial.println("[LXMF-TX] ERROR: Message too large for encrypted transport");
    return false;
}

// Option B: Change lxmf_build sanity check (lxmf.cpp:71)
if (total > 383) return false;  // Match RNS ENCRYPTED_MDU, not raw MTU
```

Option A is preferred — it keeps `lxmf_build` general-purpose and puts the transport-specific limit in the transport layer.

**Also note**: `identity_encrypt` does not accept an output buffer size parameter. It trusts the caller to provide a large enough buffer. This is a latent API hazard. Consider adding `max_out_len` in a future refactor.

### 1c. pkt.payload memcpy (lxmf_transport.cpp:123) — SAME BUG

```cpp
memcpy(pkt.payload, encrypted, enc_len);
```

`pkt.payload` is `uint8_t[RNS_MTU]` (500 bytes). If `enc_len` exceeds 500 (per the encryption overflow above), this is a second overflow on the same path. Fixing the pre-check (1b) prevents both.

### 1d. full_lxmf[600] in lxmf_transport_poll (lxmf_transport.cpp:193) — SAFE

Bounded by the explicit check at line 194: `if (16 + dec_len > sizeof(full_lxmf))`. Since `dec_len` comes from decrypting a radio packet payload (max ~481 bytes) minus encryption overhead (~80 bytes), `dec_len` is at most ~400 bytes. `16 + 400 = 416 < 600`. **No issue.**

### 1e. decrypted[RNS_MTU] in lxmf_transport_poll (lines 181, 234) — SAFE

Decryption always shrinks data (removes ephemeral key + IV + HMAC + padding). Input comes from `pkt.payload` bounded by `RNS_MTU`. Output is always smaller than input. **No issue.**

### 1f. rx_buf[RNS_MTU] in lxmf_transport_poll (line 143) — SAFE

Passed to `hal::radio_receive` with `sizeof(rx_buf)` as the limit. **No issue.**

---

## 2. Destination Routing — CORRECT

### Send path (lxmf_transport.cpp:121)

```cpp
memcpy(pkt.dest_hash, peer->lxmf_dest_hash, DEST_HASH_SIZE);
```

**CORRECT.** The DATA packet is addressed to `peer->lxmf_dest_hash` (lxmf.delivery destination), NOT `peer->dest_hash` (traildrop.waypoint announce destination). This matches Python LXMF opportunistic delivery (LXMessage.py:629):
```python
RNS.Packet(delivery_dest, self.packed[DESTINATION_LENGTH:])
```

### LXMF-level dest_hash (lxmf_transport.cpp:88)

```cpp
lxmf_build(our_identity, our_lxmf_dest, peer->lxmf_dest_hash, ...)
```

The `dest_hash` passed to `lxmf_build` is the peer's lxmf.delivery hash, used in LXMF hash computation (`hashed_part = dest_hash + source_hash + packed_payload`). **Correct.**

### Zero-check guard (lxmf_transport.cpp:76-79)

```cpp
uint8_t zero[DEST_HASH_SIZE] = {0};
if (memcmp(peer->lxmf_dest_hash, zero, DEST_HASH_SIZE) == 0) {
    return false;
}
```

**CORRECT.** Guards against sending to a legacy peer that was stored before Phase 4a.5 (lxmf_dest_hash would be zeroed).

### Receive path dispatch (lxmf_transport.cpp:179-245)

```cpp
if (memcmp(pkt.dest_hash, s_lxmf_dest->hash, DEST_HASH_SIZE) == 0) {
    // LXMF DATA — decrypt, parse, verify, deliver
} else if (s_announce_dest && memcmp(pkt.dest_hash, s_announce_dest->hash, ...) == 0) {
    // Legacy DATA to traildrop.waypoint — decrypt and log
} else {
    // Not for us
}
```

Priority order correct: LXMF first, legacy fallback second. **Correct.**

**Verdict: All destination routing is correct throughout both send and receive paths.**

---

## 3. Signature Verification — CORRECT

### Sender lookup (lxmf_transport.cpp:216)

```cpp
const net::Peer* sender = net::peer_lookup_by_lxmf_dest(msg.source_hash);
```

The LXMF `source_hash` is the sender's lxmf.delivery destination hash. `peer_lookup_by_lxmf_dest` scans the peer table for a matching `lxmf_dest_hash`. If found, the peer's `ed25519_public` key is used for verification.

### Verification chain

```
msg.source_hash → peer_lookup_by_lxmf_dest → peer.ed25519_public → lxmf_verify → identity_verify
```

`lxmf_verify` (lxmf.cpp:174-197) reconstructs `signed_part = dest_hash + source_hash + packed_payload + message_hash` and calls `identity_verify`. This matches the LXMF spec (confirmed Phase 4 review, section 1). **Correct.**

### Unknown sender handling (lxmf_transport.cpp:222-225)

If `peer_lookup_by_lxmf_dest` returns nullptr, the message is delivered with `signature_valid = false`. The callback receives the message and can check this flag. **Correct design** — the transport layer doesn't reject messages, it annotates them.

### Spoofing resistance

A malicious node could set `source_hash` to another peer's lxmf.delivery hash. The Ed25519 signature verification would fail (attacker lacks the private key), so `signature_valid` would be false. The callback-based policy is correct.

---

## 4. Dedup Ring Buffer — CORRECT

### Structure (lxmf_transport.cpp:22-24)

```cpp
static const size_t DEDUP_BUFFER_SIZE = 64;
static uint8_t dedup_hashes[DEDUP_BUFFER_SIZE][32];  // 2048 bytes total
static size_t dedup_index = 0;
```

### Linear scan (lxmf_transport.cpp:26-33) — CORRECT

Scans all 64 slots with `memcmp(..., 32)`. O(64) per check = ~2KB of comparisons. Negligible on ESP32 at 240MHz. **No performance concern.**

### Wraparound (lxmf_transport.cpp:37) — CORRECT

```cpp
dedup_index = (dedup_index + 1) % DEDUP_BUFFER_SIZE;
```

Standard ring buffer modulo. Oldest entries overwritten. **Correct.**

### Zero-initialized slots

After init, all 64 slots are zero. A real SHA-256 hash being all-zero has probability 1/2^256. **Negligible risk.**

### Self-dedup on send (lxmf_transport.cpp:132)

After sending, records our own message hash to prevent processing reflected packets. **Good design.**

### Dedup timing

The dedup check happens AFTER decryption and parsing (line 209). This is necessarily late — the message hash depends on plaintext content. Wasted decrypt/parse work for duplicates, but at LoRa message rates this is fine.

---

## 5. Static State Management — SAFE with one null-guard gap

### Pointer storage (lxmf_transport.cpp:15-17)

```cpp
static const crypto::Identity* s_identity = nullptr;
static const net::Destination* s_announce_dest = nullptr;
static const net::Destination* s_lxmf_dest = nullptr;
```

Raw pointers to caller-owned objects. In production, these point to `device_identity`, `device_destination`, `device_lxmf_destination` — file-scope statics in main_test.cpp that live for the entire program. **No lifetime issue.**

### Post-test re-initialization (main_test.cpp:2458-2470)

Correctly resets pointers to long-lived globals after tests may have set them to stack-local objects. **Correct.**

### **BUG (LOW): Missing null guard on s_lxmf_dest**

At lxmf_transport.cpp:179:
```cpp
if (memcmp(pkt.dest_hash, s_lxmf_dest->hash, DEST_HASH_SIZE) == 0) {
```

If `lxmf_transport_poll` is called before `lxmf_transport_init`, `s_lxmf_dest` is nullptr → crash. Compare with the `s_announce_dest` check at line 231 which has a null guard:
```cpp
if (s_announce_dest && memcmp(...)) {
```

**Inconsistent.** The LXMF dest check should also have a null guard.

**Fix**:
```cpp
if (s_lxmf_dest && memcmp(pkt.dest_hash, s_lxmf_dest->hash, DEST_HASH_SIZE) == 0) {
```

**Severity: LOW** — `setup()` ensures init before first poll. But defensive code is good firmware practice.

---

## 6. Test Coverage

### Phase 4b test suite (4 tests)

| Test | What it covers | Verdict |
|------|---------------|---------|
| `test_lxmf_send_receive_roundtrip` | Build LXMF → encrypt → decrypt → reconstruct → parse → verify sig → check fields | Excellent — full pipeline |
| `test_lxmf_dedup` | Init clears state, first msg not dup, same hash is dup, different hash not dup | Good |
| `test_peer_lookup_by_lxmf_dest_fn` | Store peer with lxmf_dest, lookup succeeds, wrong dest returns nullptr, regular lookup works | Good |
| `test_lxmf_receive_craft` | Second full cycle: build → encrypt → decrypt → reconstruct → parse → verify hash + sig | Good |

### Missing tests (ordered by priority)

1. **No integration test for lxmf_transport_poll.** All tests call lxmf_build/encrypt/decrypt/parse directly. The dispatch loop — which IS Phase 4b — has no automated test. The wiring between packet receive → dest match → decrypt → parse → dedup → sender lookup → callback is only exercised by live radio testing. **Should-add.**

2. **No dedup wraparound test.** Insert 65+ hashes, verify the first is evicted and no longer detected as duplicate. The ring buffer's key correctness property is untested. **Should-add.**

3. **No near-limit message size test.** Build an LXMF message with ~280 bytes content, encrypt, and verify it either succeeds or fails gracefully. This would surface the encrypted[] buffer overflow (section 1b). **Should-add (validates the fix).**

4. **No send-to-legacy-peer test.** Store a peer with nullptr lxmf_dest, attempt lxmf_send, verify it returns false. Lines 76-79 handle this but it's untested. **Should-add.**

5. **No test for unknown sender on receive.** Message from a peer not in the table should be delivered with `signature_valid = false`. **Nice-to-have.**

6. **No test for legacy DATA fallback.** The path at line 231-242 is untested. **Nice-to-have.**

7. **No decryption failure test.** Corrupted encrypted packet should fail gracefully. **Nice-to-have.**

8. **No callback mechanism test.** `lxmf_set_receive_callback` and actual callback invocation untested in isolation. **Nice-to-have.**

**Severity: MEDIUM overall.** The roundtrip tests provide strong confidence in the core crypto+LXMF pipeline. But the transport_poll dispatch — the primary new code in Phase 4b — lacks automated coverage.

---

## 7. Additional Observations

### 7a. Off-by-one: custom_type length (main_test.cpp:2504, 2578)

```cpp
(const uint8_t*)"traildrop/waypoint", 19,
```

`"traildrop/waypoint"` is 18 characters. Length 19 includes the null terminator, so the field is sent as `b"traildrop/waypoint\x00"` (19 bytes) on the wire. The automated test at line 2039 correctly uses 18. **Bug: should be 18 at lines 2504 and 2578.** Affects live wire-test messages only.

### 7b. Incomplete Identity init in test_lxmf_receive_craft (main_test.cpp:2186-2188)

```cpp
crypto::Identity receiver_pub;
memcpy(receiver_pub.x25519_public, receiver.x25519_public, 32);
memcpy(receiver_pub.hash, receiver.hash, 16);
receiver_pub.valid = true;
```

Missing: `ed25519_public` not copied, private keys not zeroed. `identity_encrypt` only needs `x25519_public` for ECDH, so this works today. But the incomplete initialization is inconsistent with lxmf_send (lines 100-106) which properly initializes all fields. **Minor.**

### 7c. Peer Identity reconstruction in lxmf_send (lxmf_transport.cpp:100-106)

The send path reconstructs a partial `Identity` struct for encryption, with private keys zeroed. This is correct and defensive. Consider adding an `Identity::from_public()` factory in a future refactor.

### 7d. Auto-send ignores lxmf_send return value (main_test.cpp:2574)

The auto-send path at line 2574 ignores the return value of `lxmf_send`. The manual send at line 2500 correctly checks it. **Minor: should check and log failure.**

### 7e. s_rx_count counts all packets (lxmf_transport.cpp:162)

`s_rx_count` increments for every deserialized packet, not just LXMF messages. Includes announces, legacy DATA, unknown types. The function name `lxmf_rx_count()` is slightly misleading. **Consider renaming or splitting.**

### 7f. Phase 4a.5 should-fix items

Both items from my previous review were fixed in commit 86b0557:
1. Bounds check on `app_data_len` in `announce_process` — **FIXED.**
2. `0xdc` (array16) detection in format check — **FIXED.**

---

## 8. Summary — Verdict

### Overall: PASS with one must-fix

The implementation correctly implements LXMF opportunistic delivery over encrypted LoRa. The architecture is clean: sender encrypts LXMF plaintext to the receiver's lxmf.delivery destination, addresses the RNS DATA packet to that destination, receiver matches on dest_hash, decrypts, prepends dest_hash for LXMF reconstruction, parses, looks up sender by lxmf source_hash, and verifies the Ed25519 signature. The design matches the Python LXMF source faithfully.

### Must-fix (before Phase 4c)

1. **encrypted[] buffer overflow in lxmf_send** (section 1b) — Add a pre-check: `if (lxmf_len > 383) return false;` after lxmf_build. Current code can overflow the 500-byte buffer for messages with content >~280 bytes. Low practical risk with today's small waypoint messages, but this is a memory corruption bug.

### Should-fix

2. **Null guard on s_lxmf_dest** (section 5) — Add `s_lxmf_dest &&` before the memcmp at line 179.
3. **custom_type length 19 → 18** (section 7a) — Two instances in loop() at lines 2504 and 2578.
4. **Add lxmf_transport_poll integration test** (section 6, missing #1) — The dispatch loop has no automated coverage.
5. **Add dedup wraparound test** (section 6, missing #2) — Ring buffer's key property untested.
6. **Add near-limit size test** (section 6, missing #3) — Validates the buffer overflow fix.

### Nice-to-have

7. Fix incomplete Identity init in test_lxmf_receive_craft (section 7b).
8. Check lxmf_send return value in auto-send path (section 7d).
9. Add send-to-legacy-peer negative test (section 6, missing #4).
10. Add unknown-sender receive test (section 6, missing #5).

---

*Reviewed by Cal (firmware reviewer agent), 2026-03-01*
