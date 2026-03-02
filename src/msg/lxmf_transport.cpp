#include "lxmf_transport.h"
#include "lxmf.h"
#include "net/packet.h"
#include "net/announce.h"
#include "net/peer.h"
#include "net/transport.h"
#include "hal/radio.h"
#include "crypto/identity.h"
#include <Arduino.h>
#include <cstring>

namespace msg {

// State
static const crypto::Identity* s_identity = nullptr;
static const net::Destination* s_announce_dest = nullptr;
static const net::Destination* s_lxmf_dest = nullptr;
static lxmf_receive_callback_t s_receive_cb = nullptr;
static uint32_t s_rx_count = 0;

// Dedup ring buffer
static const size_t DEDUP_BUFFER_SIZE = 64;
static uint8_t dedup_hashes[DEDUP_BUFFER_SIZE][32];
static size_t dedup_index = 0;

bool lxmf_is_duplicate(const uint8_t hash[32]) {
    for (size_t i = 0; i < DEDUP_BUFFER_SIZE; i++) {
        if (memcmp(dedup_hashes[i], hash, 32) == 0) {
            return true;
        }
    }
    return false;
}

void lxmf_record_message(const uint8_t hash[32]) {
    memcpy(dedup_hashes[dedup_index], hash, 32);
    dedup_index = (dedup_index + 1) % DEDUP_BUFFER_SIZE;
}

bool lxmf_transport_init(
    const crypto::Identity& id,
    const net::Destination& announce_dest,
    const net::Destination& lxmf_dest)
{
    s_identity = &id;
    s_announce_dest = &announce_dest;
    s_lxmf_dest = &lxmf_dest;
    s_rx_count = 0;
    s_receive_cb = nullptr;

    // Clear dedup buffer
    memset(dedup_hashes, 0, sizeof(dedup_hashes));
    dedup_index = 0;

    return true;
}

bool lxmf_send(
    const crypto::Identity& our_identity,
    const uint8_t our_lxmf_dest[16],
    const uint8_t peer_announce_dest[16],
    const char* title,
    const char* content,
    const uint8_t* custom_type, size_t custom_type_len,
    const uint8_t* custom_data, size_t custom_data_len,
    uint8_t message_hash_out[32])
{
    // Step 1: Look up peer by announce dest
    const net::Peer* peer = net::peer_lookup(peer_announce_dest);
    if (!peer) {
        Serial.println("[LXMF-TX] ERROR: Peer not found");
        return false;
    }

    // Check peer has LXMF destination
    uint8_t zero[DEST_HASH_SIZE] = {0};
    if (memcmp(peer->lxmf_dest_hash, zero, DEST_HASH_SIZE) == 0) {
        Serial.println("[LXMF-TX] ERROR: Peer has no LXMF destination");
        return false;
    }

    // Step 2: Build LXMF plaintext
    uint8_t lxmf_plain[500];
    size_t lxmf_len = 0;
    double timestamp = millis() / 1000.0;

    if (!lxmf_build(
            our_identity, our_lxmf_dest, peer->lxmf_dest_hash,
            timestamp,
            (const uint8_t*)title, strlen(title),
            (const uint8_t*)content, strlen(content),
            custom_type, custom_type_len,
            custom_data, custom_data_len,
            lxmf_plain, &lxmf_len, message_hash_out)) {
        Serial.println("[LXMF-TX] ERROR: LXMF build failed");
        return false;
    }

    // Pre-check: LXMF plaintext must fit in encrypted MTU
    // identity_encrypt adds ~81-96 bytes overhead (ephemeral key + IV + padding + HMAC)
    // RNS ENCRYPTED_MDU = MTU - overhead ≈ 383 bytes
    if (lxmf_len > 383) {
        Serial.printf("[LXMF-TX] ERROR: Message too large for encrypted transport (%d > 383)\n", (int)lxmf_len);
        return false;
    }

    // Step 3: Encrypt for peer
    crypto::Identity peer_id;
    memcpy(peer_id.x25519_public, peer->x25519_public, 32);
    memcpy(peer_id.ed25519_public, peer->ed25519_public, 32);
    memcpy(peer_id.hash, peer->identity_hash, DEST_HASH_SIZE);
    memset(peer_id.x25519_private, 0, 32);
    memset(peer_id.ed25519_private, 0, 32);
    peer_id.valid = true;

    uint8_t encrypted[RNS_MTU];
    size_t enc_len = 0;

    if (!crypto::identity_encrypt(peer_id, lxmf_plain, lxmf_len, encrypted, &enc_len)) {
        Serial.println("[LXMF-TX] ERROR: Encryption failed");
        return false;
    }

    // Step 4: Build DATA packet — dest_hash = peer's lxmf_dest_hash
    Packet pkt;
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_DATA);
    pkt.hops = 0;
    pkt.has_transport = false;
    memcpy(pkt.dest_hash, peer->lxmf_dest_hash, DEST_HASH_SIZE);
    pkt.context = CTX_NONE;
    memcpy(pkt.payload, encrypted, enc_len);
    pkt.payload_len = enc_len;

    // Step 5: Transmit via transport_send (handles serialization + radio)
    bool sent = net::transport_send(pkt);
    if (sent) {
        Serial.printf("[LXMF-TX] Sent LXMF message (%d bytes LXMF, %d bytes encrypted, ~%d bytes on wire)\n",
                      (int)lxmf_len, (int)enc_len, (int)(enc_len + 18));
        // Record in dedup to avoid processing our own reflected packets
        lxmf_record_message(message_hash_out);
    }

    return sent;
}

void lxmf_set_receive_callback(lxmf_receive_callback_t cb) {
    s_receive_cb = cb;
}

void lxmf_transport_poll() {
    uint8_t rx_buf[RNS_MTU];
    int rx_len = hal::radio_receive(rx_buf, sizeof(rx_buf));

    if (rx_len <= 0) return;

    // Capture RSSI/SNR immediately after receive
    int rssi = (int)hal::radio_rssi();
    float snr = hal::radio_snr();

    Serial.print("[RX_HEX] ");
    for (int i = 0; i < rx_len; i++) Serial.printf("%02x", rx_buf[i]);
    Serial.println();

    Packet pkt;
    if (!net::packet_deserialize(rx_buf, rx_len, pkt)) {
        Serial.println("[RX] ERROR: Failed to deserialize packet");
        return;
    }

    s_rx_count++;

    Serial.printf("[RX] %d bytes, type=%d, RSSI=%d SNR=%.1f\n",
                  rx_len, pkt.get_packet_type(), rssi, snr);

    switch (pkt.get_packet_type()) {
        case PKT_ANNOUNCE: {
            if (net::announce_process(pkt)) {
                Serial.println("[RX] Announce processed successfully");
            } else {
                Serial.println("[RX] Announce processing failed");
            }
            break;
        }

        case PKT_DATA: {
            // Check if addressed to our LXMF destination
            if (s_lxmf_dest && memcmp(pkt.dest_hash, s_lxmf_dest->hash, DEST_HASH_SIZE) == 0) {
                // Decrypt with our identity
                uint8_t decrypted[RNS_MTU];
                size_t dec_len = 0;

                if (!crypto::identity_decrypt(*s_identity, pkt.payload, pkt.payload_len,
                                              decrypted, &dec_len)) {
                    Serial.println("[LXMF-RX] Decryption failed");
                    break;
                }

                Serial.printf("[LXMF-RX] Decrypted: %d bytes\n", (int)dec_len);

                // Reconstruct full LXMF: prepend our lxmf dest_hash
                uint8_t full_lxmf[600];
                if (16 + dec_len > sizeof(full_lxmf)) {
                    Serial.println("[LXMF-RX] Message too large");
                    break;
                }
                memcpy(full_lxmf, s_lxmf_dest->hash, 16);
                memcpy(full_lxmf + 16, decrypted, dec_len);

                // Parse LXMF message
                LXMessage msg;
                if (!lxmf_parse(full_lxmf, 16 + dec_len, msg)) {
                    Serial.println("[LXMF-RX] Parse failed");
                    break;
                }

                // Dedup check
                if (lxmf_is_duplicate(msg.message_hash)) {
                    Serial.println("[LXMF-RX] Duplicate message, ignoring");
                    break;
                }
                lxmf_record_message(msg.message_hash);

                // Look up sender by source_hash (their lxmf.delivery dest_hash)
                const net::Peer* sender = net::peer_lookup_by_lxmf_dest(msg.source_hash);
                if (sender) {
                    msg.signature_valid = lxmf_verify(msg, sender->ed25519_public);
                    if (!msg.signature_valid) {
                        Serial.println("[LXMF-RX] WARNING: Signature verification failed");
                    }
                } else {
                    Serial.println("[LXMF-RX] WARNING: Sender not in peer table, cannot verify");
                    msg.signature_valid = false;
                }

                // Deliver to callback
                if (s_receive_cb) {
                    s_receive_cb(msg, rssi, snr);
                }
            } else if (s_announce_dest &&
                       memcmp(pkt.dest_hash, s_announce_dest->hash, DEST_HASH_SIZE) == 0) {
                // Legacy DATA to our announce/waypoint dest
                uint8_t decrypted[RNS_MTU];
                size_t dec_len = 0;
                if (crypto::identity_decrypt(*s_identity, pkt.payload, pkt.payload_len,
                                             decrypted, &dec_len)) {
                    Serial.printf("[RX] Legacy DATA decrypted: %d bytes\n", (int)dec_len);
                    Serial.printf("[RX] Content: %.*s\n", (int)dec_len, (const char*)decrypted);
                } else {
                    Serial.println("[RX] Legacy DATA decryption failed");
                }
            } else {
                Serial.println("[RX] DATA not for us, ignoring");
            }
            break;
        }

        case PKT_PROOF:
            Serial.println("[RX] PROOF packet received (not implemented)");
            break;

        case PKT_LINKREQUEST:
            Serial.println("[RX] LINKREQUEST packet received (not implementing links)");
            break;

        default:
            Serial.printf("[RX] Unknown packet type: %d\n", pkt.get_packet_type());
            break;
    }
}

uint32_t lxmf_rx_count() {
    return s_rx_count;
}

} // namespace msg
