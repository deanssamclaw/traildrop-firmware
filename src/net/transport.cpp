#include "transport.h"
#include "net/announce.h"
#include "net/peer.h"
#include "hal/radio.h"
#include "crypto/identity.h"
#include "crypto/encrypt.h"
#include <Arduino.h>
#include <RadioLib.h>
#include <cstring>

namespace net {

// State variables (file-scope static)
static const crypto::Identity* s_identity = nullptr;
static const net::Destination* s_destination = nullptr;
static uint32_t s_last_announce = 0;
static uint32_t s_rx_count = 0;
static uint32_t s_tx_count = 0;
static net::data_callback_t s_data_callback = nullptr;

bool transport_init(const crypto::Identity& id, const Destination& dest) {
    s_identity = &id;
    s_destination = &dest;
    s_last_announce = 0;  // Trigger immediate first announce
    s_rx_count = 0;
    s_tx_count = 0;
    return true;
}

bool transport_send(const Packet& pkt) {
    uint8_t buf[RNS_MTU];
    int len = packet_serialize(pkt, buf, RNS_MTU);
    
    if (len < 0) {
        Serial.println("[TX] ERROR: Failed to serialize packet");
        return false;
    }
    
    int result = hal::radio_send(buf, len);
    
    if (result == RADIOLIB_ERR_NONE) {
        s_tx_count++;
        Serial.printf("[TX] %d bytes, type=%d\n", len, pkt.get_packet_type());
        return true;
    } else {
        Serial.printf("[TX] ERROR: radio_send failed with code %d\n", result);
        return false;
    }
}

bool transport_send_data(const uint8_t peer_dest_hash[DEST_HASH_SIZE],
                         const uint8_t* data, size_t data_len) {
    // Look up peer
    const Peer* peer = peer_lookup(peer_dest_hash);
    if (peer == nullptr) {
        Serial.println("[TX] ERROR: Peer not found");
        return false;
    }
    
    // Build a temporary Identity for the peer with just their public keys
    // identity_encrypt only needs the x25519_public key for ECDH
    crypto::Identity peer_id;
    memcpy(peer_id.x25519_public, peer->x25519_public, 32);
    memcpy(peer_id.ed25519_public, peer->ed25519_public, 32);
    memcpy(peer_id.hash, peer->identity_hash, DEST_HASH_SIZE);
    // Private keys are not needed for encryption
    memset(peer_id.x25519_private, 0, 32);
    memset(peer_id.ed25519_private, 0, 32);
    peer_id.valid = true;
    
    // Encrypt payload for the peer
    uint8_t encrypted[RNS_MTU];
    size_t enc_len = 0;
    
    if (!crypto::identity_encrypt(peer_id, data, data_len, encrypted, &enc_len)) {
        Serial.println("[TX] ERROR: Encryption failed");
        return false;
    }
    
    // Build DATA packet
    Packet pkt;
    pkt.set_flags(HEADER_1, false, TRANSPORT_BROADCAST, DEST_SINGLE, PKT_DATA);
    pkt.hops = 0;
    pkt.has_transport = false;
    memcpy(pkt.dest_hash, peer_dest_hash, DEST_HASH_SIZE);
    pkt.context = CTX_NONE;
    memcpy(pkt.payload, encrypted, enc_len);
    pkt.payload_len = enc_len;
    
    return transport_send(pkt);
}

void transport_poll() {
    // Buffer sized to RNS_MTU per Cal's rule (max input size)
    uint8_t rx_buf[RNS_MTU];
    
    int rx_len = hal::radio_receive(rx_buf, sizeof(rx_buf));
    
    if (rx_len <= 0) {
        return;  // Nothing received
    }
    
    // Deserialize packet
    Packet pkt;
    if (!packet_deserialize(rx_buf, rx_len, pkt)) {
        Serial.println("[RX] ERROR: Failed to deserialize packet");
        return;
    }
    
    s_rx_count++;
    
    Serial.printf("[RX] %d bytes, type=%d, RSSI=%.1f SNR=%.1f\n",
                  rx_len, pkt.get_packet_type(),
                  hal::radio_rssi(), hal::radio_snr());
    
    // Dispatch by packet type
    switch (pkt.get_packet_type()) {
        case PKT_ANNOUNCE: {
            if (announce_process(pkt)) {
                Serial.println("[RX] Announce processed successfully");
            } else {
                Serial.println("[RX] Announce processing failed");
            }
            break;
        }
        
        case PKT_DATA: {
            // Check if packet is addressed to us
            if (memcmp(pkt.dest_hash, s_destination->hash, DEST_HASH_SIZE) == 0) {
                // Decrypt packet
                uint8_t decrypted[RNS_MTU];  // Buffer sized to max input per Cal's rule
                size_t dec_len = 0;
                
                if (crypto::identity_decrypt(*s_identity, pkt.payload, pkt.payload_len,
                                            decrypted, &dec_len)) {
                    Serial.printf("[RX] DATA decrypted: %d bytes\n", dec_len);
                    
                    // Call callback if registered
                    if (s_data_callback != nullptr) {
                        s_data_callback(pkt.dest_hash, decrypted, dec_len);
                    }
                } else {
                    Serial.println("[RX] DATA decryption failed");
                }
            } else {
                // Not for us, silently ignore
                Serial.println("[RX] DATA not for us, ignoring");
            }
            break;
        }
        
        case PKT_PROOF: {
            Serial.println("[RX] PROOF packet received (Phase 4 - not implemented yet)");
            break;
        }
        
        case PKT_LINKREQUEST: {
            Serial.println("[RX] LINKREQUEST packet received (not implementing links)");
            break;
        }
        
        default: {
            Serial.printf("[RX] Unknown packet type: %d\n", pkt.get_packet_type());
            break;
        }
    }
}

bool transport_announce(const char* app_data) {
    if (s_identity == nullptr || s_destination == nullptr) {
        Serial.println("[TX] ERROR: Transport not initialized");
        return false;
    }
    
    Packet pkt;
    if (!announce_build(*s_identity, *s_destination, app_data, pkt)) {
        Serial.println("[TX] ERROR: Failed to build announce packet");
        return false;
    }
    
    bool result = transport_send(pkt);
    
    if (result) {
        s_last_announce = millis();
        Serial.println("[TX] Announce sent");
    }
    
    return result;
}

void transport_on_data(data_callback_t cb) {
    s_data_callback = cb;
}

uint32_t transport_rx_count() {
    return s_rx_count;
}

uint32_t transport_tx_count() {
    return s_tx_count;
}

} // namespace net
