#pragma once
// LXMF transport layer — send/receive LXMF messages over encrypted LoRa
// Sits above the RNS packet layer and LXMF build/parse layer.
// Handles encryption, decryption, dedup, signature verification.

#include <cstdint>
#include <cstddef>
#include "crypto/identity.h"
#include "net/destination.h"
#include "msg/lxmf.h"

namespace msg {

// Initialize LXMF transport layer.
// announce_dest: traildrop.waypoint (for announce processing + legacy DATA)
// lxmf_dest: lxmf.delivery (for LXMF DATA matching)
bool lxmf_transport_init(
    const crypto::Identity& id,
    const net::Destination& announce_dest,
    const net::Destination& lxmf_dest
);

// Send an LXMF message to a peer (opportunistic, encrypted).
// Looks up peer by peer_announce_dest, encrypts to their lxmf.delivery dest.
// Returns true if message was built, encrypted, and transmitted.
bool lxmf_send(
    const crypto::Identity& our_identity,
    const uint8_t our_lxmf_dest[16],
    const uint8_t peer_announce_dest[16],
    const char* title,
    const char* content,
    const uint8_t* custom_type, size_t custom_type_len,
    const uint8_t* custom_data, size_t custom_data_len,
    uint8_t message_hash_out[32]
);

// Callback type for received LXMF messages
typedef void (*lxmf_receive_callback_t)(const LXMessage& msg, int rssi, float snr);

// Register callback for incoming LXMF messages
void lxmf_set_receive_callback(lxmf_receive_callback_t cb);

// Poll for incoming packets. Call from loop().
// Handles announce processing, LXMF DATA decryption/parsing, and legacy DATA.
void lxmf_transport_poll();

// Message deduplication (exposed for testing)
bool lxmf_is_duplicate(const uint8_t hash[32]);
void lxmf_record_message(const uint8_t hash[32]);

// Statistics
uint32_t lxmf_rx_count();

} // namespace msg
