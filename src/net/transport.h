#pragma once
#include <cstdint>
#include <cstddef>
#include "config.h"
#include "net/packet.h"
#include "crypto/identity.h"
#include "net/destination.h"

namespace net {

// Initialize transport layer. Call after radio, identity, and destination are ready.
// Stores references to device identity and destination for packet handling.
bool transport_init(const crypto::Identity& id, const Destination& dest);

// Send a packet over LoRa radio.
// Serializes the packet and transmits via hal::radio_send().
// Returns true on success.
bool transport_send(const Packet& pkt);

// Send a data packet to a known peer (by destination hash).
// Encrypts payload for the peer using identity_encrypt.
// Returns true on success, false if peer unknown or encryption fails.
bool transport_send_data(const uint8_t peer_dest_hash[DEST_HASH_SIZE],
                         const uint8_t* data, size_t data_len);

// Poll for incoming packets. Call from loop().
// Receives raw bytes from radio, deserializes, dispatches by packet_type.
void transport_poll();

// Send our announce packet. Called periodically and on demand.
bool transport_announce(const char* app_data);

// Get transport statistics
uint32_t transport_rx_count();
uint32_t transport_tx_count();

// Callback type for received data packets addressed to us
// Note: Reticulum HEADER_1 DATA packets don't carry sender identity.
// sender_dest_hash is nullptr — sender attribution requires link-layer features (Phase 4+).
typedef void (*data_callback_t)(const uint8_t* sender_dest_hash,
                                 const uint8_t* data, size_t data_len);

// Register callback for incoming data packets
void transport_on_data(data_callback_t cb);

} // namespace net
