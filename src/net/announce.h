#pragma once
// Reticulum announce broadcast and processing
// Reference: RNS/Packet.py (announce handling)
// Phase 3c: Announce send/receive + peer table

#include <cstdint>
#include <cstddef>
#include "config.h"
#include "crypto/identity.h"
#include "net/destination.h"
#include "net/packet.h"

namespace net {

// Build an announce packet for our identity and destination.
// app_data is optional (e.g., display name). Pass nullptr and 0 if none.
// Fills out_pkt with a ready-to-serialize announce packet.
// Returns true on success.
bool announce_build(const crypto::Identity& id,
                    const Destination& dest,
                    const char* app_data,
                    Packet& out_pkt);

// Validate and process a received announce packet.
// pkt = the deserialized packet (packet_type must be PKT_ANNOUNCE).
// Returns true if announce is valid and peer was stored.
bool announce_process(const Packet& pkt);

} // namespace net
