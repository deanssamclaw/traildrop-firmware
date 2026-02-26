#pragma once
// Reticulum announce broadcast and processing
// Reference: RNS/Packet.py (announce handling)
// TODO: Phase 3 implementation

#include "net/destination.h"
#include "crypto/identity.h"

namespace net {

bool announce_send(const crypto::Identity& id, const Destination& dest);
bool announce_process(const uint8_t* data, size_t len);

} // namespace net
