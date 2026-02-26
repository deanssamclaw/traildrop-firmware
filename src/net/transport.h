#pragma once
// Reticulum transport layer (single-hop initially)
// Reference: RNS/Transport.py
// TODO: Phase 3 implementation

#include "net/packet.h"

namespace net {

bool transport_init();
bool transport_send(const Packet& pkt);
void transport_poll();  // Called from main loop, processes incoming

} // namespace net
