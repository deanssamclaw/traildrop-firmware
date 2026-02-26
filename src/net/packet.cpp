#include "packet.h"

namespace net {

bool packet_serialize(const Packet& pkt, uint8_t* buf, size_t* len) {
    // TODO: Reticulum wire format serialization
    return false;
}

bool packet_deserialize(const uint8_t* buf, size_t len, Packet& pkt) {
    // TODO: Reticulum wire format deserialization
    return false;
}

} // namespace net
