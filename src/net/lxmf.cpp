#include "lxmf.h"

namespace net {

bool lxmf_encode_waypoint(const WaypointMessage& wp, uint8_t* buf, size_t* len) {
    // TODO: JSON or msgpack serialization
    return false;
}

bool lxmf_decode_waypoint(const uint8_t* buf, size_t len, WaypointMessage& wp) {
    // TODO: deserialize
    return false;
}

bool lxmf_encode_emergency(const EmergencyMessage& em, uint8_t* buf, size_t* len) {
    // TODO: JSON or msgpack serialization
    return false;
}

bool lxmf_decode_emergency(const uint8_t* buf, size_t len, EmergencyMessage& em) {
    // TODO: deserialize
    return false;
}

} // namespace net
