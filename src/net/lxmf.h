#pragma once
// LXMF message format for TrailDrop
// Waypoint and emergency message types
// Reference: LXMF/LXMessage.py
// TODO: Phase 4 implementation

#include <cstdint>
#include <cstddef>

namespace net {

enum LxmfMessageType : uint8_t {
    WAYPOINT  = 0x01,
    EMERGENCY = 0x02,
};

struct WaypointMessage {
    double latitude;
    double longitude;
    char category[16];     // CAMP, WATER, FUEL, HAZARD, SCENIC, INFO, EMERGENCY
    char description[256];
    uint32_t timestamp;
};

struct EmergencyMessage {
    double latitude;
    double longitude;
    char status[256];
    uint32_t timestamp;
};

bool lxmf_encode_waypoint(const WaypointMessage& wp, uint8_t* buf, size_t* len);
bool lxmf_decode_waypoint(const uint8_t* buf, size_t len, WaypointMessage& wp);
bool lxmf_encode_emergency(const EmergencyMessage& em, uint8_t* buf, size_t* len);
bool lxmf_decode_emergency(const uint8_t* buf, size_t len, EmergencyMessage& em);

} // namespace net
