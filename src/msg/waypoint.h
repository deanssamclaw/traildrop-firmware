#pragma once
// Waypoint codec — encode/decode GPS waypoints as msgpack dicts
// for embedding in LXMF custom fields (traildrop/waypoint).

#include <cstdint>
#include <cstddef>
#include "crypto/identity.h"

namespace msg {

struct Waypoint {
    double lat;          // Latitude (decimal degrees, float64)
    double lon;          // Longitude (decimal degrees, float64)
    float ele;           // Elevation (meters)
    char name[32];       // Waypoint name (null-terminated)
    char notes[128];     // Optional notes (null-terminated)
    uint32_t timestamp;  // Unix timestamp (seconds)
    bool valid;
};

// Encode waypoint to msgpack dict.
// Returns encoded length, or 0 on failure.
size_t waypoint_encode(const Waypoint& wp, uint8_t* out, size_t out_cap);

// Decode msgpack dict to waypoint.
// Returns true if decoded successfully.
bool waypoint_decode(const uint8_t* data, size_t len, Waypoint& wp);

// Send current GPS position as a waypoint to a peer.
// Reads GPS from HAL, refuses if no fix.
bool waypoint_send(
    const crypto::Identity& our_identity,
    const uint8_t our_lxmf_dest[16],
    const uint8_t peer_announce_dest[16],
    const char* name,
    const char* notes
);

// Send a waypoint with explicit coordinates (for testing without GPS fix).
bool waypoint_send_explicit(
    const crypto::Identity& our_identity,
    const uint8_t our_lxmf_dest[16],
    const uint8_t peer_announce_dest[16],
    double lat, double lon, float ele,
    const char* name,
    const char* notes
);

} // namespace msg
