#include "waypoint.h"
#include "msg/msgpack.h"
#include "msg/lxmf_transport.h"
#include "hal/gps.h"
#include <cstring>
#include <Arduino.h>

namespace msg {

size_t waypoint_encode(const Waypoint& wp, uint8_t* out, size_t out_cap) {
    Encoder enc(out, out_cap);

    // Count fields: lat, lon, ele, name, ts are always present; notes only if non-empty
    bool has_notes = (wp.notes[0] != '\0');
    uint8_t field_count = has_notes ? 6 : 5;

    enc.write_map(field_count);

    enc.write_str("lat", 3);
    enc.write_float64(wp.lat);

    enc.write_str("lon", 3);
    enc.write_float64(wp.lon);

    enc.write_str("ele", 3);
    enc.write_float64((double)wp.ele);

    enc.write_str("name", 4);
    enc.write_str(wp.name, strlen(wp.name));

    if (has_notes) {
        enc.write_str("notes", 5);
        enc.write_str(wp.notes, strlen(wp.notes));
    }

    enc.write_str("ts", 2);
    enc.write_uint(wp.timestamp);

    if (enc.error) return 0;
    return enc.pos;
}

bool waypoint_decode(const uint8_t* data, size_t len, Waypoint& wp) {
    Decoder dec(data, len);

    memset(&wp, 0, sizeof(wp));

    uint8_t map_count = dec.read_map();
    if (dec.error || map_count < 4) return false;

    for (uint8_t i = 0; i < map_count; i++) {
        char key[16];
        size_t key_len = dec.read_str(key, sizeof(key) - 1);
        if (dec.error) return false;
        key[key_len] = '\0';

        if (strcmp(key, "lat") == 0) {
            wp.lat = dec.read_float64();
        } else if (strcmp(key, "lon") == 0) {
            wp.lon = dec.read_float64();
        } else if (strcmp(key, "ele") == 0) {
            wp.ele = (float)dec.read_float64();
        } else if (strcmp(key, "name") == 0) {
            size_t n = dec.read_str(wp.name, sizeof(wp.name) - 1);
            wp.name[n] = '\0';
        } else if (strcmp(key, "notes") == 0) {
            size_t n = dec.read_str(wp.notes, sizeof(wp.notes) - 1);
            wp.notes[n] = '\0';
        } else if (strcmp(key, "ts") == 0) {
            wp.timestamp = dec.read_uint();
        } else {
            dec.skip();  // Unknown key — skip value
        }

        if (dec.error) return false;
    }

    wp.valid = true;
    return true;
}

bool waypoint_send(
    const crypto::Identity& our_identity,
    const uint8_t our_lxmf_dest[16],
    const uint8_t peer_announce_dest[16],
    const char* name,
    const char* notes
) {
    if (!hal::gps_has_fix()) {
        Serial.println("[WAYPOINT] No GPS fix — cannot send");
        return false;
    }

    return waypoint_send_explicit(
        our_identity, our_lxmf_dest, peer_announce_dest,
        hal::gps_latitude(), hal::gps_longitude(), hal::gps_altitude(),
        name, notes
    );
}

bool waypoint_send_explicit(
    const crypto::Identity& our_identity,
    const uint8_t our_lxmf_dest[16],
    const uint8_t peer_announce_dest[16],
    double lat, double lon, float ele,
    const char* name,
    const char* notes
) {
    Waypoint wp;
    memset(&wp, 0, sizeof(wp));
    wp.lat = lat;
    wp.lon = lon;
    wp.ele = ele;
    strncpy(wp.name, name ? name : "Waypoint", sizeof(wp.name) - 1);
    if (notes) strncpy(wp.notes, notes, sizeof(wp.notes) - 1);
    wp.timestamp = (uint32_t)(millis() / 1000);  // Uptime as placeholder
    wp.valid = true;

    // Encode waypoint to msgpack
    uint8_t custom_data[256];
    size_t custom_data_len = waypoint_encode(wp, custom_data, sizeof(custom_data));
    if (custom_data_len == 0) {
        Serial.println("[WAYPOINT] Encode failed");
        return false;
    }

    // Send via LXMF with custom fields
    uint8_t msg_hash[32];
    bool ok = lxmf_send(
        our_identity, our_lxmf_dest, peer_announce_dest,
        name ? name : "Waypoint",
        notes ? notes : "",
        (const uint8_t*)"traildrop/waypoint", 18,
        custom_data, custom_data_len,
        msg_hash
    );

    if (ok) {
        Serial.printf("[WAYPOINT] Sent: %s (%.6f, %.6f, %.1fm)\n",
                      wp.name, wp.lat, wp.lon, wp.ele);
    }
    return ok;
}

} // namespace msg
