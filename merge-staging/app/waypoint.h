#pragma once
// Waypoint data model and database
// TODO: Phase 5-6 implementation

#include <cstdint>

namespace app {

enum WaypointCategory : uint8_t {
    CAMP      = 0,
    WATER     = 1,
    FUEL      = 2,
    HAZARD    = 3,
    SCENIC    = 4,
    INFO      = 5,
    EMERGENCY = 6,
};

const char* category_name(WaypointCategory cat);
const char* category_emoji(WaypointCategory cat);

struct Waypoint {
    uint32_t id;
    double latitude;
    double longitude;
    WaypointCategory category;
    char description[256];
    uint32_t timestamp;
    uint8_t sender_hash[16];  // Zero if local
};

// Database operations
bool waypoint_db_init(const char* path);
uint32_t waypoint_add(const Waypoint& wp);
bool waypoint_delete(uint32_t id);
bool waypoint_update(uint32_t id, const Waypoint& wp);
int waypoint_list(Waypoint* out, int max, WaypointCategory* filter = nullptr);
int waypoint_search(const char* query, Waypoint* out, int max);
int waypoint_count();

} // namespace app
