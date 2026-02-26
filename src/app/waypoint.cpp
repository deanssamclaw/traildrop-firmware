#include "waypoint.h"

namespace app {

const char* category_name(WaypointCategory cat) {
    switch (cat) {
        case CAMP:      return "Campsite";
        case WATER:     return "Water Source";
        case FUEL:      return "Fuel";
        case HAZARD:    return "Hazard";
        case SCENIC:    return "Scenic";
        case INFO:      return "Info";
        case EMERGENCY: return "Emergency";
        default:        return "Unknown";
    }
}

const char* category_emoji(WaypointCategory cat) {
    switch (cat) {
        case CAMP:      return "⛺";
        case WATER:     return "💧";
        case FUEL:      return "⛽";
        case HAZARD:    return "⚠️";
        case SCENIC:    return "📸";
        case INFO:      return "ℹ️";
        case EMERGENCY: return "🚨";
        default:        return "?";
    }
}

bool waypoint_db_init(const char* path) { return false; }
uint32_t waypoint_add(const Waypoint& wp) { return 0; }
bool waypoint_delete(uint32_t id) { return false; }
bool waypoint_update(uint32_t id, const Waypoint& wp) { return false; }
int waypoint_list(Waypoint* out, int max, WaypointCategory* filter) { return 0; }
int waypoint_search(const char* query, Waypoint* out, int max) { return 0; }
int waypoint_count() { return 0; }

} // namespace app
