#include "destination.h"
#include "crypto/identity.h"
#include <cstdio>
#include <cstring>

namespace net {

bool destination_derive(const crypto::Identity& id,
                        const char* app_name,
                        const char* aspects,
                        Destination& dest) {
    // Build full_name = "app_name.aspects"
    char full_name[128];
    snprintf(full_name, sizeof(full_name), "%s.%s", app_name, aspects);
    
    // Delegate to crypto layer (correct two-step hash process)
    crypto::identity_destination_hash(full_name, id, dest.hash);
    
    // Store names for later use (announces, etc.)
    strncpy(dest.app_name, app_name, sizeof(dest.app_name) - 1);
    dest.app_name[sizeof(dest.app_name) - 1] = '\0';
    strncpy(dest.aspects, aspects, sizeof(dest.aspects) - 1);
    dest.aspects[sizeof(dest.aspects) - 1] = '\0';
    
    return true;
}

} // namespace net
