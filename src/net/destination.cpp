#include "destination.h"
#include "crypto/hash.h"

namespace net {

bool destination_derive(const crypto::Identity& id,
                        const char* app_name,
                        const char* aspects,
                        Destination& dest) {
    // TODO: SHA-256(identity_public + app_name + aspects), truncate to 16 bytes
    return false;
}

} // namespace net
