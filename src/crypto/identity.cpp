#include "identity.h"

namespace crypto {

bool identity_generate(Identity& id) {
    // TODO: libsodium X25519 + Ed25519 keygen
    return false;
}

bool identity_load(Identity& id, const char* path) {
    // TODO: load from flash/SD
    return false;
}

bool identity_save(const Identity& id, const char* path) {
    // TODO: persist to flash/SD
    return false;
}

} // namespace crypto
