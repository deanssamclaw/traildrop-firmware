#include "announce.h"

namespace net {

bool announce_send(const crypto::Identity& id, const Destination& dest) {
    // TODO: broadcast announce packet with identity public keys
    return false;
}

bool announce_process(const uint8_t* data, size_t len) {
    // TODO: parse incoming announce, store peer identity
    return false;
}

} // namespace net
