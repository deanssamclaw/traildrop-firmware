#include "transport.h"

namespace net {

bool transport_init() {
    // TODO: init LoRa radio interface
    return false;
}

bool transport_send(const Packet& pkt) {
    // TODO: serialize + transmit via radio
    return false;
}

void transport_poll() {
    // TODO: check radio for incoming, deserialize, dispatch
}

} // namespace net
