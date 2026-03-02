#include "peers.h"

namespace app {

bool peers_init() { return false; }
bool peer_add_or_update(const Peer& peer) { return false; }
bool peer_remove(const uint8_t* dest_hash) { return false; }
int peer_list(Peer* out, int max) { return 0; }
const Peer* peer_find(const uint8_t* dest_hash) { return nullptr; }

} // namespace app
