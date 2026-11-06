#pragma once

#include "node_client.hpp"
#include "store.hpp"

namespace tier::messenger {

// Run the interactive terminal UI against the node `client` and local `store`,
// acting as `account` (a local user id hosted on the node). Returns the process
// exit code.
int run_ui(NodeClient& client, Store& store, const tier::core::PeerId& account);

}  // namespace tier::messenger
