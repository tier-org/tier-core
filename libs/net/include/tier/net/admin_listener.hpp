#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "tier/core/admin.hpp"

namespace tier::net {

// A local Unix-domain admin endpoint. The daemon owns one and calls serve()
// once per loop iteration to answer any pending tierctl request. It is
// non-blocking when idle (no pending connection costs nothing) and bounded per
// connection, so a slow or malicious local client can never stall the node's
// QUIC loop. Not a network surface: the socket lives on the filesystem and is
// reachable only by processes the OS permits (service user and root).
class AdminListener {
 public:
  // Produce the response payload for a decoded request op. Returning an empty
  // vector sends nothing and closes the connection.
  using Handler = std::function<std::vector<std::uint8_t>(tier::core::AdminOp)>;

  // Bind and listen on `path` (any stale socket file is removed first). Throws
  // std::runtime_error on failure so the daemon can decide to run without admin.
  explicit AdminListener(std::string path);
  ~AdminListener();
  AdminListener(const AdminListener&) = delete;
  AdminListener& operator=(const AdminListener&) = delete;
  AdminListener(AdminListener&&) = delete;
  AdminListener& operator=(AdminListener&&) = delete;

  // Accept and fully serve up to `max_conns` pending connections, then return.
  void serve(const Handler& handler, int max_conns = 4);

 private:
  int fd_ = -1;
  std::string path_;
};

}  // namespace tier::net
