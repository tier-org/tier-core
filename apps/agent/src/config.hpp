#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "envelope.hpp"
#include "tier/core/membership.hpp"  // PeerId

namespace tier::agent {

enum class Role : std::uint8_t { agent, collector, both };

struct Config {
  Role role = Role::agent;
  // Path to tierd's admin UNIX socket (the node this agent drives).
  std::string admin_socket = "/run/tier/tierd.sock";
  // Where this actor's 32-byte Ed25519 identity seed is stored (created on first
  // run). Its user id/address is stable across restarts so peers can target it.
  std::string seed_file = "/var/lib/tier/agent.seed";

  // --- agent role ---
  tier::core::PeerId collector{};  // resolved from the collector's tier address
  bool has_collector = false;
  // Batched shipping: buffer samples and flush one envelope every `interval_secs`
  // (or early once `max_batch` distinct samples are buffered). Gauges collapse to
  // the newest value per key within a batch; events are all retained.
  std::uint32_t interval_secs = 10;
  std::uint32_t max_batch = 256;
  // Optional periodic source (serf-like): run this shell command every interval
  // and parse its stdout as ingest lines. Empty = read ingest lines from stdin.
  std::string exec;

  // --- collector role ---
  std::string store_path = "/var/lib/tier/agent-store.log";
  std::vector<tier::core::PeerId> accept_from;  // allowlist; empty = accept any
  bool keeper_persistence = false;              // opt-in HA (not wired yet)
  // Optional local read interface: a UNIX socket that serves a snapshot of the
  // store (optionally filtered by a request line). Empty = no read socket.
  std::string query_socket;
};

// Parse the TOML-subset config text. On error returns nullopt and sets `err`.
[[nodiscard]] std::optional<Config> parse_config(const std::string& text,
                                                 std::string& err);

// Parse one ingest line: "<kind> <key> <value...>" where kind is
// gauge|g|event|e. The value is the rest of the line (may contain spaces).
// Returns nullopt on a blank/comment line or a malformed one.
[[nodiscard]] std::optional<Sample> parse_sample_line(const std::string& line);

}  // namespace tier::agent
