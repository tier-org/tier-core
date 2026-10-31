#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <span>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/core/seeds.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"
#include "tier/net/endpoint.hpp"
#include "tier/net/node.hpp"

namespace {

std::string join_addresses(const std::vector<std::string>& addresses) {
  std::string out;
  for (const std::string& addr : addresses) {
    if (!out.empty()) {
      out += ',';
    }
    out += addr;
  }
  return out;
}

const char* role_name(tier::core::Role role) {
  switch (role) {
    case tier::core::Role::client:
      return "client";
    case tier::core::Role::validator:
      return "validator";
    case tier::core::Role::keeper:
      return "keeper";
    case tier::core::Role::transmitter:
      return "transmitter";
  }
  return "?";
}

// Render a role set as "client|validator|..." (just "-" if empty).
std::string format_roles(tier::core::RoleSet roles) {
  std::string out;
  for (const tier::core::Role r :
       {tier::core::Role::client, tier::core::Role::validator,
        tier::core::Role::keeper, tier::core::Role::transmitter}) {
    if (tier::core::has_role(roles, r)) {
      if (!out.empty()) {
        out += '|';
      }
      out += role_name(r);
    }
  }
  return out.empty() ? "-" : out;
}

// Where the node's long-term Ed25519 seed lives. Override with TIER_ID_FILE
// (e.g. /etc/tier-network/id or /var/lib/tier/id for a system daemon);
// otherwise a non-root XDG state path is used.
std::string resolve_id_path() {
  if (const char* const env = std::getenv("TIER_ID_FILE"); env != nullptr) {
    return env;
  }
  if (const char* const xdg = std::getenv("XDG_STATE_HOME"); xdg != nullptr) {
    return std::string(xdg) + "/tier/node_key";
  }
  if (const char* const home = std::getenv("HOME"); home != nullptr) {
    return std::string(home) + "/.local/state/tier/node_key";
  }
  return "tier_node_key";
}

// Load the node identity from a 32-byte seed file, creating (and persisting) a
// fresh one if the file is absent. The seed is secret: file 0600, dir 0700.
tier::crypto::NodeIdentity load_or_create_identity(const std::string& path) {
  namespace fs = std::filesystem;

  std::error_code ec;
  if (fs::exists(path, ec) &&
      fs::file_size(path, ec) == tier::crypto::kEd25519SeedSize) {
    std::array<tier::crypto::Byte, tier::crypto::kEd25519SeedSize> seed{};
    std::ifstream in(path, std::ios::binary);
    in.read(reinterpret_cast<char*>(seed.data()),
            static_cast<std::streamsize>(seed.size()));
    if (in.gcount() == static_cast<std::streamsize>(seed.size())) {
      return tier::crypto::NodeIdentity::from_seed(seed);
    }
  }

  const auto identity = tier::crypto::NodeIdentity::generate();
  const fs::path file(path);
  if (file.has_parent_path()) {
    fs::create_directories(file.parent_path(), ec);
    fs::permissions(file.parent_path(), fs::perms::owner_all,
                    fs::perm_options::replace, ec);
  }
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  const auto& seed = identity.seed();
  out.write(reinterpret_cast<const char*>(seed.data()),
            static_cast<std::streamsize>(seed.size()));
  out.close();
  fs::permissions(path, fs::perms::owner_read | fs::perms::owner_write,
                  fs::perm_options::replace, ec);
  return identity;
}

void print_hex(const char* label, std::span<const tier::crypto::Byte> bytes) {
  std::fputs(label, stdout);
  for (const auto b : bytes) {
    std::printf("%02x", static_cast<unsigned>(b));
  }
  std::fputc('\n', stdout);
}

int usage() {
  std::fputs(
      "usage:\n"
      "  tierd run <port> [<seed_ip> <seed_port>]\n"
      "  tierd listen <port>\n"
      "  tierd connect <ip> <port>\n",
      stderr);
  return 2;
}

// Long-lived participant: gossips membership and logs every peer it learns of.
int run_node(const tier::crypto::NodeIdentity& identity, std::uint16_t port,
             const char* seed_ip, std::uint16_t seed_port, bool has_seed) {
  // Bind the IPv6 wildcard: the endpoint's socket is dual-stack, so "::" serves
  // both IPv6 and IPv4 (v4-mapped) peers. "0.0.0.0" would bind the v4 side only.
  tier::net::Node node(identity, tier::core::role_bit(tier::core::Role::client),
                       "::", port);
  const tier::core::PeerId self = node.peer_id();
  node.on_membership_change([self](const tier::core::PeerInfo& peer) {
    if (peer.id == self) {
      // Our own entry changed: we adopted a reachable address from a peer.
      std::printf("advertising addr=%s\n", join_addresses(peer.addresses).c_str());
      std::fflush(stdout);
      return;
    }
    std::fputs("discovered peer ", stdout);
    for (const auto b : peer.id) {
      std::printf("%02x", static_cast<unsigned>(b));
    }
    std::printf(" roles=%s addr=%s\n", format_roles(peer.roles).c_str(),
                join_addresses(peer.addresses).c_str());
    std::fflush(stdout);
  });

  print_hex("node id:  ", node.peer_id());
  std::printf("listening on [::]:%u\n", static_cast<unsigned>(node.local_port()));

  // Join via the preconfigured seeds baked into the binary. One reachable seed
  // is enough; the rest of the membership arrives by anti-entropy. A node that
  // is itself a seed skips its own address.
  const auto seeds = tier::core::default_seed_addresses();
  std::printf("dialing %zu preconfigured seed address(es)\n", seeds.size());
  node.bootstrap(seeds);

  // An optional explicit seed on the command line is dialed in addition.
  if (has_seed) {
    std::printf("dialing seed %s:%u\n", seed_ip, static_cast<unsigned>(seed_port));
    node.connect(seed_ip, seed_port);
  }
  std::fflush(stdout);

  // Periodically report how many peers we know of versus how many we actually
  // hold a connection to, so mesh formation is visible at a glance.
  auto last_status = std::chrono::steady_clock::now();
  for (;;) {
    node.poll(200);
    const auto now = std::chrono::steady_clock::now();
    if (now - last_status >= std::chrono::seconds(2)) {
      std::printf("status: known=%zu connected=%zu\n", node.membership().size(),
                  node.connected_peers().size());
      std::fflush(stdout);
      last_status = now;
    }
  }
}

bool parse_port(std::string_view text, std::uint16_t& out) {
  unsigned value = 0;
  const auto* const end = text.data() + text.size();
  const auto result = std::from_chars(text.data(), end, value);
  if (result.ec != std::errc{} || result.ptr != end || value > 65535) {
    return false;
  }
  out = static_cast<std::uint16_t>(value);
  return true;
}

int run_listen(const tier::crypto::NodeIdentity& identity, std::uint16_t port) {
  tier::net::Endpoint ep(identity, "::", port);
  ep.on_handshake(
      [](tier::net::ConnId, bool, const tier::net::PeerId& peer) {
        print_hex("peer connected: ", peer);
        std::fflush(stdout);
      });
  ep.on_message([&ep](tier::net::ConnId conn, const tier::net::PeerId&,
                      std::span<const tier::crypto::Byte> payload) {
    ep.send(conn, payload);  // echo
    std::printf("echoed %zu bytes\n", payload.size());
    std::fflush(stdout);
  });

  print_hex("node id:  ", identity.public_key());
  std::printf("listening on [::]:%u\n", static_cast<unsigned>(ep.local_port()));
  std::fflush(stdout);
  for (;;) {
    ep.poll(1000);
  }
}

int run_connect(const tier::crypto::NodeIdentity& identity, const char* ip,
                std::uint16_t port) {
  tier::net::Endpoint ep(identity, "::", 0);
  const std::vector<tier::crypto::Byte> ping{0x70, 0x69, 0x6E, 0x67};  // "ping"

  bool got_echo = false;
  ep.on_handshake([&ep, &ping](tier::net::ConnId conn, bool initiator,
                               const tier::net::PeerId& peer) {
    print_hex("connected to: ", peer);
    if (initiator) {
      ep.send(conn, ping);
    }
  });
  ep.on_message([&got_echo](tier::net::ConnId, const tier::net::PeerId&,
                            std::span<const tier::crypto::Byte> payload) {
    print_hex("echo:         ", payload);
    got_echo = true;
  });

  print_hex("node id:      ", identity.public_key());
  ep.connect(ip, port);
  for (int i = 0; i < 5000 && !got_echo; ++i) {
    ep.poll(5);
  }
  if (!got_echo) {
    std::fputs("no echo received\n", stderr);
    return 1;
  }
  std::printf("kex group:    %s\n", ep.last_negotiated_group().c_str());
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return usage();
  }

  const std::string id_path = resolve_id_path();
  const auto identity = load_or_create_identity(id_path);
  std::printf("id file:  %s\n", id_path.c_str());
  const std::string_view cmd = argv[1];

  if (cmd == "run") {
    std::uint16_t port = 0;
    if ((argc != 3 && argc != 5) || !parse_port(argv[2], port)) {
      return usage();
    }
    if (argc == 5) {
      std::uint16_t seed_port = 0;
      if (!parse_port(argv[4], seed_port)) {
        return usage();
      }
      return run_node(identity, port, argv[3], seed_port, true);
    }
    return run_node(identity, port, nullptr, 0, false);
  }

  if (cmd == "listen") {
    std::uint16_t port = 0;
    if (argc != 3 || !parse_port(argv[2], port)) {
      return usage();
    }
    return run_listen(identity, port);
  }

  if (cmd == "connect") {
    std::uint16_t port = 0;
    if (argc != 4 || !parse_port(argv[3], port)) {
      return usage();
    }
    return run_connect(identity, argv[2], port);
  }

  return usage();
}
