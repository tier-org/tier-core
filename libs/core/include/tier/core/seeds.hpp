#pragma once

#include <cstddef>
#include <cstdint>
#include <iterator>
#include <string>
#include <string_view>
#include <vector>

namespace tier::core {

// Preconfigured bootstrap seeds, per network (cluster). A node joins exactly one
// network; `mainnet` is the default and the production cluster. The seed set is
// the single source of truth for how a fresh node joins its network: it is
// compiled into the binary, not fetched at runtime, so joining adds no extra
// point of failure. Seeds change only by editing this file and cutting a new
// release.
//
// Networks are isolated at the transport layer (the network name is folded into
// the ALPN token), so the choice of network determines both which seeds a node
// dials and which peers it will even complete a handshake with. Nodes on
// different networks never see each other, even when they share a seed address.
//
// Each seed is reachable over both IPv4 and IPv6. A joining node dials whichever
// family it has (IPv6 preferred by the dial policy); one reachable seed is
// enough, the rest of the membership spreads by anti-entropy. A node that is
// itself a seed skips its own address at startup (see Node::bootstrap), and a
// connection to self is dropped regardless (see Node::poll).
struct SeedNode {
  const char* ipv4;  // bare IPv4 literal, no port
  const char* ipv6;  // bare IPv6 literal, no brackets, no port
};

// The QUIC/UDP port every seed listens on.
inline constexpr std::uint16_t kSeedPort = 7777;

// The network a node joins when none is configured (TIER_NETWORK unset).
inline constexpr std::string_view kDefaultNetwork = "mainnet";

// A seed's identity on the wire is its PeerId (hash of its key), learned from
// the handshake - not a name. The trailing comments are just labels for whoever
// edits this file. Adding or moving a seed is an edit here plus a new release.
inline constexpr SeedNode kMainnetSeeds[] = {
    {"66.220.12.143", "2a0b:8c40:1::143"},  // tier-01
    {"66.220.20.177", "2a0b:8c40:2::177"},  // tier-02
    {"5.255.64.147", "2a0b:8c40:3::147"},   // tier-03
    {"66.165.245.6", "2604:4500:9:7::2"},   // tier-04
};
// testnet has no baked seeds yet; a testnet node joins via TIER_SEEDS until
// they are added here. Private networks never have baked seeds.

// A network name is a short DNS-style label: lowercase letters, digits and
// hyphens, 1..32 chars. It must fold cleanly into the ALPN token and appear in
// config and logs, so it is kept small and conservative.
inline bool is_valid_network_name(std::string_view name) {
  if (name.empty() || name.size() > 32) {
    return false;
  }
  for (const char c : name) {
    const bool ok =
        (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    if (!ok) {
      return false;
    }
  }
  return true;
}

// Expand a seed table to dialable "ip:port" strings (IPv6 bracketed as
// "[addr]:port" and listed first, reflecting the dial policy's IPv6 preference).
inline std::vector<std::string> expand_seeds(const SeedNode* seeds,
                                             std::size_t count) {
  std::vector<std::string> out;
  out.reserve(count * 2);
  const std::string port = ":" + std::to_string(kSeedPort);
  for (std::size_t i = 0; i < count; ++i) {
    out.push_back("[" + std::string(seeds[i].ipv6) + "]" + port);
    out.push_back(std::string(seeds[i].ipv4) + port);
  }
  return out;
}

// Preconfigured seeds for a network. mainnet returns the baked production set;
// testnet and private networks have none baked in and join via TIER_SEEDS.
inline std::vector<std::string> seed_addresses(std::string_view network) {
  if (network == "mainnet") {
    return expand_seeds(kMainnetSeeds, std::size(kMainnetSeeds));
  }
  return {};
}

// The default network's seeds.
inline std::vector<std::string> default_seed_addresses() {
  return seed_addresses(kDefaultNetwork);
}

// Parse a seed-override list (the TIER_SEEDS environment variable): addresses
// separated by commas and/or whitespace, e.g. "[fd00::2]:7777, 10.0.0.2:7777".
// Empty tokens are dropped; each surviving token is expected to be a dialable
// "ip:port" (IPv6 bracketed), but dialability is validated downstream in
// Node::bootstrap, so this is a plain tokenizer.
//
// When set, this is a FULL replacement of the baked list above, used for private
// networks and tests. It is local static configuration, not a runtime fetch, so
// it keeps the "no extra point of failure at join" property: a node dials only
// what its operator compiled in or configured, never an address learned from the
// network before a TLS handshake authenticates the peer.
inline std::vector<std::string> parse_seed_list(std::string_view spec) {
  std::vector<std::string> out;
  std::string token;
  const auto flush = [&] {
    if (!token.empty()) {
      out.push_back(token);
      token.clear();
    }
  };
  for (const char c : spec) {
    if (c == ',' || c == ' ' || c == '\t' || c == '\n' || c == '\r') {
      flush();
    } else {
      token.push_back(c);
    }
  }
  flush();
  return out;
}

}  // namespace tier::core
