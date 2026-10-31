#pragma once

#include <cstdint>
#include <iterator>
#include <string>
#include <vector>

namespace tier::core {

// Preconfigured bootstrap seeds. This list is the single source of truth for
// how a fresh node joins the network: it is compiled into the binary, not
// fetched at runtime, so joining adds no extra point of failure. The seeds are
// operated by the project; their addresses change only by editing this file and
// cutting a new release.
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

// A seed's identity on the wire is its PeerId (hash of its key), learned from
// the handshake - not a name. The trailing comments are just labels for whoever
// edits this file. Adding or moving a seed is an edit here plus a new release.
inline constexpr SeedNode kSeedNodes[] = {
    {"66.220.12.143", "2a0b:8c40:1::143"},  // tier-01
    {"66.220.20.177", "2a0b:8c40:2::177"},  // tier-02
    {"5.255.64.147", "2a0b:8c40:3::147"},   // tier-03
    {"66.165.245.6", "2604:4500:9:7::2"},   // tier-04
};

// The seeds as dialable "ip:port" strings (IPv6 bracketed as "[addr]:port").
// IPv6 is listed first so list order reflects the dial policy's IPv6 preference.
inline std::vector<std::string> default_seed_addresses() {
  std::vector<std::string> out;
  out.reserve(std::size(kSeedNodes) * 2);
  const std::string port = ":" + std::to_string(kSeedPort);
  for (const SeedNode& s : kSeedNodes) {
    out.push_back("[" + std::string(s.ipv6) + "]" + port);
    out.push_back(std::string(s.ipv4) + port);
  }
  return out;
}

}  // namespace tier::core
