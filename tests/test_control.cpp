#include <cstdio>
#include <vector>

#include "tier/core/control.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

tier::core::PeerInfo peer(std::uint8_t tag, tier::core::Role role,
                          std::uint64_t incarnation, tier::core::Liveness liveness,
                          std::vector<std::string> addresses) {
  tier::core::PeerInfo info;
  info.id.fill(tag);
  info.role = role;
  info.incarnation = incarnation;
  info.liveness = liveness;
  info.addresses = std::move(addresses);
  return info;
}

}  // namespace

int main() {
  using tier::core::Liveness;
  using tier::core::Role;

  // Round-trip peers carrying zero, one and several addresses (IPv4 + IPv6).
  std::vector<tier::core::PeerInfo> in;
  in.push_back(peer(0x01, Role::validator, 3, Liveness::alive, {}));
  in.push_back(peer(0x02, Role::client, 0, Liveness::suspect, {"1.2.3.4:5"}));
  in.push_back(peer(0x03, Role::keeper, 9, Liveness::dead,
                    {"10.0.0.1:7777", "[2001:db8::1]:7777"}));

  const auto encoded = tier::core::encode_membership_message(in);
  check(tier::core::peek_control_type(encoded) ==
            tier::core::ControlType::membership,
        "membership peeks as its type");

  const auto decoded = tier::core::decode_membership_message(encoded);
  check(decoded.has_value(), "membership decodes");
  check(decoded && decoded->size() == in.size(), "peer count round-trips");
  if (decoded && decoded->size() == in.size()) {
    for (std::size_t i = 0; i < in.size(); ++i) {
      const auto& a = in[i];
      const auto& b = (*decoded)[i];
      check(a.id == b.id, "id round-trips");
      check(a.role == b.role, "role round-trips");
      check(a.incarnation == b.incarnation, "incarnation round-trips");
      check(a.liveness == b.liveness, "liveness round-trips");
      check(a.addresses == b.addresses, "address set round-trips");
    }
  }

  // Trailing garbage is rejected.
  {
    auto trailing = encoded;
    trailing.push_back(0xFF);
    check(!tier::core::decode_membership_message(trailing).has_value(),
          "trailing byte rejected");
  }

  // Truncation anywhere in the stream is rejected without crashing.
  {
    bool all_rejected = true;
    for (std::size_t n = 1; n < encoded.size(); ++n) {
      std::vector<std::uint8_t> prefix(encoded.begin(),
                                       encoded.begin() + static_cast<long>(n));
      if (tier::core::decode_membership_message(prefix).has_value()) {
        all_rejected = false;
        break;
      }
    }
    check(all_rejected, "every truncation is rejected");
  }

  // An address count above the per-peer bound is rejected. Hand-build a single
  // peer and set its addr_count byte past kMaxAddressesPerPeer.
  {
    const auto one = tier::core::encode_membership_message(
        {peer(0x04, Role::client, 1, Liveness::alive, {"1.2.3.4:5"})});
    // Layout: type(1) count(4) id(32) role(1) incarnation(8) liveness(1)
    //         addr_count(1) ...  -> addr_count is at offset 47.
    auto bad = one;
    bad[47] = static_cast<std::uint8_t>(tier::core::kMaxAddressesPerPeer + 1);
    check(!tier::core::decode_membership_message(bad).has_value(),
          "addr_count over the bound is rejected");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
