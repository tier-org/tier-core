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

tier::core::PeerInfo peer(std::uint8_t tag, tier::core::RoleSet roles,
                          std::uint64_t incarnation, tier::core::Liveness liveness,
                          std::vector<std::string> addresses) {
  tier::core::PeerInfo info;
  info.id.fill(tag);
  info.roles = roles;
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
  in.push_back(peer(0x01, tier::core::role_bit(Role::validator), 3,
                    Liveness::alive, {}));
  in.push_back(peer(0x02, tier::core::role_bit(Role::client), 0,
                    Liveness::suspect, {"1.2.3.4:5"}));
  // A multi-role node (validator + keeper) must round-trip as a set.
  in.push_back(peer(0x03,
                    tier::core::role_bit(Role::validator) |
                        tier::core::role_bit(Role::keeper),
                    9, Liveness::dead, {"10.0.0.1:7777", "[2001:db8::1]:7777"}));
  // Versions: empty (a peer too old to advertise one), a plain release, and a
  // semver with a pre-release/build suffix.
  in[0].version = "";
  in[1].version = "0.2.4";
  in[2].version = "1.0.0-rc.1+build.7";

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
      check(a.incarnation == b.incarnation, "incarnation round-trips");
      check(a.liveness == b.liveness, "liveness round-trips");
      check(a.roles == b.roles, "role set round-trips");
      check(a.addresses == b.addresses, "address set round-trips");
      check(a.version == b.version, "version round-trips");
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

  // Hand-built corruptions of a single-peer message. Layout:
  //   type(1) count(4) id(32) role(1) incarnation(8) liveness(1) addr_count(1)...
  // so the role byte is at offset 37 and addr_count at offset 47.
  const auto one = tier::core::encode_membership_message(
      {peer(0x04, tier::core::role_bit(Role::client), 1, Liveness::alive,
            {"1.2.3.4:5"})});

  // An address count above the per-peer bound is rejected.
  {
    auto bad = one;
    bad[47] = static_cast<std::uint8_t>(tier::core::kMaxAddressesPerPeer + 1);
    check(!tier::core::decode_membership_message(bad).has_value(),
          "addr_count over the bound is rejected");
  }

  // A role byte with a bit outside the defined role set is rejected.
  {
    auto bad = one;
    bad[37] = static_cast<std::uint8_t>(tier::core::kAllRoles | 0x10U);
    check(!tier::core::decode_membership_message(bad).has_value(),
          "unknown role bit is rejected");
  }

  // A version carrying a control character is rejected (it would be rendered by
  // diagnostics tools, so no terminal escapes may ride through it).
  {
    auto evil = peer(0x05, tier::core::role_bit(Role::client), 1,
                     Liveness::alive, {});
    evil.version = std::string("1.0") + '\x1b' + "[31m";
    check(!tier::core::decode_membership_message(
               tier::core::encode_membership_message({evil}))
               .has_value(),
          "version with a control character is rejected");
  }

  // A version longer than the bound is clamped on encode (never overflows the
  // one-byte length), and what encodes still decodes.
  {
    auto big = peer(0x06, tier::core::role_bit(Role::client), 1,
                    Liveness::alive, {});
    big.version.assign(tier::core::kMaxVersionLen + 50U, 'v');
    const auto round = tier::core::decode_membership_message(
        tier::core::encode_membership_message({big}));
    check(round.has_value() && round->size() == 1 &&
              (*round)[0].version.size() == tier::core::kMaxVersionLen,
          "over-long version is clamped to the bound");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
