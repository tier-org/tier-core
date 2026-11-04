// Tests for the presence layer (tier::msg presence): register round-trip and
// field fidelity, signature verification, tamper rejection (every single-byte
// flip), wrong network / wrong expected id, the lookup and result codecs, and
// the not-found result.
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/presence.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::crypto::Byte;

tier::core::PeerId id_of(const tier::crypto::NodeIdentity& id) {
  const auto& pub = id.public_key();
  const auto d = tier::crypto::sha256(tier::crypto::ByteSpan(pub.data(), pub.size()));
  tier::core::PeerId p{};
  for (std::size_t i = 0; i < p.size(); ++i) p[i] = d[i];
  return p;
}

tier::crypto::ByteSpan sp(const std::vector<Byte>& v) {
  return tier::crypto::ByteSpan(v.data(), v.size());
}

const char* kNet = "mainnet";

}  // namespace

int main() {
  using tier::core::Role;
  const tier::core::RoleSet kClient = tier::core::role_bit(Role::client);

  const auto alice = tier::crypto::NodeIdentity::generate();
  const std::vector<std::string> addrs = {"10.0.0.1:7777",
                                          "[2001:db8::1]:7777"};
  const std::uint64_t issued = 1700000000;
  const std::uint64_t expiry = 1800000000;  // some future unix time

  const std::vector<Byte> reg =
      tier::msg::make_presence_register(alice, kNet, kClient, addrs, issued,
                                        expiry);

  // Round-trip and field fidelity.
  {
    const auto rec = tier::msg::open_presence_register(kNet, sp(reg));
    check(rec.has_value(), "register verifies");
    if (rec) {
      check(rec->id == id_of(alice), "id matches");
      check(rec->identity_key == alice.public_key(), "identity key carried");
      check(rec->roles == kClient, "roles carried");
      check(rec->issued_unix == issued, "issue stamp carried");
      check(rec->expiry_unix == expiry, "expiry carried");
      check(rec->addresses == addrs, "addresses carried in order");
      check(rec->enc_keys.x25519 == alice.x25519_identity_key().public_key,
            "x25519 key carried");
      check(rec->enc_keys.mlkem == alice.mlkem768_identity_key().public_key,
            "ml-kem key carried");
      check(!rec->record_bytes.empty(), "record_bytes populated");
    }
  }

  // Wrong network: the signature is bound to the network, so it must fail.
  {
    const auto rec = tier::msg::open_presence_register("testnet", sp(reg));
    check(!rec.has_value(), "register under a different network is rejected");
  }

  // Every single-byte flip of the register frame is rejected (structure or
  // signature). This is the key property: a communicator cannot be fed a
  // tampered record that still verifies.
  {
    int accepted = 0;
    for (std::size_t i = 0; i < reg.size(); ++i) {
      for (int bit = 0; bit < 8; ++bit) {
        std::vector<Byte> bad = reg;
        bad[i] = static_cast<Byte>(bad[i] ^ (1U << bit));
        if (tier::msg::open_presence_register(kNet, sp(bad)).has_value()) {
          ++accepted;
        }
      }
    }
    check(accepted == 0, "no single-byte flip of a register verifies");
  }

  // Result round-trip: a communicator re-emits the stored record bytes verbatim
  // and the resolver verifies them independently.
  {
    const auto rec = tier::msg::open_presence_register(kNet, sp(reg));
    check(rec.has_value(), "register verifies (for result test)");
    const auto queried = id_of(alice);
    const std::vector<Byte> result =
        tier::msg::make_presence_result(queried, sp(rec->record_bytes));
    const auto out = tier::msg::open_presence_result(kNet, queried, sp(result));
    check(out.has_value(), "result parses");
    check(out && out->has_value(), "result carries a found record");
    if (out && out->has_value()) {
      check((*out)->id == queried, "resolved id matches the query");
      check((*out)->addresses == addrs, "resolved addresses match");
    }
  }

  // A result whose id does not match what the resolver asked for is rejected
  // (a communicator cannot answer a query for X with a record for Y).
  {
    const auto rec = tier::msg::open_presence_register(kNet, sp(reg));
    const auto bob = tier::crypto::NodeIdentity::generate();
    const std::vector<Byte> result =
        tier::msg::make_presence_result(id_of(bob), sp(rec->record_bytes));
    const auto out = tier::msg::open_presence_result(kNet, id_of(bob), sp(result));
    check(!out.has_value(), "a result whose record id != queried id is rejected");
  }

  // Not-found result.
  {
    const auto queried = id_of(alice);
    const std::vector<Byte> result =
        tier::msg::make_presence_result(queried, tier::crypto::ByteSpan());
    const auto out = tier::msg::open_presence_result(kNet, queried, sp(result));
    check(out.has_value(), "not-found result parses");
    check(out && !out->has_value(), "not-found result has no record");
  }

  // A found result read with the wrong expected id is rejected before any
  // record parsing.
  {
    const auto rec = tier::msg::open_presence_register(kNet, sp(reg));
    const auto queried = id_of(alice);
    const std::vector<Byte> result =
        tier::msg::make_presence_result(queried, sp(rec->record_bytes));
    const auto bob = tier::crypto::NodeIdentity::generate();
    const auto out = tier::msg::open_presence_result(kNet, id_of(bob), sp(result));
    check(!out.has_value(), "result for a different expected id is rejected");
  }

  // Lookup codec.
  {
    const auto target = id_of(alice);
    const std::vector<Byte> look = tier::msg::make_presence_lookup(target);
    const auto got = tier::msg::open_presence_lookup(sp(look));
    check(got.has_value() && *got == target, "lookup round-trips");

    std::vector<Byte> truncated = look;
    truncated.pop_back();
    check(!tier::msg::open_presence_lookup(sp(truncated)).has_value(),
          "a truncated lookup is rejected");

    std::vector<Byte> trailing = look;
    trailing.push_back(0);
    check(!tier::msg::open_presence_lookup(sp(trailing)).has_value(),
          "a lookup with trailing bytes is rejected");
  }

  // Empty / junk inputs never crash and are rejected.
  {
    check(!tier::msg::open_presence_register(kNet, tier::crypto::ByteSpan())
               .has_value(),
          "empty register rejected");
    check(!tier::msg::open_presence_lookup(tier::crypto::ByteSpan()).has_value(),
          "empty lookup rejected");
    const auto queried = id_of(alice);
    check(!tier::msg::open_presence_result(kNet, queried, tier::crypto::ByteSpan())
               .has_value(),
          "empty result rejected");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
