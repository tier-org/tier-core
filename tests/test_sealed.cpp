// Tests for the sealed-message layer (tier::msg): round-trip of all three
// suites, sender authentication, tamper rejection (any single-byte flip),
// wrong recipient/sender/network, malformed input, and the enc_keys announce.
#include <array>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/sealed.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::crypto::Byte;
using tier::msg::Suite;

tier::core::PeerId id_of(const tier::crypto::NodeIdentity& id) {
  const auto& pub = id.public_key();
  const auto d = tier::crypto::sha256(tier::crypto::ByteSpan(pub.data(), pub.size()));
  tier::core::PeerId p{};
  for (std::size_t i = 0; i < p.size(); ++i) p[i] = d[i];
  return p;
}

tier::msg::Recipient recipient_of(const tier::crypto::NodeIdentity& id) {
  tier::msg::Recipient r;
  r.id = id_of(id);
  r.keys.x25519 = id.x25519_identity_key().public_key;
  r.keys.mlkem = id.mlkem768_identity_key().public_key;
  return r;
}

tier::crypto::ByteSpan sp(const std::vector<Byte>& v) {
  return tier::crypto::ByteSpan(v.data(), v.size());
}

const char* kNet = "mainnet";

void test_roundtrip(Suite suite, const char* name) {
  const auto alice = tier::crypto::NodeIdentity::generate();
  const auto bob = tier::crypto::NodeIdentity::generate();
  const tier::msg::Recipient bob_r = recipient_of(bob);

  const std::string text = "hello bob, this is a secret for suite ";
  const std::vector<Byte> pt(text.begin(), text.end());

  const auto msg = tier::msg::seal(alice, kNet, suite, bob_r, sp(pt));

  const auto opened = tier::msg::open(bob, kNet, alice.public_key(), sp(msg));
  check(opened.has_value(), name);
  if (opened) {
    check(opened->plaintext == pt, "opened plaintext matches");
    check(opened->suite == suite, "opened suite matches");
    check(opened->sender_id == id_of(alice), "opened sender id matches");
  }

  // Any single-byte flip anywhere must make open fail (integrity + auth).
  bool all_flips_fail = true;
  for (std::size_t i = 0; i < msg.size(); ++i) {
    auto bad = msg;
    bad[i] ^= 0x01;
    if (tier::msg::open(bob, kNet, alice.public_key(), sp(bad)).has_value()) {
      all_flips_fail = false;
      break;
    }
  }
  check(all_flips_fail, "every single-byte flip is rejected");

  // Wrong recipient: a third party cannot open it.
  const auto carol = tier::crypto::NodeIdentity::generate();
  check(!tier::msg::open(carol, kNet, alice.public_key(), sp(msg)).has_value(),
        "wrong recipient cannot open");

  // Wrong claimed sender: verifying against the wrong identity key fails.
  check(!tier::msg::open(bob, kNet, carol.public_key(), sp(msg)).has_value(),
        "wrong sender identity rejected");

  // Wrong network: the header is bound to the network, so the signature fails.
  check(!tier::msg::open(bob, "testnet", alice.public_key(), sp(msg)).has_value(),
        "wrong network rejected");
}

void test_truncation() {
  const auto alice = tier::crypto::NodeIdentity::generate();
  const auto bob = tier::crypto::NodeIdentity::generate();
  const std::vector<Byte> pt = {1, 2, 3, 4};
  const auto msg = tier::msg::seal(alice, kNet, Suite::hybrid, recipient_of(bob), sp(pt));

  // Every prefix (including empty) is rejected without crashing.
  bool ok = true;
  for (std::size_t n = 0; n < msg.size(); ++n) {
    std::vector<Byte> prefix(msg.begin(), msg.begin() + static_cast<long>(n));
    if (tier::msg::open(bob, kNet, alice.public_key(), sp(prefix)).has_value()) {
      ok = false;
      break;
    }
  }
  check(ok, "truncated messages rejected");

  // Trailing garbage is rejected.
  auto extended = msg;
  extended.push_back(0x00);
  check(!tier::msg::open(bob, kNet, alice.public_key(), sp(extended)).has_value(),
        "trailing byte rejected");

  // An unknown suite byte is rejected.
  auto bad_suite = msg;
  bad_suite[1] = 0x7F;
  check(!tier::msg::open(bob, kNet, alice.public_key(), sp(bad_suite)).has_value(),
        "unknown suite rejected");

  // Empty and one-byte inputs.
  check(!tier::msg::open(bob, kNet, alice.public_key(), tier::crypto::ByteSpan()).has_value(),
        "empty input rejected");
}

void test_empty_and_oversize() {
  const auto alice = tier::crypto::NodeIdentity::generate();
  const auto bob = tier::crypto::NodeIdentity::generate();

  // Empty plaintext round-trips.
  const auto msg = tier::msg::seal(alice, kNet, Suite::classical, recipient_of(bob),
                                   tier::crypto::ByteSpan());
  const auto opened = tier::msg::open(bob, kNet, alice.public_key(), sp(msg));
  check(opened.has_value() && opened->plaintext.empty(), "empty plaintext round-trips");

  // Oversize plaintext throws.
  std::vector<Byte> big(tier::msg::kMaxSealedPlaintext + 1, 0x41);
  bool threw = false;
  try {
    const auto ignored =
        tier::msg::seal(alice, kNet, Suite::classical, recipient_of(bob), sp(big));
    (void)ignored;
  } catch (const std::length_error&) {
    threw = true;
  }
  check(threw, "oversize plaintext throws length_error");
}

void test_determinism() {
  // Two identities from the same seed produce the same encryption keys, and
  // repeated derivation is stable.
  tier::crypto::Ed25519Seed seed{};
  for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<Byte>(i + 5);
  const auto a = tier::crypto::NodeIdentity::from_seed(
      tier::crypto::ByteSpan(seed.data(), seed.size()));
  const auto b = tier::crypto::NodeIdentity::from_seed(
      tier::crypto::ByteSpan(seed.data(), seed.size()));
  check(a.x25519_identity_key().public_key == b.x25519_identity_key().public_key,
        "x25519 identity key deterministic in seed");
  check(a.mlkem768_identity_key().public_key == b.mlkem768_identity_key().public_key,
        "ml-kem identity key deterministic in seed");
  check(a.x25519_identity_key().public_key == a.x25519_identity_key().public_key,
        "x25519 derivation stable across calls");
}

void test_enc_keys_announce() {
  const auto node = tier::crypto::NodeIdentity::generate();
  const auto announce = tier::msg::make_enc_keys_announce(node, kNet);

  const auto keys = tier::msg::open_enc_keys_announce(kNet, node.public_key(), sp(announce));
  check(keys.has_value(), "enc_keys announce verifies");
  if (keys) {
    check(keys->x25519 == node.x25519_identity_key().public_key, "announce x25519 matches");
    check(keys->mlkem == node.mlkem768_identity_key().public_key, "announce mlkem matches");
  }

  // Wrong identity key (not the announcer) -> reject.
  const auto other = tier::crypto::NodeIdentity::generate();
  check(!tier::msg::open_enc_keys_announce(kNet, other.public_key(), sp(announce)).has_value(),
        "announce rejects wrong identity");

  // Wrong network -> reject (bound into the signed input).
  check(!tier::msg::open_enc_keys_announce("testnet", node.public_key(), sp(announce)).has_value(),
        "announce rejects wrong network");

  // Any single-byte flip -> reject.
  bool ok = true;
  for (std::size_t i = 0; i < announce.size(); ++i) {
    auto bad = announce;
    bad[i] ^= 0x01;
    if (tier::msg::open_enc_keys_announce(kNet, node.public_key(), sp(bad)).has_value()) {
      ok = false;
      break;
    }
  }
  check(ok, "announce rejects every single-byte flip");

  // Truncations -> reject, no crash.
  bool trunc_ok = true;
  for (std::size_t n = 0; n < announce.size(); ++n) {
    std::vector<Byte> prefix(announce.begin(), announce.begin() + static_cast<long>(n));
    if (tier::msg::open_enc_keys_announce(kNet, node.public_key(), sp(prefix)).has_value()) {
      trunc_ok = false;
      break;
    }
  }
  check(trunc_ok, "announce truncations rejected");
}

}  // namespace

int main() {
  test_roundtrip(Suite::classical, "classical round-trip");
  test_roundtrip(Suite::hybrid, "hybrid round-trip");
  test_roundtrip(Suite::pq, "pq round-trip");
  test_truncation();
  test_empty_and_oversize();
  test_determinism();
  test_enc_keys_announce();
  if (g_failures == 0) {
    std::puts("sealed messages: all checks passed");
  }
  return g_failures == 0 ? 0 : 1;
}
