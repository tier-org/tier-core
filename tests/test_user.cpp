// Tests for the user-identity layer (tier::msg user): device credential
// mint/verify, the user envelope, and the security property that the
// authenticated sender user id cannot be forged by tampering.
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/user.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::crypto::Byte;

tier::core::PeerId device_id_of(const tier::crypto::NodeIdentity& id) {
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
  const auto user = tier::crypto::NodeIdentity::generate();
  const auto device = tier::crypto::NodeIdentity::generate();
  const auto other_device = tier::crypto::NodeIdentity::generate();
  const auto other_user = tier::crypto::NodeIdentity::generate();
  const auto device_id = device_id_of(device);
  const std::uint64_t expiry = 2000;

  const auto cred =
      tier::msg::make_device_credential(user, kNet, device_id, expiry);

  // Credential verifies for the right (user, device, network) before expiry.
  check(tier::msg::verify_device_credential(kNet, user.public_key(), device_id,
                                            /*now=*/1000, sp(cred)),
        "credential verifies for the authorized device");
  check(!tier::msg::verify_device_credential(kNet, user.public_key(), device_id,
                                             /*now=*/2000, sp(cred)),
        "credential rejected at expiry");
  check(!tier::msg::verify_device_credential(kNet, user.public_key(), device_id,
                                             /*now=*/3000, sp(cred)),
        "credential rejected after expiry");
  check(!tier::msg::verify_device_credential("testnet", user.public_key(),
                                             device_id, 1000, sp(cred)),
        "credential rejected under a different network");
  check(!tier::msg::verify_device_credential(
            kNet, user.public_key(), device_id_of(other_device), 1000, sp(cred)),
        "credential does not authorize a different device");
  check(!tier::msg::verify_device_credential(kNet, other_user.public_key(),
                                             device_id, 1000, sp(cred)),
        "credential does not verify under a different user key");

  // Every single-byte flip of the credential fails to verify.
  {
    int accepted = 0;
    for (std::size_t i = 0; i < cred.size(); ++i) {
      for (int bit = 0; bit < 8; ++bit) {
        auto bad = cred;
        bad[i] = static_cast<Byte>(bad[i] ^ (1U << bit));
        if (tier::msg::verify_device_credential(kNet, user.public_key(),
                                                device_id, 1000, sp(bad))) {
          ++accepted;
        }
      }
    }
    check(accepted == 0, "no single-byte flip of a credential verifies");
  }

  // User envelope round-trip: inner payload, authenticated sender user id, and
  // the recipient user id (which local user the receiver routes to).
  const std::string text = "hello from a user";
  const std::vector<Byte> inner(text.begin(), text.end());
  const auto recipient_user = device_id_of(other_device);  // any 32-byte id
  const auto envelope = tier::msg::make_user_envelope(user.public_key(), sp(cred),
                                                      recipient_user, sp(inner));

  {
    const auto opened =
        tier::msg::open_user_envelope(kNet, device_id, /*now=*/1000, sp(envelope));
    check(opened.has_value(), "envelope opens for the authorized device");
    if (opened) {
      check(opened->sender_user_id == tier::msg::user_id_of(user.public_key()),
            "sender user id is the user key hash");
      check(opened->recipient_user_id == recipient_user,
            "recipient user id recovered");
      check(opened->plaintext == inner, "inner plaintext recovered");
    }
  }

  // Opened against the wrong device id (the credential does not bind it): fails.
  check(!tier::msg::open_user_envelope(kNet, device_id_of(other_device), 1000,
                                       sp(envelope))
             .has_value(),
        "envelope does not authenticate for a device the credential omits");

  // Security property: no single-byte flip of the envelope yields a *different*
  // authenticated sender user id. (Flips inside the inner payload may still open
  // with the same user - the transport AEAD protects the inner bytes, not this
  // layer - but the sender's user identity must be unforgeable here.)
  {
    const auto real = tier::msg::user_id_of(user.public_key());
    int forged = 0;
    for (std::size_t i = 0; i < envelope.size(); ++i) {
      for (int bit = 0; bit < 8; ++bit) {
        auto bad = envelope;
        bad[i] = static_cast<Byte>(bad[i] ^ (1U << bit));
        const auto opened =
            tier::msg::open_user_envelope(kNet, device_id, 1000, sp(bad));
        if (opened && opened->sender_user_id != real) {
          ++forged;
        }
      }
    }
    check(forged == 0, "no byte flip forges a different sender user id");
  }

  // Empty / junk never crashes and is rejected.
  check(!tier::msg::open_user_envelope(kNet, device_id, 1000,
                                       tier::crypto::ByteSpan())
             .has_value(),
        "empty envelope rejected");
  check(!tier::msg::verify_device_credential(kNet, user.public_key(), device_id,
                                             1000, tier::crypto::ByteSpan()),
        "empty credential rejected");

  // user_deregister codec: round-trips the user key and credential, and is
  // distinct from a register frame (the type byte differs, so neither parser
  // accepts the other's frame).
  {
    const auto dereg =
        tier::msg::make_user_deregister(user.public_key(), sp(cred), /*issued=*/7);
    const auto opened = tier::msg::open_user_deregister(sp(dereg));
    check(opened.has_value(), "deregister frame parses");
    if (opened) {
      check(opened->user_pub == user.public_key(),
            "deregister carries the user key");
      check(opened->credential == cred, "deregister carries the credential");
    }
    check(!tier::msg::open_user_register(sp(dereg)).has_value(),
          "a register parser rejects a deregister frame");
    const auto reg = tier::msg::make_user_register(user.public_key(), sp(cred),
                                                   /*issued=*/7, /*expiry=*/99);
    check(!tier::msg::open_user_deregister(sp(reg)).has_value(),
          "a deregister parser rejects a register frame");
    check(!tier::msg::open_user_deregister(tier::crypto::ByteSpan()).has_value(),
          "empty deregister rejected");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
