#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/core/membership.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/user.hpp"

// The user-identity decoders parse bytes a remote peer (or a relaying
// communicator) sent, so they must never crash or read out of bounds on any
// input. Each input is fed to the credential verifier, the user envelope opener,
// and all three directory frame parsers, with fixed ids.
namespace {

tier::core::PeerId fixed_id(std::uint8_t tag) {
  tier::core::PeerId p{};
  for (auto& b : p) b = tag;
  return p;
}

const tier::crypto::Ed25519PublicKey& user_pub() {
  static const auto id = tier::crypto::NodeIdentity::generate();
  return id.public_key();
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> in(data, size);
  static_cast<void>(tier::msg::verify_device_credential(
      "mainnet", user_pub(), fixed_id(0x11), /*now=*/1000, in));
  static_cast<void>(tier::msg::open_user_envelope("mainnet", fixed_id(0x11),
                                                  /*now=*/1000, in));
  static_cast<void>(tier::msg::open_user_register(in));
  static_cast<void>(tier::msg::open_user_lookup(in));
  static_cast<void>(tier::msg::open_user_result(fixed_id(0x22), in));
  return 0;
}
