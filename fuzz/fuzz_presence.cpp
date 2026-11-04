#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/core/membership.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/presence.hpp"

// The presence decoders parse bytes a remote peer (or a relaying communicator)
// sent, so they must never crash or read out of bounds on any input. Each input
// is fed to all three parse paths: register, lookup, and result. A fixed
// expected id is used for the result path; the signed-record checks reject
// almost everything before any real work, so this stays fast.
namespace {

tier::core::PeerId expected_id() {
  static const tier::core::PeerId id = [] {
    const auto node = tier::crypto::NodeIdentity::generate();
    const auto& pub = node.public_key();
    const auto d = tier::crypto::sha256(tier::crypto::ByteSpan(pub.data(), pub.size()));
    tier::core::PeerId p{};
    for (std::size_t i = 0; i < p.size(); ++i) p[i] = d[i];
    return p;
  }();
  return id;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> in(data, size);
  static_cast<void>(tier::msg::open_presence_register("mainnet", in));
  static_cast<void>(tier::msg::open_presence_lookup(in));
  static_cast<void>(tier::msg::open_presence_result("mainnet", expected_id(), in));
  return 0;
}
