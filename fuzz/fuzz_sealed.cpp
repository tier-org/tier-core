#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/crypto/identity.hpp"
#include "tier/msg/sealed.hpp"

// The sealed-message and enc_keys decoders parse bytes a remote peer sent, so
// they must never crash or read out of bounds on any input. A fixed recipient
// and sender identity are built once; each input is fed to both decode paths.
// Most random inputs are rejected at the header/signature stage before any
// key-agreement work, so this stays fast.
namespace {

const tier::crypto::NodeIdentity& recipient() {
  static const tier::crypto::NodeIdentity id = tier::crypto::NodeIdentity::generate();
  return id;
}

const tier::crypto::NodeIdentity& sender() {
  static const tier::crypto::NodeIdentity id = tier::crypto::NodeIdentity::generate();
  return id;
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> in(data, size);
  static_cast<void>(tier::msg::open(recipient(), "mainnet", sender().public_key(), in));
  static_cast<void>(
      tier::msg::open_enc_keys_announce("mainnet", sender().public_key(), in));
  return 0;
}
