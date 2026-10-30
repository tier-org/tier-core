#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/core/control.hpp"

// The membership control message is decoded straight from bytes a remote peer
// sent, so its decoder is a prime fuzz target: it must never crash or read out
// of bounds, whatever the input.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static_cast<void>(tier::core::decode_membership_message(
      std::span<const std::uint8_t>(data, size)));
  return 0;
}
