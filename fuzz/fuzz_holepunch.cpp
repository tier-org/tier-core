#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/msg/holepunch.hpp"

// The hole-punch signaling decoders parse bytes a remote peer or a relaying
// communicator sent, so they must never crash or read out of bounds on any
// input. Each input is fed to both parse paths.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> in(data, size);
  static_cast<void>(tier::msg::open_hole_punch_request(in));
  static_cast<void>(tier::msg::open_hole_punch_signal(in));
  return 0;
}
