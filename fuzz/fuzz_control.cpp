#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/core/control.hpp"

// The SWIM probe decoders (ping/ack/ping_req) parse bytes a remote peer sent, so
// each must never crash or read out of bounds, whatever the input. One entry
// point feeds the same bytes to every control decoder.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> in(data, size);
  static_cast<void>(tier::core::peek_control_type(in));
  static_cast<void>(tier::core::decode_ping(in));
  static_cast<void>(tier::core::decode_ack(in));
  static_cast<void>(tier::core::decode_ping_req(in));
  static_cast<void>(tier::core::decode_observed_addr(in));
  return 0;
}
