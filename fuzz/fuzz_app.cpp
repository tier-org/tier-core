#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/app/frame.hpp"
#include "tier/core/admin.hpp"

// The application frame decoder parses the inner plaintext of a user envelope,
// which a remote peer controls, so it must never crash or read out of bounds on
// any input. The admin stream-event decoder parses the daemon-to-client push
// records; fuzz it too since a client frames them from the socket. Neither may
// fault on arbitrary bytes.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::span<const std::uint8_t> in(data, size);
  static_cast<void>(tier::app::decode_app_frame(in));
  static_cast<void>(tier::core::decode_admin_stream_event(in));
  return 0;
}
