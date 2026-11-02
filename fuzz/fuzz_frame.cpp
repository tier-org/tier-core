#include <cstddef>
#include <cstdint>
#include <span>

#include "tier/net/framing.hpp"

// The wire-frame decoder reads a 4-byte length prefix straight from bytes an
// untrusted peer sent, so it must never read out of bounds or trust a length
// past the cap, whatever the input. Drive it the way the receive loop does:
// peel whole frames off the front until the buffer is incomplete, oversize, or
// empty.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  std::span<const std::uint8_t> buf(data, size);
  for (;;) {
    const auto f = tier::net::framing::take_frame(buf);
    if (f.status != tier::net::framing::FrameStatus::ok) {
      break;
    }
    // Touch the reported payload window to catch an off-by-one in the offsets.
    volatile std::uint8_t sink = 0;
    for (std::size_t i = 0; i < f.payload_len; ++i) {
      sink = static_cast<std::uint8_t>(sink ^ buf[f.payload_off + i]);
    }
    static_cast<void>(sink);
    buf = buf.subspan(f.consumed);
  }
  return 0;
}
