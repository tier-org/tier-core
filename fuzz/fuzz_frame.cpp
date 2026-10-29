#include <cstddef>
#include <cstdint>

// Placeholder libFuzzer target. Once the wire-frame decoder exists this will
// feed it the untrusted bytes; for now it just exercises the build wiring.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static_cast<void>(data);
  static_cast<void>(size);
  return 0;
}
