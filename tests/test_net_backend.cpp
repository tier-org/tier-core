#include <cstdio>
#include <string_view>

#include "tier/net/backend.hpp"

int main() {
  const std::string_view version = tier::net::quic_library_version();
  if (version.empty()) {
    std::fprintf(stderr, "FAIL: empty ngtcp2 version string\n");
    return 1;
  }
  std::printf("ngtcp2 %.*s\n", static_cast<int>(version.size()), version.data());
  return 0;
}
