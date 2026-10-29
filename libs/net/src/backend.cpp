#include "tier/net/backend.hpp"

#include <ngtcp2/ngtcp2.h>

namespace tier::net {

std::string_view quic_library_version() noexcept {
  const ngtcp2_info* const info = ngtcp2_version(0);
  if (info == nullptr || info->version_str == nullptr) {
    return {};
  }
  return std::string_view(info->version_str);
}

}  // namespace tier::net
