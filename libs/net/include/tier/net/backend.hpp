#pragma once

#include <string_view>

namespace tier::net {

// Version string of the vendored ngtcp2 transport library. Exposed mainly so a
// build can prove the QUIC stack (core + OpenSSL crypto backend) is linked;
// also useful for diagnostics.
[[nodiscard]] std::string_view quic_library_version() noexcept;

}  // namespace tier::net
