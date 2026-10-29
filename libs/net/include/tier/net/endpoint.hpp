#pragma once

namespace tier::net {

// TODO: QUIC endpoint able to both listen and dial on a single UDP socket
// (required for NAT hole punching via DCUtR). Backed by ngtcp2 with aws-lc as
// the TLS/crypto backend; node identity is a self-signed certificate bound to
// the node key. Implemented in a later step.

}  // namespace tier::net
