#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/crypto/primitives.hpp"

// NAT hole-punch signaling (see docs/communicator.md, M-NAT). These are the
// hole_punch_request / hole_punch_signal control frames, relayed by a
// communicator to coordinate a simultaneous open between two NAT'd peers. They
// carry only ids and candidate addresses - no crypto, no application data.
namespace tier::msg {

using Byte = tier::crypto::Byte;
using ByteSpan = tier::crypto::ByteSpan;

// A punch is a single round: the initiator asks, the target responds. A respond
// is terminal (no further reply), so there is no ping-pong.
enum class PunchPhase : std::uint8_t {
  initiate = 0,
  respond = 1,
};

[[nodiscard]] bool is_known_punch_phase(std::uint8_t v) noexcept;

// client -> communicator: coordinate a punch toward `target`, carrying my
// candidate addresses. The communicator reads the originator from the
// connection, so it is not a field here.
[[nodiscard]] std::vector<Byte> make_hole_punch_request(
    const tier::core::PeerId& target, PunchPhase phase,
    const std::vector<std::string>& addresses);

struct HolePunchRequest {
  tier::core::PeerId target{};
  PunchPhase phase{};
  std::vector<std::string> addresses;
};

[[nodiscard]] std::optional<HolePunchRequest> open_hole_punch_request(
    ByteSpan message);

// communicator -> client: a relayed punch request from `origin`, carrying the
// origin's candidate addresses.
[[nodiscard]] std::vector<Byte> make_hole_punch_signal(
    const tier::core::PeerId& origin, PunchPhase phase,
    const std::vector<std::string>& addresses);

struct HolePunchSignal {
  tier::core::PeerId origin{};
  PunchPhase phase{};
  std::vector<std::string> addresses;
};

[[nodiscard]] std::optional<HolePunchSignal> open_hole_punch_signal(
    ByteSpan message);

}  // namespace tier::msg
