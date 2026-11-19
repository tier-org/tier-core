#pragma once

#include <optional>
#include <string>
#include <string_view>

#include "tier/core/membership.hpp"  // PeerId

namespace tier::core {

// Text form of a 32-byte identity id, encoded with bech32m (BIP350) under the
// implicit human-readable prefix "tier". The prefix is folded into the checksum
// but NOT printed, so the primary form is prefix-less ("elided") and looks like
// a random bech32 string; a "tier1..."-prefixed form is also available for
// display. Both carry the same bytes and decode back to the same id.
//
// The checksum catches typos and foreign-network addresses (a string built for
// another network's implicit prefix fails verification here), with a false-pass
// probability of 2^-30. It is error detection, not authentication: a well-formed
// address only means "a valid tier id string", never "a registered identity".
//
// Network-agnostic by design: the same id yields the same address on every tier
// network (mainnet, testnet, ...). Replay protection belongs in signed
// transactions (network id + recent anchor + nullifier/nonce), not in the
// address, so there is deliberately no per-network tagging here.

// 32-byte id -> 58-char elided address (52 data + 6 checksum, no visible prefix).
[[nodiscard]] std::string address_from_id(const PeerId& id);

// 32-byte id -> 63-char "tier1..." address (same bytes, visible prefix).
[[nodiscard]] std::string address_from_id_prefixed(const PeerId& id);

// Parse either form back to the id, verifying the bech32m checksum under the
// implicit "tier" prefix. Returns nullopt on any checksum/format error: a typo,
// a foreign-network address, a wrong length, an out-of-charset char, non-zero
// padding, or a mixed-case string (rejected per BIP173). Accepts all-lowercase
// or all-uppercase input.
[[nodiscard]] std::optional<PeerId> id_from_address(std::string_view address);

}  // namespace tier::core
