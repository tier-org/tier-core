#include <cctype>
#include <cstdint>
#include <cstdio>
#include <optional>
#include <string>

#include "tier/core/address.hpp"
#include "tier/core/membership.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::core::PeerId;

PeerId id_from_hex(const std::string& hex) {
  PeerId id{};
  for (std::size_t i = 0; i < id.size(); ++i) {
    id[i] = static_cast<std::uint8_t>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
  }
  return id;
}

// Known vector, computed independently from the bech32m reference routines.
const char* const kVecHex =
    "05ca62c8eff20c96a64b37062000806ffa8cd06b185798db92b35fdff45d944f";
const char* const kVecElided =
    "qh9x9j807gxfdfjtxurzqqyqdlage5rtrpte3kujkd0alazaj38snd9pcx";
// Same 52 data symbols but checksummed under a different prefix ("tiert"): a
// foreign-network address that must NOT verify here.
const char* const kForeign =
    "qh9x9j807gxfdfjtxurzqqyqdlage5rtrpte3kujkd0alazaj38sqk7gas";

}  // namespace

int main() {
  const PeerId vec = id_from_hex(kVecHex);

  // --- known vector, both forms ---
  check(tier::core::address_from_id(vec) == kVecElided,
        "elided encoding matches vector");
  check(tier::core::address_from_id(vec).size() == 58, "elided length is 58");
  check(tier::core::address_from_id_prefixed(vec) ==
            std::string("tier1") + kVecElided,
        "prefixed encoding is tier1 + body");
  check(tier::core::address_from_id_prefixed(vec).size() == 63,
        "prefixed length is 63");

  // --- decode both forms back to the id ---
  {
    const auto a = tier::core::id_from_address(kVecElided);
    const auto b = tier::core::id_from_address(std::string("tier1") + kVecElided);
    check(a && *a == vec, "elided decodes to id");
    check(b && *b == vec, "prefixed decodes to id");
  }

  // --- case handling ---
  {
    std::string upper = std::string("TIER1") + kVecElided;
    for (char& c : upper) {
      if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
    }
    const auto u = tier::core::id_from_address(upper);
    check(u && *u == vec, "all-uppercase decodes to id");
    // Mixed case is rejected. Index 5 is the first body char ('q'), a letter,
    // so upper-casing it against the lowercase "tier1" guarantees mixed case.
    std::string mixed = std::string("tier1") + kVecElided;
    mixed[5] = static_cast<char>(std::toupper(mixed[5]));
    check(!tier::core::id_from_address(mixed), "mixed case rejected");
  }

  // --- round-trip over a spread of ids ---
  for (int t = 0; t < 256; ++t) {
    PeerId id{};
    for (std::size_t i = 0; i < id.size(); ++i) {
      id[i] = static_cast<std::uint8_t>(
          (static_cast<std::size_t>(t) * 31 + i * 7) & 0xFF);
    }
    const auto back = tier::core::id_from_address(tier::core::address_from_id(id));
    check(back && *back == id, "round-trip elided");
    const auto back2 =
        tier::core::id_from_address(tier::core::address_from_id_prefixed(id));
    check(back2 && *back2 == id, "round-trip prefixed");
  }
  {
    PeerId zero{};
    PeerId ones{};
    for (auto& b : ones) b = 0xFF;
    check(tier::core::id_from_address(tier::core::address_from_id(zero)) == zero,
          "round-trip all-zero id");
    check(tier::core::id_from_address(tier::core::address_from_id(ones)) == ones,
          "round-trip all-ones id");
  }

  // --- rejections ---
  check(!tier::core::id_from_address(kForeign),
        "foreign-network (tiert) checksum rejected under tier");
  {
    // Single-character corruption fails the checksum.
    std::string bad = kVecElided;
    bad[0] = (bad[0] == 'q') ? 'p' : 'q';
    check(!tier::core::id_from_address(bad), "flipped first char rejected");
    std::string bad2 = kVecElided;
    bad2[57] = (bad2[57] == 'q') ? 'p' : 'q';
    check(!tier::core::id_from_address(bad2), "flipped checksum char rejected");
  }
  check(!tier::core::id_from_address(""), "empty string rejected");
  check(!tier::core::id_from_address(std::string(kVecElided) + "q"),
        "too long rejected");
  check(!tier::core::id_from_address(std::string(kVecElided).substr(0, 57)),
        "too short rejected");
  {
    // An out-of-charset character ('b' is not in the bech32 alphabet).
    std::string bad = kVecElided;
    bad[3] = 'b';
    check(!tier::core::id_from_address(bad), "out-of-charset char rejected");
  }

  if (g_failures != 0) {
    std::fprintf(stderr, "%d check(s) failed\n", g_failures);
    return 1;
  }
  std::puts("all address checks passed");
  return 0;
}
