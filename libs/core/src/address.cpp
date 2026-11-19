#include "tier/core/address.hpp"

#include <array>
#include <cctype>
#include <cstdint>
#include <vector>

// bech32m (BIP350) over a 32-byte id, with the human-readable prefix "tier"
// folded into the checksum but elided from the printed string. See address.hpp
// for the scheme and its guarantees. This is a straight port of the reference
// bech32 routines (polymod, hrp expansion, bit regrouping) with the bech32m
// final constant and no segwit witness-version symbol.

namespace tier::core {
namespace {

constexpr char kCharset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr std::uint32_t kBech32mConst = 0x2bc830a3U;
constexpr char kHrp[] = "tier";
constexpr std::size_t kDataSymbols = 52;    // ceil(32 bytes * 8 / 5)
constexpr std::size_t kChecksumSymbols = 6;
constexpr std::size_t kBodyLen = kDataSymbols + kChecksumSymbols;  // 58

std::uint32_t polymod(const std::vector<std::uint8_t>& values) {
  static constexpr std::uint32_t kGen[5] = {0x3b6a57b2U, 0x26508e6dU,
                                            0x1ea119faU, 0x3d4233ddU,
                                            0x2a1462b3U};
  std::uint32_t chk = 1;
  for (const std::uint8_t v : values) {
    const std::uint8_t top = static_cast<std::uint8_t>(chk >> 25);
    chk = ((chk & 0x01ffffffU) << 5) ^ v;
    for (int i = 0; i < 5; ++i) {
      if ((top >> i) & 1) chk ^= kGen[i];
    }
  }
  return chk;
}

// hrp_expand("tier"): high bits, a 0 separator, then low bits.
std::vector<std::uint8_t> hrp_expand() {
  std::vector<std::uint8_t> out;
  const std::string_view hrp(kHrp);
  out.reserve(hrp.size() * 2 + 1);
  for (const char c : hrp) out.push_back(static_cast<std::uint8_t>(c) >> 5);
  out.push_back(0);
  for (const char c : hrp) out.push_back(static_cast<std::uint8_t>(c) & 31);
  return out;
}

int charset_index(char c) {
  for (int i = 0; i < 32; ++i) {
    if (kCharset[i] == c) return i;
  }
  return -1;
}

// BIP173 bit regrouping. With pad, emits a final partial group zero-padded
// (encode); without pad, requires no leftover bits and zero padding (decode).
bool convertbits(const std::vector<std::uint8_t>& in, int from_bits, int to_bits,
                 bool pad, std::vector<std::uint8_t>& out) {
  std::uint32_t acc = 0;
  int bits = 0;
  const std::uint32_t maxv = (1U << to_bits) - 1;
  const std::uint32_t max_acc = (1U << (from_bits + to_bits - 1)) - 1;
  for (const std::uint8_t value : in) {
    acc = ((acc << from_bits) | value) & max_acc;
    bits += from_bits;
    while (bits >= to_bits) {
      bits -= to_bits;
      out.push_back(static_cast<std::uint8_t>((acc >> bits) & maxv));
    }
  }
  if (pad) {
    if (bits > 0) {
      out.push_back(static_cast<std::uint8_t>((acc << (to_bits - bits)) & maxv));
    }
  } else if (bits >= from_bits ||
             ((acc << (to_bits - bits)) & maxv) != 0) {
    return false;  // leftover full group, or non-zero padding bits
  }
  return true;
}

std::string encode_body(const PeerId& id) {
  std::vector<std::uint8_t> data5;
  convertbits(std::vector<std::uint8_t>(id.begin(), id.end()), 8, 5, true, data5);

  std::vector<std::uint8_t> values = hrp_expand();
  values.insert(values.end(), data5.begin(), data5.end());
  for (std::size_t i = 0; i < kChecksumSymbols; ++i) values.push_back(0);
  const std::uint32_t pm = polymod(values) ^ kBech32mConst;

  std::string out;
  out.reserve(kBodyLen);
  for (const std::uint8_t d : data5) out.push_back(kCharset[d]);
  for (std::size_t i = 0; i < kChecksumSymbols; ++i) {
    out.push_back(kCharset[(pm >> 5 * (5 - i)) & 31]);
  }
  return out;
}

}  // namespace

std::string address_from_id(const PeerId& id) { return encode_body(id); }

std::string address_from_id_prefixed(const PeerId& id) {
  return std::string(kHrp) + "1" + encode_body(id);
}

std::optional<PeerId> id_from_address(std::string_view address) {
  // Reject mixed case (BIP173), then normalize to lower.
  bool has_lower = false;
  bool has_upper = false;
  for (const char c : address) {
    if (c >= 'a' && c <= 'z') has_lower = true;
    if (c >= 'A' && c <= 'Z') has_upper = true;
  }
  if (has_lower && has_upper) return std::nullopt;
  std::string s;
  s.reserve(address.size());
  for (const char c : address) {
    s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }

  // Strip an optional visible "tier1" prefix. A prefix-less body is pure
  // charset, which excludes 'i' and '1', so it can never begin with "tier1" -
  // the detection is unambiguous.
  const std::string prefix = std::string(kHrp) + "1";
  if (s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0) {
    s.erase(0, prefix.size());
  }
  if (s.size() != kBodyLen) return std::nullopt;

  std::vector<std::uint8_t> values;
  values.reserve(s.size());
  for (const char c : s) {
    const int idx = charset_index(c);
    if (idx < 0) return std::nullopt;
    values.push_back(static_cast<std::uint8_t>(idx));
  }

  std::vector<std::uint8_t> checked = hrp_expand();
  checked.insert(checked.end(), values.begin(), values.end());
  if (polymod(checked) != kBech32mConst) return std::nullopt;

  const std::vector<std::uint8_t> data5(values.begin(),
                                        values.end() - kChecksumSymbols);
  std::vector<std::uint8_t> bytes;
  if (!convertbits(data5, 5, 8, false, bytes)) return std::nullopt;
  if (bytes.size() != PeerId{}.size()) return std::nullopt;
  PeerId id{};
  for (std::size_t i = 0; i < id.size(); ++i) id[i] = bytes[i];
  return id;
}

}  // namespace tier::core
