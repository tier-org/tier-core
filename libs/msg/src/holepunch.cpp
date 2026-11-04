#include "tier/msg/holepunch.hpp"

#include <cstring>

#include "tier/core/control.hpp"

namespace tier::msg {
namespace {

using tier::crypto::Byte;

constexpr std::uint8_t kRequestType =
    static_cast<std::uint8_t>(tier::core::ControlType::hole_punch_request);
constexpr std::uint8_t kSignalType =
    static_cast<std::uint8_t>(tier::core::ControlType::hole_punch_signal);

void put_u16(std::vector<Byte>& out, std::uint16_t v) {
  out.push_back(static_cast<Byte>(v >> 8));
  out.push_back(static_cast<Byte>(v & 0xFF));
}

void put_bytes(std::vector<Byte>& out, ByteSpan b) {
  out.insert(out.end(), b.begin(), b.end());
}

void put_addresses(std::vector<Byte>& out, const std::vector<std::string>& addrs) {
  const std::size_t n = addrs.size() > tier::core::kMaxAddressesPerPeer
                            ? tier::core::kMaxAddressesPerPeer
                            : addrs.size();
  out.push_back(static_cast<Byte>(n));
  for (std::size_t i = 0; i < n; ++i) {
    const std::string& a = addrs[i];
    const auto len = static_cast<std::uint16_t>(
        a.size() > tier::core::kMaxAddressLen ? tier::core::kMaxAddressLen
                                              : a.size());
    put_u16(out, len);
    out.insert(out.end(), a.begin(), a.begin() + len);
  }
}

class Reader {
 public:
  explicit Reader(ByteSpan in) : in_(in) {}
  bool take(std::size_t n, ByteSpan& out) {
    if (pos_ > in_.size() || n > in_.size() - pos_) return false;
    out = in_.subspan(pos_, n);
    pos_ += n;
    return true;
  }
  bool take_u8(std::uint8_t& v) {
    ByteSpan s;
    if (!take(1, s)) return false;
    v = s[0];
    return true;
  }
  bool take_u16(std::uint16_t& v) {
    ByteSpan s;
    if (!take(2, s)) return false;
    v = static_cast<std::uint16_t>((s[0] << 8) | s[1]);
    return true;
  }
  [[nodiscard]] bool done() const { return pos_ == in_.size(); }

 private:
  ByteSpan in_;
  std::size_t pos_ = 0;
};

// Parse [id:32][phase:1][addr_count:1][ (len:2 + addr) ... ] after the type tag.
bool parse_body(Reader& r, tier::core::PeerId& id, PunchPhase& phase,
                std::vector<std::string>& addrs) {
  ByteSpan idb;
  if (!r.take(id.size(), idb)) return false;
  std::memcpy(id.data(), idb.data(), id.size());

  std::uint8_t phase_byte = 0;
  if (!r.take_u8(phase_byte) || !is_known_punch_phase(phase_byte)) return false;
  phase = static_cast<PunchPhase>(phase_byte);

  std::uint8_t count = 0;
  if (!r.take_u8(count) || count > tier::core::kMaxAddressesPerPeer) return false;
  for (std::uint8_t i = 0; i < count; ++i) {
    std::uint16_t len = 0;
    ByteSpan a;
    if (!r.take_u16(len) || len > tier::core::kMaxAddressLen || !r.take(len, a)) {
      return false;
    }
    addrs.emplace_back(reinterpret_cast<const char*>(a.data()), a.size());
  }
  return r.done();
}

}  // namespace

bool is_known_punch_phase(std::uint8_t v) noexcept {
  return v == static_cast<std::uint8_t>(PunchPhase::initiate) ||
         v == static_cast<std::uint8_t>(PunchPhase::respond);
}

std::vector<Byte> make_hole_punch_request(const tier::core::PeerId& target,
                                          PunchPhase phase,
                                          const std::vector<std::string>& addresses) {
  std::vector<Byte> out;
  out.push_back(kRequestType);
  put_bytes(out, ByteSpan(target.data(), target.size()));
  out.push_back(static_cast<Byte>(phase));
  put_addresses(out, addresses);
  return out;
}

std::optional<HolePunchRequest> open_hole_punch_request(ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kRequestType) return std::nullopt;
  HolePunchRequest req;
  if (!parse_body(r, req.target, req.phase, req.addresses)) return std::nullopt;
  return req;
}

std::vector<Byte> make_hole_punch_signal(const tier::core::PeerId& origin,
                                         PunchPhase phase,
                                         const std::vector<std::string>& addresses) {
  std::vector<Byte> out;
  out.push_back(kSignalType);
  put_bytes(out, ByteSpan(origin.data(), origin.size()));
  out.push_back(static_cast<Byte>(phase));
  put_addresses(out, addresses);
  return out;
}

std::optional<HolePunchSignal> open_hole_punch_signal(ByteSpan message) {
  Reader r(message);
  std::uint8_t type = 0;
  if (!r.take_u8(type) || type != kSignalType) return std::nullopt;
  HolePunchSignal sig;
  if (!parse_body(r, sig.origin, sig.phase, sig.addresses)) return std::nullopt;
  return sig;
}

}  // namespace tier::msg
