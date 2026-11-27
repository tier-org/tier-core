#include "envelope.hpp"

#include <algorithm>
#include <utility>

namespace tier::agent {
namespace {

constexpr std::uint8_t kMagic0 = 'T';
constexpr std::uint8_t kMagic1 = 'M';
constexpr std::uint8_t kVersion = 1;

// Guard rails against a malformed or hostile message. The collector authenticates
// the sender (transport), but still must never trust sizes in the payload. The
// limits live in the header so the encoder and decoder cannot drift apart.

void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
  out.push_back(static_cast<std::uint8_t>(v >> 24));
  out.push_back(static_cast<std::uint8_t>(v >> 16));
  out.push_back(static_cast<std::uint8_t>(v >> 8));
  out.push_back(static_cast<std::uint8_t>(v));
}

void put_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    out.push_back(static_cast<std::uint8_t>(v >> shift));
  }
}

// A bounds-checked reader over the input span.
struct Reader {
  const std::uint8_t* p;
  std::size_t n;
  std::size_t at = 0;

  bool need(std::size_t k) const { return at + k <= n; }
  std::uint8_t u8() { return p[at++]; }
  std::uint16_t u16() {
    const std::uint16_t v = static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[at]) << 8) | p[at + 1]);
    at += 2;
    return v;
  }
  std::uint32_t u32() {
    std::uint32_t v = 0;
    for (int i = 0; i < 4; ++i) v = (v << 8) | p[at++];
    return v;
  }
  std::uint64_t u64() {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8) | p[at++];
    return v;
  }
};

}  // namespace

std::size_t encoded_size(const Sample& s) {
  return 1 + 2 + s.key.size() + 4 + s.value.size();
}

std::size_t encoded_size(const Envelope& e) {
  std::size_t n = 3 + 8 + 8 + 2;
  for (const Sample& s : e.samples) n += encoded_size(s);
  return n;
}

std::optional<std::vector<std::uint8_t>> encode(const Envelope& env) {
  if (env.samples.size() > kMaxSamples) return std::nullopt;
  for (const Sample& s : env.samples) {
    if (s.key.size() > kMaxKeyLen || s.value.size() > kMaxValueLen) {
      return std::nullopt;
    }
  }
  std::vector<std::uint8_t> out;
  out.push_back(kMagic0);
  out.push_back(kMagic1);
  out.push_back(kVersion);
  put_u64(out, env.seq);
  put_u64(out, env.ts_unix);
  put_u16(out, static_cast<std::uint16_t>(env.samples.size()));
  for (const Sample& s : env.samples) {
    out.push_back(static_cast<std::uint8_t>(s.kind));
    put_u16(out, static_cast<std::uint16_t>(s.key.size()));
    out.insert(out.end(), s.key.begin(), s.key.end());
    put_u32(out, static_cast<std::uint32_t>(s.value.size()));
    out.insert(out.end(), s.value.begin(), s.value.end());
  }
  return out;
}

std::vector<Envelope> split(const Envelope& env, std::size_t max_bytes,
                            std::size_t& dropped) {
  constexpr std::size_t header = 3 + 8 + 8 + 2;
  const std::size_t limit = std::min(max_bytes, kMaxEnvelopeBytes);
  dropped = 0;
  std::vector<Envelope> out;
  if (limit <= header) {
    dropped = env.samples.size();
    return out;
  }

  Envelope cur;
  cur.seq = env.seq;
  cur.ts_unix = env.ts_unix;
  std::size_t bytes = header;
  for (const Sample& s : env.samples) {
    const std::size_t size = encoded_size(s);
    if (s.key.size() > kMaxKeyLen || s.value.size() > kMaxValueLen ||
        size > limit - header) {
      ++dropped;  // unsendable even on its own
      continue;
    }
    if (!cur.samples.empty() && bytes + size > limit) {
      out.push_back(std::move(cur));
      cur = Envelope{};
      cur.seq = env.seq;
      cur.ts_unix = env.ts_unix;
      bytes = header;
    }
    cur.samples.push_back(s);
    bytes += size;
  }
  if (!cur.samples.empty()) out.push_back(std::move(cur));
  return out;
}

std::optional<Envelope> decode(const std::uint8_t* data, std::size_t n) {
  Reader r{data, n};
  if (!r.need(3) || r.u8() != kMagic0 || r.u8() != kMagic1 || r.u8() != kVersion) {
    return std::nullopt;
  }
  if (!r.need(8 + 8 + 2)) return std::nullopt;
  Envelope env;
  env.seq = r.u64();
  env.ts_unix = r.u64();
  const std::uint16_t count = r.u16();
  if (count > kMaxSamples) return std::nullopt;
  env.samples.reserve(count);
  for (std::uint16_t i = 0; i < count; ++i) {
    if (!r.need(1 + 2)) return std::nullopt;
    const std::uint8_t kind = r.u8();
    if (kind != static_cast<std::uint8_t>(Kind::gauge) &&
        kind != static_cast<std::uint8_t>(Kind::event)) {
      return std::nullopt;
    }
    const std::uint16_t klen = r.u16();
    if (klen > kMaxKeyLen || !r.need(klen)) return std::nullopt;
    Sample s;
    s.kind = static_cast<Kind>(kind);
    s.key.assign(reinterpret_cast<const char*>(r.p + r.at), klen);
    r.at += klen;
    if (!r.need(4)) return std::nullopt;
    const std::uint32_t vlen = r.u32();
    if (vlen > kMaxValueLen || !r.need(vlen)) return std::nullopt;
    s.value.assign(reinterpret_cast<const char*>(r.p + r.at), vlen);
    r.at += vlen;
    env.samples.push_back(std::move(s));
  }
  if (r.at != n) return std::nullopt;  // trailing bytes
  return env;
}

}  // namespace tier::agent
