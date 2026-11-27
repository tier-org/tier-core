#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

#include "envelope.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::agent::decode;
using tier::agent::encode;
using tier::agent::Envelope;
using tier::agent::kMaxKeyLen;
using tier::agent::kMaxSamples;
using tier::agent::kMaxValueLen;
using tier::agent::Kind;
using tier::agent::Sample;
using tier::agent::split;

}  // namespace

int main() {
  // Round-trip a mixed batch.
  Envelope env;
  env.seq = 0x0102030405060708ULL;
  env.ts_unix = 1731000000;
  env.samples.push_back({Kind::gauge, "cpu.load", "0.42"});
  env.samples.push_back({Kind::gauge, "mem.used_mb", "2048"});
  env.samples.push_back({Kind::event, "unit.sshd", "activating->active"});
  env.samples.push_back({Kind::gauge, "", ""});  // empty key/value is legal

  const auto wire = encode(env);
  check(wire.has_value(), "valid envelope encodes");
  if (!wire) return 1;
  const auto back = decode(wire->data(), wire->size());
  check(back.has_value(), "round-trip decodes");
  if (back) {
    check(back->seq == env.seq, "seq preserved");
    check(back->ts_unix == env.ts_unix, "ts preserved");
    check(back->samples.size() == env.samples.size(), "sample count preserved");
    bool same = back->samples.size() == env.samples.size();
    for (std::size_t i = 0; same && i < env.samples.size(); ++i) {
      same = back->samples[i].kind == env.samples[i].kind &&
             back->samples[i].key == env.samples[i].key &&
             back->samples[i].value == env.samples[i].value;
    }
    check(same, "every sample round-trips (kind/key/value)");
  }

  // Empty batch.
  {
    Envelope e;
    e.seq = 7;
    const auto w = encode(e);
    const auto d = w ? decode(w->data(), w->size()) : std::nullopt;
    check(d && d->samples.empty() && d->seq == 7, "empty batch round-trips");
  }

  // A large value within the decoder's bounds.
  {
    Envelope e;
    e.samples.push_back({Kind::event, "blob", std::string(50000, 'x')});
    const auto w = encode(e);
    const auto d = w ? decode(w->data(), w->size()) : std::nullopt;
    check(d && d->samples.size() == 1 && d->samples[0].value.size() == 50000,
          "large value round-trips");
  }

  // Rejections: truncation at every prefix, trailing byte, bad magic/version.
  {
    const auto encoded = encode(env);
    if (!encoded) return 1;
    const auto w = *encoded;
    bool any_accepted_truncated = false;
    for (std::size_t cut = 0; cut < w.size(); ++cut) {
      if (decode(w.data(), cut).has_value()) any_accepted_truncated = true;
    }
    check(!any_accepted_truncated, "no truncation decodes");

    auto trailing = w;
    trailing.push_back(0);
    check(!decode(trailing.data(), trailing.size()).has_value(),
          "trailing byte rejected");

    auto bad_magic = w;
    bad_magic[0] = 'X';
    check(!decode(bad_magic.data(), bad_magic.size()).has_value(),
          "bad magic rejected");

    auto bad_ver = w;
    bad_ver[2] = 9;
    check(!decode(bad_ver.data(), bad_ver.size()).has_value(),
          "bad version rejected");

    check(!decode(nullptr, 0).has_value(), "empty input rejected");
  }

  // An unknown kind byte is rejected.
  {
    Envelope e;
    e.samples.push_back({Kind::gauge, "k", "v"});
    const auto encoded = encode(e);
    if (!encoded) return 1;
    auto w = *encoded;
    // kind byte sits right after the 3-byte header + 8 seq + 8 ts + 2 count.
    w[3 + 8 + 8 + 2] = 0x7F;
    check(!decode(w.data(), w.size()).has_value(), "unknown kind rejected");
  }

  // The encoder must refuse anything the decoder would reject.
  {
    Envelope e;
    e.samples.push_back({Kind::event, "k", std::string(kMaxValueLen + 1, 'x')});
    check(!encode(e).has_value(), "oversize value rejected by encoder");

    Envelope k;
    k.samples.push_back({Kind::gauge, std::string(kMaxKeyLen + 1, 'k'), "v"});
    check(!encode(k).has_value(), "oversize key rejected by encoder");

    Envelope many;
    for (std::size_t i = 0; i <= kMaxSamples; ++i) {
      many.samples.push_back({Kind::gauge, std::to_string(i), "v"});
    }
    check(!encode(many).has_value(), "oversize sample count rejected by encoder");
  }

  // A batch larger than the transport budget is split, not dropped.
  {
    Envelope e;
    e.seq = 3;
    e.ts_unix = 77;
    for (int i = 0; i < 10; ++i) {
      e.samples.push_back(
          {Kind::gauge, "k" + std::to_string(i), std::string(100, 'v')});
    }
    std::size_t dropped = 99;
    const auto parts = split(e, 500, dropped);
    check(dropped == 0, "split drops no shippable samples");
    check(parts.size() > 1, "split produces several envelopes");
    std::size_t total = 0;
    for (const auto& part : parts) {
      check(part.seq == 3 && part.ts_unix == 77, "split keeps seq/ts");
      const auto w = encode(part);
      check(w.has_value() && w->size() <= 500, "split parts fit the budget");
      total += part.samples.size();
    }
    check(total == e.samples.size(), "split preserves every sample");

    Envelope big;
    big.samples.push_back({Kind::event, "k", std::string(1000, 'v')});
    dropped = 0;
    const auto none = split(big, 100, dropped);
    check(none.empty() && dropped == 1, "unsendable sample is reported");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
