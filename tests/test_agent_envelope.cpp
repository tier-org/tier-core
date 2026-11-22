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
using tier::agent::Kind;
using tier::agent::Sample;

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
  const auto back = decode(wire.data(), wire.size());
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
    const auto d = decode(w.data(), w.size());
    check(d && d->samples.empty() && d->seq == 7, "empty batch round-trips");
  }

  // A large value within bounds.
  {
    Envelope e;
    e.samples.push_back({Kind::event, "blob", std::string(50000, 'x')});
    const auto w = encode(e);
    const auto d = decode(w.data(), w.size());
    check(d && d->samples.size() == 1 && d->samples[0].value.size() == 50000,
          "large value round-trips");
  }

  // Rejections: truncation at every prefix, trailing byte, bad magic/version.
  {
    const auto w = encode(env);
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
    auto w = encode(e);
    // kind byte sits right after the 3-byte header + 8 seq + 8 ts + 2 count.
    w[3 + 8 + 8 + 2] = 0x7F;
    check(!decode(w.data(), w.size()).has_value(), "unknown kind rejected");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
