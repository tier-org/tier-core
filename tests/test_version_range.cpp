#include <cstdio>

#include "tier/core/version_range.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

bool admits(const char* spec, const char* version) {
  const auto r = tier::core::parse_version_range(spec);
  return r && tier::core::version_admitted(*r, version);
}

}  // namespace

int main() {
  using tier::core::parse_version_range;

  // The pessimistic "pin the minor" window: 1.4.x in, 1.5.0 out, 1.3.x out.
  check(admits("1.4.0,1.5.0", "1.4.0"), "min is inclusive");
  check(admits("1.4.0,1.5.0", "1.4.3"), "a patch inside the window is admitted");
  check(!admits("1.4.0,1.5.0", "1.5.0"), "max is exclusive");
  check(!admits("1.4.0,1.5.0", "1.3.9"), "below min is refused");
  check(!admits("1.4.0,1.5.0", "2.0.0"), "well above the window is refused");

  // Open bounds.
  check(admits("1.4.0,", "9.9.9"), "open upper bound admits anything >= min");
  check(!admits("1.4.0,", "1.3.0"), "open upper bound still enforces min");
  check(admits(",2.0.0", "0.0.1"), "open lower bound admits anything < max");
  check(!admits(",2.0.0", "2.0.0"), "open lower bound still enforces max");

  // Unconstrained: empty and "," admit everything.
  {
    const auto a = parse_version_range("");
    const auto b = parse_version_range(",");
    check(a && a->unconstrained(), "empty spec is unconstrained");
    check(b && b->unconstrained(), "lone comma is unconstrained");
    check(a && tier::core::version_admitted(*a, "123.4.5"),
          "unconstrained admits any version");
  }

  // Whitespace around bounds is tolerated.
  check(admits(" 1.4.0 , 1.5.0 ", "1.4.2"), "bounds are trimmed");

  // Malformed specs are rejected.
  const char* bad[] = {"1.4.0",         "1.4.0-1.5.0", "1.4.0,1.5.0,2.0.0",
                       "x,1.5.0",        "1.4.0,y",     "1.5.0,1.4.0",
                       "1.4.0,1.4.0"};
  bool all_bad = true;
  for (const char* s : bad) {
    if (parse_version_range(s).has_value()) {
      std::fprintf(stderr, "FAIL: range '%s' should not parse\n", s);
      all_bad = false;
    }
  }
  check(all_bad, "malformed / empty-window ranges are rejected");

  // Lenient admission: an unknown or unparseable version is admitted even under
  // a constraint (a peer too old to advertise one must not be partitioned off).
  {
    const auto r = parse_version_range("1.4.0,1.5.0");
    check(r && tier::core::version_admitted(*r, ""),
          "empty version is admitted leniently");
    check(r && tier::core::version_admitted(*r, "not-a-version"),
          "unparseable version is admitted leniently");
  }

  // No network is pinned yet: every network resolves unconstrained.
  check(tier::core::network_version_range("mainnet").unconstrained(),
        "mainnet is unconstrained until governance pins it");
  check(tier::core::network_version_range("testnet").unconstrained(),
        "testnet is unconstrained until governance pins it");
  check(tier::core::network_version_range("some-private-net").unconstrained(),
        "a network with no baked file is unconstrained");

  // Build gate: every baked networks/ file must have a valid name and a
  // parseable version_range, or this fails and blocks the release.
  {
    std::string err;
    check(tier::core::validate_baked_networks(&err),
          err.empty() ? "baked networks table is valid" : err.c_str());

    const auto all = tier::core::baked_networks();
    bool has_mainnet = false;
    bool has_testnet = false;
    for (const auto& n : all) {
      has_mainnet = has_mainnet || n.name == "mainnet";
      has_testnet = has_testnet || n.name == "testnet";
    }
    check(has_mainnet, "mainnet is a baked network");
    check(has_testnet, "testnet is a baked network");
  }

  // Rendering for logs.
  check(tier::core::to_string(*parse_version_range("1.4.0,1.5.0")) ==
            "[1.4.0, 1.5.0)",
        "closed range renders");
  check(tier::core::to_string(*parse_version_range("1.4.0,")) ==
            "[1.4.0, +inf)",
        "open upper bound renders");
  check(tier::core::to_string(*parse_version_range("")) == "unconstrained",
        "unconstrained renders");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
