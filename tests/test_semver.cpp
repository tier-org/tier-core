#include <cstdio>

#include "tier/core/semver.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

bool parses(const char* s, std::uint64_t maj, std::uint64_t min,
            std::uint64_t pat, const char* pre) {
  const auto v = tier::core::parse_semver(s);
  return v && v->major == maj && v->minor == min && v->patch == pat &&
         v->prerelease == pre;
}

int cmp(const char* a, const char* b) {
  return tier::core::compare_semver(*tier::core::parse_semver(a),
                                    *tier::core::parse_semver(b));
}

}  // namespace

int main() {
  // Well-formed cores and suffixes.
  check(parses("0.2.4", 0, 2, 4, ""), "plain release parses");
  check(parses("1.4.0-rc.1", 1, 4, 0, "rc.1"), "pre-release parses");
  check(parses("1.4.0+build.7", 1, 4, 0, ""), "build metadata parsed off");
  check(parses("1.4.0-rc.1+b.2", 1, 4, 0, "rc.1"),
        "pre-release kept, build dropped");
  check(parses("10.20.30", 10, 20, 30, ""), "multi-digit components parse");

  // Malformed inputs are rejected (never crash).
  const char* bad[] = {"",       "1",     "1.2",     "1.2.3.4", "1.2.x",
                       "v1.2.3", "1.2.3-", "1.2.3+",  "1.2.3-rc..1",
                       "01.2.3-.", " 1.2.3", "1.2.3 "};
  bool all_bad = true;
  for (const char* s : bad) {
    if (tier::core::parse_semver(s).has_value()) {
      std::fprintf(stderr, "FAIL: '%s' should not parse\n", s);
      all_bad = false;
    }
  }
  check(all_bad, "malformed versions are rejected");

  // Core ordering.
  check(cmp("1.0.0", "2.0.0") < 0, "major orders");
  check(cmp("1.4.0", "1.5.0") < 0, "minor orders");
  check(cmp("1.4.1", "1.4.2") < 0, "patch orders");
  check(cmp("1.4.2", "1.4.2") == 0, "equal cores compare equal");

  // Pre-release precedence (SemVer 11): a pre-release is below its release, and
  // identifiers order per the spec.
  check(cmp("1.4.0-rc.1", "1.4.0") < 0, "pre-release below release");
  check(cmp("1.4.0-alpha", "1.4.0-beta") < 0, "pre-release identifiers order");
  check(cmp("1.4.0-rc.1", "1.4.0-rc.2") < 0, "numeric pre-release orders");
  check(cmp("1.4.0-rc.2", "1.4.0-rc.10") < 0,
        "numeric identifiers compare numerically, not lexically");
  check(cmp("1.4.0-rc", "1.4.0-rc.1") < 0, "fewer identifiers rank lower");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
