#include <cstdio>
#include <string>

#include "config.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

tier::node::Config parse_ok(const char* text) {
  std::string err;
  auto cfg = tier::node::parse_config(text, err);
  if (!cfg) {
    std::fprintf(stderr, "unexpected parse error: %s\n", err.c_str());
    ++g_failures;
    return {};
  }
  return *cfg;
}

bool parse_fails(const char* text) {
  std::string err;
  return !tier::node::parse_config(text, err).has_value();
}

}  // namespace

int main() {
  // Full, well-formed config exercising every key, arrays, quoting and comments.
  {
    const auto cfg = parse_ok(
        "# node config\n"
        "network = \"testnet\"\n"
        "version_range = \"1.4.0,1.5.0\"\n"
        "roles = [\"validator\", \"keeper\"]   # primary + storage\n"
        "seeds = [\"[fd00::2]:7777\", \"10.0.0.2:7777\"]\n");
    check(cfg.network && *cfg.network == "testnet", "network parsed");
    check(cfg.version_range && *cfg.version_range == "1.4.0,1.5.0",
          "version_range parsed");
    check(cfg.roles && cfg.roles->size() == 2 && (*cfg.roles)[0] == "validator" &&
              (*cfg.roles)[1] == "keeper",
          "roles array parsed");
    check(cfg.seeds && cfg.seeds->size() == 2 &&
              (*cfg.seeds)[0] == "[fd00::2]:7777" &&
              (*cfg.seeds)[1] == "10.0.0.2:7777",
          "seeds array parsed (IPv6 bracket preserved)");
  }

  // Absent keys stay unset; the daemon then falls back to env/baked.
  {
    const auto cfg = parse_ok("network = \"mainnet\"\n");
    check(cfg.network.has_value(), "present key set");
    check(!cfg.roles && !cfg.seeds && !cfg.version_range,
          "absent keys remain unset");
  }

  // Empty and comment-only input is valid and yields an all-unset config.
  {
    const auto cfg = parse_ok("\n  \n# just a comment\n");
    check(!cfg.network && !cfg.roles && !cfg.seeds && !cfg.version_range,
          "empty config is all-unset");
  }

  // A bare scalar is accepted for an array key as a single element, and a bare
  // scalar for a string key works too.
  {
    const auto cfg = parse_ok("roles = transmitter\nnetwork = testnet\n");
    check(cfg.roles && cfg.roles->size() == 1 && (*cfg.roles)[0] == "transmitter",
          "bare scalar becomes single-element array");
    check(cfg.network && *cfg.network == "testnet", "bare scalar string");
  }

  // An empty array is valid (an explicit "no seeds" / isolated node).
  {
    const auto cfg = parse_ok("seeds = []\n");
    check(cfg.seeds && cfg.seeds->empty(), "empty array parsed");
  }

  // Error cases, each fails closed with a diagnostic.
  check(parse_fails("bogus = 1\n"), "unknown key rejected");
  check(parse_fails("network\n"), "line without '=' rejected");
  check(parse_fails("network =\n"), "missing value rejected");
  check(parse_fails("network = \"unterminated\n"), "unterminated string rejected");
  check(parse_fails("network = [\"a\"]\n"), "string key given array rejected");
  check(parse_fails("network = \"a\"\nnetwork = \"b\"\n"), "duplicate key rejected");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
