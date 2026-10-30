#include <chrono>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include "tier/net/node.hpp"

// Unit test for the dial policy (tier::net::Node::select_dial_candidate): which
// of a peer's candidate addresses to attempt next. Pure and clock-driven, so it
// needs no sockets.

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

}  // namespace

int main() {
  using Clock = std::chrono::steady_clock;
  using tier::net::Node;
  const auto retry = std::chrono::seconds(2);
  const Clock::time_point base = Clock::now();

  const std::string v4 = "1.2.3.4:5";
  const std::string v6 = "[2001:db8::1]:5";
  const std::vector<std::string> both{v4, v6};
  const std::map<std::string, Clock::time_point> none;

  // Nothing to dial.
  check(!Node::select_dial_candidate({}, none, base, retry).has_value(),
        "empty candidate set yields nothing");
  check(!Node::select_dial_candidate({"0.0.0.0:7777"}, none, base, retry)
             .has_value(),
        "a wildcard-only set is not dialable");

  // A single address is chosen as-is.
  {
    const auto pick = Node::select_dial_candidate({v4}, none, base, retry);
    check(pick && *pick == v4, "single candidate is chosen");
  }

  // With both families and nothing tried yet, IPv6 is preferred.
  {
    const auto pick = Node::select_dial_candidate(both, none, base, retry);
    check(pick && *pick == v6, "IPv6 preferred on a fresh dial");
  }

  // After dialing IPv6, a second attempt to the same peer waits out the retry
  // window rather than opening a parallel connection.
  {
    std::map<std::string, Clock::time_point> dialed{{v6, base}};
    check(!Node::select_dial_candidate(both, dialed, base + std::chrono::seconds(1),
                                       retry)
               .has_value(),
          "within the retry window, attempts are serialized");

    // Past the window, the attempt rotates to the untried IPv4 candidate.
    const auto pick = Node::select_dial_candidate(
        both, dialed, base + std::chrono::seconds(3), retry);
    check(pick && *pick == v4, "past the window, rotate to the other family");
  }

  // Both tried: the least-recently dialed (IPv6 here) comes up again.
  {
    std::map<std::string, Clock::time_point> dialed{
        {v6, base}, {v4, base + std::chrono::seconds(3)}};
    const auto pick = Node::select_dial_candidate(
        both, dialed, base + std::chrono::seconds(6), retry);
    check(pick && *pick == v6, "rotation returns to the oldest attempt");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
