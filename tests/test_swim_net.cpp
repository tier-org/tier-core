#include <chrono>
#include <cstdio>
#include <memory>

#include "tier/core/membership.hpp"
#include "tier/core/swim.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/net/node.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

tier::core::SwimConfig fast_config() {
  tier::core::SwimConfig cfg;
  cfg.probe_period = std::chrono::milliseconds(100);
  cfg.ping_timeout = std::chrono::milliseconds(40);
  cfg.suspicion_timeout = std::chrono::milliseconds(300);
  cfg.dead_cleanup = std::chrono::milliseconds(300);
  return cfg;
}

// Pump both nodes until `done` holds or the wall-clock deadline passes.
template <typename Fn>
bool pump(const std::chrono::milliseconds budget, Fn&& done,
          tier::net::Node* a, tier::net::Node* b) {
  const auto start = std::chrono::steady_clock::now();
  while (std::chrono::steady_clock::now() - start < budget) {
    if (a != nullptr) {
      a->poll(10);
    }
    if (b != nullptr) {
      b->poll(10);
    }
    if (done()) {
      return true;
    }
  }
  return done();
}

}  // namespace

int main() {
  using tier::core::Role;

  auto a = std::make_unique<tier::net::Node>(
      tier::crypto::NodeIdentity::generate(), tier::core::role_bit(Role::validator),
      "127.0.0.1", 0, fast_config());
  auto b = std::make_unique<tier::net::Node>(
      tier::crypto::NodeIdentity::generate(), tier::core::role_bit(Role::client),
      "127.0.0.1", 0, fast_config());

  const auto a_id = a->peer_id();
  b->connect("127.0.0.1", a->local_port());

  const bool converged = pump(
      std::chrono::seconds(10),
      [&] { return a->membership().size() == 2 && b->membership().size() == 2; },
      a.get(), b.get());
  check(converged, "two nodes converge to size 2");

  // Kill A. B should probe it, fail, and walk it suspect -> dead -> removed.
  a.reset();

  const bool detected_dead = pump(
      std::chrono::seconds(15),
      [&] {
        const auto info = b->membership().find(a_id);
        return info && info->liveness == tier::core::Liveness::dead;
      },
      nullptr, b.get());
  check(detected_dead, "B marks the departed peer dead");

  const bool removed = pump(
      std::chrono::seconds(15), [&] { return !b->membership().find(a_id); },
      nullptr, b.get());
  check(removed, "B eventually removes the dead peer");

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
