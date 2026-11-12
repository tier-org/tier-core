// Tests for the communicator's user directory (tier::net): enroll and lookup,
// expiry, the monotonic-issue rollback guard, and the per-user and total bounds.
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/net/user_directory.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

tier::core::PeerId id_from(unsigned idx) {
  tier::core::PeerId id{};
  id[0] = static_cast<std::uint8_t>(idx & 0xFF);
  id[1] = static_cast<std::uint8_t>((idx >> 8) & 0xFF);
  id[2] = static_cast<std::uint8_t>((idx >> 16) & 0xFF);
  return id;
}

bool has(const std::vector<tier::core::PeerId>& v, const tier::core::PeerId& id) {
  return std::find(v.begin(), v.end(), id) != v.end();
}

}  // namespace

int main() {
  using tier::net::UserDirectory;

  // Enroll two devices under one user; both resolve.
  {
    UserDirectory d;
    const auto user = id_from(1);
    check(d.enroll(user, id_from(10), /*issued=*/1, /*expiry=*/100, /*now=*/0),
          "device 1 enrolled");
    check(d.enroll(user, id_from(11), /*issued=*/1, /*expiry=*/100, /*now=*/0),
          "device 2 enrolled");
    const auto devices = d.lookup(user, 50);
    check(devices.size() == 2, "both devices resolve");
    check(has(devices, id_from(10)) && has(devices, id_from(11)),
          "both device ids present");
    check(d.lookup(id_from(999), 50).empty(), "unknown user resolves empty");
  }

  // remove(): a single (user, device) enrollment is dropped on demand (an
  // authenticated user_deregister), and the user disappears once empty.
  {
    UserDirectory d;
    const auto user = id_from(1);
    d.enroll(user, id_from(10), 1, /*expiry=*/100, 0);
    d.enroll(user, id_from(11), 1, /*expiry=*/100, 0);
    check(!d.remove(user, id_from(99)), "removing an unknown device is a no-op");
    check(d.remove(user, id_from(10)), "device 1 removed");
    check(d.lookup(user, 50).size() == 1, "only device 2 remains");
    check(d.remove(user, id_from(11)), "device 2 removed");
    check(d.lookup(user, 50).empty() && d.user_count() == 0,
          "user dropped once it has no devices");
    check(!d.remove(id_from(999), id_from(10)), "removing from an unknown user is a no-op");
  }

  // Expiry: a device drops out at its expiry, and the user disappears once it
  // has no live devices.
  {
    UserDirectory d;
    const auto user = id_from(1);
    d.enroll(user, id_from(10), 1, /*expiry=*/100, 0);
    check(d.lookup(user, 99).size() == 1, "present before expiry");
    check(d.lookup(user, 100).empty(), "gone at expiry");
    d.prune(100);
    check(d.user_count() == 0, "user pruned once it has no live devices");
  }

  // Monotonic issue stamp: a refresh must be strictly newer.
  {
    UserDirectory d;
    const auto user = id_from(1);
    d.enroll(user, id_from(10), /*issued=*/5, /*expiry=*/100, 0);
    check(!d.enroll(user, id_from(10), /*issued=*/5, /*expiry=*/200, 0),
          "same issue stamp does not refresh");
    check(!d.enroll(user, id_from(10), /*issued=*/4, /*expiry=*/200, 0),
          "older issue stamp does not refresh");
    check(d.enroll(user, id_from(10), /*issued=*/6, /*expiry=*/200, 0),
          "newer issue stamp refreshes");
    check(d.lookup(user, 150).size() == 1, "refreshed device still present");
  }

  // Per-user device cap: a full device set refuses a new device (live ones kept).
  {
    UserDirectory d(100, /*max_devices_per_user=*/2);
    const auto user = id_from(1);
    check(d.enroll(user, id_from(10), 1, 100, 0), "device 1 under cap");
    check(d.enroll(user, id_from(11), 1, 100, 0), "device 2 fills cap");
    check(!d.enroll(user, id_from(12), 1, 100, 0),
          "a third device is refused when the set is full of live entries");
    check(d.lookup(user, 50).size() == 2, "device set stays at the cap");
  }

  // Total-user cap: a new user is refused when full of live users.
  {
    UserDirectory d(/*max_users=*/2, 8);
    check(d.enroll(id_from(1), id_from(10), 1, 100, 0), "user 1");
    check(d.enroll(id_from(2), id_from(10), 1, 100, 0), "user 2 fills cap");
    check(!d.enroll(id_from(3), id_from(10), 1, 100, 0),
          "a third user is refused when full");
    check(d.user_count() == 2, "user table stays at the cap");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
