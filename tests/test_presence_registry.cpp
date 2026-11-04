// Tests for the communicator's bounded presence registry (tier::net): store and
// lookup, expiry, the monotonic-incarnation rollback guard, and the entry cap
// with expired-only eviction.
#include <cstdint>
#include <cstdio>
#include <vector>

#include "tier/core/membership.hpp"
#include "tier/net/presence_registry.hpp"

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

std::vector<std::uint8_t> blob(std::uint8_t tag) { return {tag, tag, tag}; }

}  // namespace

int main() {
  using tier::net::PresenceRegistry;

  // Store and look up.
  {
    PresenceRegistry reg;
    const auto a = id_from(1);
    check(reg.store(a, blob(0xAA), /*incarnation=*/1, /*expiry=*/100, /*now=*/10),
          "fresh record stored");
    const auto got = reg.lookup(a, 50);
    check(got.has_value() && *got == blob(0xAA), "stored bytes returned");
    check(!reg.lookup(id_from(2), 50).has_value(), "absent id not found");
  }

  // Expiry: a record at or past its expiry is not returned, and prune drops it.
  {
    PresenceRegistry reg;
    const auto a = id_from(1);
    reg.store(a, blob(0xAA), 1, /*expiry=*/100, /*now=*/10);
    check(reg.lookup(a, 99).has_value(), "found just before expiry");
    check(!reg.lookup(a, 100).has_value(), "not found at expiry");
    check(!reg.lookup(a, 200).has_value(), "not found after expiry");
    check(reg.size() == 1, "expired entry still occupies a slot until pruned");
    reg.prune(100);
    check(reg.size() == 0, "prune drops the expired entry");
  }

  // An already-expired record is refused outright.
  {
    PresenceRegistry reg;
    check(!reg.store(id_from(1), blob(0xAA), 1, /*expiry=*/100, /*now=*/100),
          "a record expiring now is refused");
    check(!reg.store(id_from(1), blob(0xAA), 1, /*expiry=*/50, /*now=*/100),
          "a record already expired is refused");
    check(reg.size() == 0, "nothing stored");
  }

  // Monotonic incarnation: a refresh must be strictly newer, so a replay of an
  // older signed record cannot roll back a newer one.
  {
    PresenceRegistry reg;
    const auto a = id_from(1);
    reg.store(a, blob(0x01), /*incarnation=*/5, /*expiry=*/100, /*now=*/0);
    check(!reg.store(a, blob(0x02), /*incarnation=*/5, 200, 0),
          "same incarnation does not overwrite");
    check(!reg.store(a, blob(0x03), /*incarnation=*/4, 200, 0),
          "older incarnation does not overwrite");
    check(*reg.lookup(a, 10) == blob(0x01), "original record retained");
    check(reg.store(a, blob(0x09), /*incarnation=*/6, 200, 0),
          "a strictly newer incarnation overwrites");
    check(*reg.lookup(a, 10) == blob(0x09), "newer record is now held");
  }

  // Bounded: a full table of live entries refuses a new id, but makes room by
  // dropping expired entries first.
  {
    PresenceRegistry reg(4);
    for (unsigned i = 0; i < 4; ++i) {
      check(reg.store(id_from(i), blob(0x10), 1, /*expiry=*/100, /*now=*/0),
            "filled under the cap");
    }
    check(reg.size() == 4, "table at cap");
    check(!reg.store(id_from(100), blob(0x20), 1, /*expiry=*/100, /*now=*/0),
          "a new id is refused when full of live entries");
    check(reg.size() == 4, "size unchanged after refusal");

    // Once the live entries have expired, a new (future-dated) id is admitted:
    // room is reclaimed from the expired ones, not from a live entry.
    check(reg.store(id_from(200), blob(0x30), 1, /*expiry=*/300, /*now=*/150),
          "a new id is admitted once expired entries can be reclaimed");
    check(reg.size() <= 4, "table stays bounded");
    check(reg.lookup(id_from(200), 160).has_value(), "the new id is stored");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
