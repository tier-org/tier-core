#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

#include "tier/net/send_queue.hpp"

// Deterministic coverage of the bounded send-queue admission logic
// (sendq::plan_admit), which Endpoint::Impl::send delegates to. Stalling a real
// peer's flow-control window is racy, so the arithmetic is exercised here
// directly across the full case space, including the close branch that the
// 256 KiB production stream window keeps out of reach in practice.

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

// A contiguous, oldest-first run of chunks built from per-chunk sizes starting
// at `start`. `base[i]` is chunk i's absolute offset; `appended` is the end.
struct Queue {
  std::vector<std::uint64_t> base;
  std::vector<std::uint64_t> size;
  std::uint64_t appended = 0;
};

Queue make_queue(std::uint64_t start, const std::vector<std::uint64_t>& sizes) {
  Queue q;
  std::uint64_t off = start;
  for (const auto s : sizes) {
    q.base.push_back(off);
    q.size.push_back(s);
    off += s;
  }
  q.appended = off;
  return q;
}

tier::net::sendq::Admission run(const Queue& q, std::uint64_t write_cursor,
                                std::uint64_t total_acked,
                                std::uint64_t incoming, std::uint64_t cap) {
  return tier::net::sendq::plan_admit(
      q.base.size(), [&](std::size_t i) { return q.base[i]; }, q.appended,
      write_cursor, total_acked, incoming, cap);
}

// Independent reference: recompute the drop count and admit flag by walking the
// tail with the chunk SIZES (not the base-only shortcut plan_admit uses). If
// the two agree, the contiguity shortcut (next free offset after dropping a
// tail chunk == that chunk's base) holds for this input.
tier::net::sendq::Admission reference(const Queue& q, std::uint64_t write_cursor,
                                      std::uint64_t total_acked,
                                      std::uint64_t incoming,
                                      std::uint64_t cap) {
  tier::net::sendq::Admission r;
  std::uint64_t appended = q.appended;
  std::size_t n = q.base.size();
  while ((appended - total_acked) + incoming > cap && n > 0 &&
         q.base[n - 1] >= write_cursor) {
    appended -= q.size[n - 1];
    --n;
    ++r.drop_from_back;
  }
  r.admit = (appended - total_acked) + incoming <= cap;
  return r;
}

}  // namespace

int main() {
  using tier::net::sendq::kMaxSendQueueBytes;

  // 1. Empty queue, payload well under the cap: admitted, nothing dropped.
  {
    const auto q = make_queue(0, {});
    const auto d = run(q, 0, 0, 100, 1000);
    check(d.admit && d.drop_from_back == 0, "empty queue admits small payload");
  }

  // 2. Empty queue, payload exactly the cap: admitted (the test is strict `>`).
  {
    const auto q = make_queue(0, {});
    const auto d = run(q, 0, 0, 1000, 1000);
    check(d.admit && d.drop_from_back == 0, "payload == cap admitted");
  }

  // 3. Empty queue, single payload one byte over the cap: nothing to drop, so
  //    the connection is closed (a frame larger than the whole budget).
  {
    const auto q = make_queue(0, {});
    const auto d = run(q, 0, 0, 1001, 1000);
    check(!d.admit && d.drop_from_back == 0, "oversize payload on empty closes");
  }

  // 4. One fully-unsent chunk; dropping it makes room.
  {
    const auto q = make_queue(0, {800});
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/500, /*cap=*/1000);
    check(d.admit && d.drop_from_back == 1, "drop one unsent tail chunk");
  }

  // 5. Several unsent chunks; drop from the back only as many as needed.
  {
    const auto q = make_queue(0, {400, 400, 400});
    const auto d = run(q, 0, 0, 300, 1000);
    check(d.admit && d.drop_from_back == 2, "drop just enough unsent chunks");
  }

  // 6. Front chunk partly handed to the transport (write_cursor past its base);
  //    only the chunks at/after write_cursor are droppable.
  {
    const auto q = make_queue(0, {500, 500, 500});  // bases 0, 500, 1000
    const auto d = run(q, /*wc=*/500, /*ta=*/0, /*incoming=*/200, /*cap=*/1000);
    check(d.admit && d.drop_from_back == 2,
          "drop only chunks at/after write_cursor");
  }

  // 7. Whole queue in flight (write_cursor == appended), nothing droppable and
  //    already over budget: close.
  {
    const auto q = make_queue(0, {2000});
    const auto d = run(q, /*wc=*/2000, /*ta=*/0, /*incoming=*/100, /*cap=*/1000);
    check(!d.admit && d.drop_from_back == 0, "all in-flight over budget closes");
  }

  // 8. One in-flight chunk + one unsent: the unsent tail is dropped, but the
  //    in-flight backlog alone still exceeds the cap, so the peer is closed.
  {
    const auto q = make_queue(0, {1500, 1000});  // bases 0 (sent), 1500 (unsent)
    const auto d = run(q, /*wc=*/1500, /*ta=*/0, /*incoming=*/100, /*cap=*/1000);
    check(!d.admit && d.drop_from_back == 1,
          "drop unsent tail then close on in-flight backlog");
  }

  // 9. Acknowledgement shrinks the queue enough to fit with no drop.
  {
    const auto q = make_queue(0, {900});
    const auto d = run(q, /*wc=*/900, /*ta=*/500, /*incoming=*/500, /*cap=*/1000);
    check(d.admit && d.drop_from_back == 0, "acked bytes make room without drop");
  }

  // 10. Dropping lands the queue exactly on the cap boundary.
  {
    const auto q = make_queue(0, {600});
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/1000, /*cap=*/1000);
    check(d.admit && d.drop_from_back == 1, "drop to exactly the cap boundary");
  }

  // 11. The real default cap: a lone gossip frame far below it is admitted.
  {
    const auto q = make_queue(0, {});
    const auto d = run(q, 0, 0, 64 * 1024, kMaxSendQueueBytes);
    check(d.admit && d.drop_from_back == 0, "normal frame under default cap");
  }

  // 12. Randomised property sweep. Random contiguous queues with random
  //     write_cursor / total_acked / incoming against a small cap. Assert the
  //     invariants the endpoint relies on and cross-check against the
  //     size-based reference.
  {
    std::mt19937 rng(0xC0FFEEu);
    std::uniform_int_distribution<int> count_dist(0, 8);
    std::uniform_int_distribution<std::uint64_t> size_dist(1, 1500);
    std::uniform_int_distribution<std::uint64_t> start_dist(0, 5000);
    std::uniform_int_distribution<std::uint64_t> incoming_dist(1, 3000);
    std::uniform_int_distribution<std::uint64_t> cap_dist(1000, 5000);

    for (int iter = 0; iter < 20000; ++iter) {
      const int n = count_dist(rng);
      std::vector<std::uint64_t> sizes;
      sizes.reserve(static_cast<std::size_t>(n));
      for (int i = 0; i < n; ++i) {
        sizes.push_back(size_dist(rng));
      }
      const auto q = make_queue(start_dist(rng), sizes);

      // total_acked in [start, appended]; write_cursor in [total_acked,
      // appended] - matches the endpoint's ta <= wc <= appended ordering.
      const std::uint64_t start = q.base.empty() ? q.appended : q.base.front();
      std::uniform_int_distribution<std::uint64_t> ta_dist(start, q.appended);
      const std::uint64_t ta = ta_dist(rng);
      std::uniform_int_distribution<std::uint64_t> wc_dist(ta, q.appended);
      const std::uint64_t wc = wc_dist(rng);
      const std::uint64_t incoming = incoming_dist(rng);
      const std::uint64_t cap = cap_dist(rng);

      const auto d = run(q, wc, ta, incoming, cap);
      const auto ref = reference(q, wc, ta, incoming, cap);

      // Agrees with the independent size-based recompute (validates the
      // base-only contiguity shortcut).
      check(d.drop_from_back == ref.drop_from_back && d.admit == ref.admit,
            "plan_admit matches size-based reference");

      // Never drops more chunks than exist.
      check(d.drop_from_back <= q.base.size(), "drop count within bounds");

      // Every dropped chunk was fully unsent (base >= write_cursor); the
      // transport was never handed it.
      bool only_unsent_dropped = true;
      for (std::size_t k = 0; k < d.drop_from_back; ++k) {
        const std::size_t idx = q.base.size() - 1 - k;
        if (q.base[idx] < wc) {
          only_unsent_dropped = false;
        }
      }
      check(only_unsent_dropped, "only unsent chunks dropped");

      // Resulting next-free offset after the drops.
      const std::size_t kept = q.base.size() - d.drop_from_back;
      const std::uint64_t appended2 = (d.drop_from_back == 0)
                                          ? q.appended
                                          : q.base[kept];
      check(appended2 >= ta, "no queue underflow after drops");
      const std::uint64_t queued2 = (appended2 - ta) + incoming;

      if (d.admit) {
        // When admitted, the queue (including the new payload) fits the cap.
        check(queued2 <= cap, "admitted queue within cap");
      } else {
        // When closing, it did not fit AND no further drop was possible: either
        // nothing is left or the next chunk back is in flight (base < wc).
        check(queued2 > cap, "closed queue genuinely over cap");
        const bool exhausted = (kept == 0) || (q.base[kept - 1] < wc);
        check(exhausted, "closed only after unsent tail exhausted");
      }
    }
  }

  if (g_failures == 0) {
    std::puts("test_send_queue: all checks passed");
  }
  return g_failures == 0 ? 0 : 1;
}
