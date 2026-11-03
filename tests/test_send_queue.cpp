#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

#include "tier/net/send_queue.hpp"

// Deterministic coverage of the bounded send-queue admission logic
// (sendq::plan_admit), which Endpoint::Impl::send delegates to. Stalling a real
// peer's flow-control window is racy, so the arithmetic is exercised here
// directly across the full case space: the plain bulk-only drop behaviour, the
// close branch, and the SWIM control-priority rules (a control chunk is never
// dropped, and bulk is capped short of the control reserve).

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
// `control[i]` marks a SWIM control chunk (never dropped). Default: all bulk.
struct Queue {
  std::vector<std::uint64_t> base;
  std::vector<std::uint64_t> size;
  std::vector<bool> control;
  std::uint64_t appended = 0;
};

Queue make_queue(std::uint64_t start, const std::vector<std::uint64_t>& sizes,
                 const std::vector<bool>& control = {}) {
  Queue q;
  std::uint64_t off = start;
  for (std::size_t i = 0; i < sizes.size(); ++i) {
    q.base.push_back(off);
    q.size.push_back(sizes[i]);
    q.control.push_back(i < control.size() ? control[i] : false);
    off += sizes[i];
  }
  q.appended = off;
  return q;
}

tier::net::sendq::Admission run(const Queue& q, std::uint64_t write_cursor,
                                std::uint64_t total_acked,
                                std::uint64_t incoming, std::uint64_t cap,
                                std::uint64_t reserve = 0,
                                bool incoming_control = false) {
  return tier::net::sendq::plan_admit(
      q.base.size(), [&](std::size_t i) { return q.base[i]; },
      [&](std::size_t i) { return q.control[i]; }, q.appended, write_cursor,
      total_acked, incoming, cap, reserve, incoming_control);
}

// Independent reference: recompute the drop count and admit flag by walking the
// tail with the chunk SIZES (not the base-only shortcut plan_admit uses), and
// honouring the same control-priority rules. If the two agree, the contiguity
// shortcut (next free offset after dropping a tail chunk == that chunk's base)
// holds for this input.
tier::net::sendq::Admission reference(const Queue& q, std::uint64_t write_cursor,
                                      std::uint64_t total_acked,
                                      std::uint64_t incoming, std::uint64_t cap,
                                      std::uint64_t reserve,
                                      bool incoming_control) {
  tier::net::sendq::Admission r;
  const std::uint64_t bulk_cap = cap > reserve ? cap - reserve : 0;
  const std::uint64_t drop_target = incoming_control ? cap : bulk_cap;
  std::uint64_t appended = q.appended;
  std::size_t n = q.base.size();
  while ((appended - total_acked) + incoming > drop_target && n > 0 &&
         q.base[n - 1] >= write_cursor && !q.control[n - 1]) {
    appended -= q.size[n - 1];
    --n;
    ++r.drop_from_back;
  }
  r.admit = (appended - total_acked) + incoming <= cap;
  return r;
}

}  // namespace

int main() {
  using tier::net::sendq::kControlReserveBytes;
  using tier::net::sendq::kMaxSendQueueBytes;

  // --- Bulk-only behaviour (reserve 0): the original drop/close semantics. ---

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

  // --- SWIM control priority (reserve > 0). ---

  // 12. A control message is admitted alongside bulk that has filled the bulk
  //     budget (cap - reserve), because control sees the full cap. Nothing is
  //     dropped: the reserve was being held free exactly for this.
  {
    const auto q = make_queue(0, {800});  // bulk fills cap-reserve = 800
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/100, /*cap=*/1000,
                       /*reserve=*/200, /*incoming_control=*/true);
    check(d.admit && d.drop_from_back == 0,
          "control admitted into the reserve without dropping bulk");
  }

  // 13. An incoming bulk frame never drops a trailing control chunk: the scan
  //     stops at it, and the frame is admitted into the reserve rather than
  //     evicting control or closing the peer.
  {
    const auto q = make_queue(0, {500, 50}, {false, true});  // tail is control
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/400, /*cap=*/1000,
                       /*reserve=*/200, /*incoming_control=*/false);
    check(d.admit && d.drop_from_back == 0,
          "incoming bulk does not drop a trailing control chunk");
  }

  // 14. Bulk drops its own trailing bulk chunks but stops at a control chunk
  //     sitting in front of them (lower offset): control is preserved.
  {
    // bases 0(control), 50(bulk), 550(bulk); appended 1050.
    const auto q = make_queue(0, {50, 500, 500}, {true, false, false});
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/300, /*cap=*/1000,
                       /*reserve=*/200, /*incoming_control=*/false);
    check(d.admit && d.drop_from_back == 2,
          "bulk sheds its tail down to the protected control chunk");
  }

  // 15. A control chunk the transport has not drained cannot be dropped, so if
  //     the in-flight backlog plus that control chunk still exceed the full cap,
  //     the peer is closed (a genuine stall, not gossip pressure).
  {
    // base 0 (sent, 1500 in flight), base 1500 (unsent control, 50).
    const auto q = make_queue(0, {1500, 50}, {false, true});
    const auto d = run(q, /*wc=*/1500, /*ta=*/0, /*incoming=*/100, /*cap=*/1000,
                       /*reserve=*/200, /*incoming_control=*/false);
    check(!d.admit && d.drop_from_back == 0,
          "stalled peer with undroppable control still closes");
  }

  // 16. At the production scale, a tiny control probe is admitted even when the
  //     bulk queue is full to the bulk budget.
  {
    const auto q = make_queue(0, {kMaxSendQueueBytes - kControlReserveBytes});
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/64, kMaxSendQueueBytes,
                       kControlReserveBytes, /*incoming_control=*/true);
    check(d.admit && d.drop_from_back == 0,
          "control probe admitted under a full bulk queue at real scale");
  }

  // 17. Randomised property sweep. Random contiguous queues with random
  //     per-chunk control flags, write_cursor / total_acked / incoming, reserve
  //     and incoming class against a small cap. Assert the invariants the
  //     endpoint relies on and cross-check against the size-based reference.
  {
    std::mt19937 rng(0xC0FFEEu);
    std::uniform_int_distribution<int> count_dist(0, 8);
    std::uniform_int_distribution<std::uint64_t> size_dist(1, 1500);
    std::uniform_int_distribution<std::uint64_t> start_dist(0, 5000);
    std::uniform_int_distribution<std::uint64_t> incoming_dist(1, 3000);
    std::uniform_int_distribution<std::uint64_t> cap_dist(1000, 5000);
    std::uniform_int_distribution<int> bit_dist(0, 1);
    std::uniform_int_distribution<std::uint64_t> reserve_dist(0, 1500);

    for (int iter = 0; iter < 40000; ++iter) {
      const int n = count_dist(rng);
      std::vector<std::uint64_t> sizes;
      std::vector<bool> control;
      sizes.reserve(static_cast<std::size_t>(n));
      control.reserve(static_cast<std::size_t>(n));
      for (int i = 0; i < n; ++i) {
        sizes.push_back(size_dist(rng));
        control.push_back(bit_dist(rng) == 1);
      }
      const auto q = make_queue(start_dist(rng), sizes, control);

      // total_acked in [start, appended]; write_cursor in [total_acked,
      // appended] - matches the endpoint's ta <= wc <= appended ordering.
      const std::uint64_t start = q.base.empty() ? q.appended : q.base.front();
      std::uniform_int_distribution<std::uint64_t> ta_dist(start, q.appended);
      const std::uint64_t ta = ta_dist(rng);
      std::uniform_int_distribution<std::uint64_t> wc_dist(ta, q.appended);
      const std::uint64_t wc = wc_dist(rng);
      const std::uint64_t incoming = incoming_dist(rng);
      const std::uint64_t cap = cap_dist(rng);
      const std::uint64_t reserve = reserve_dist(rng);
      const bool incoming_control = bit_dist(rng) == 1;

      const auto d = run(q, wc, ta, incoming, cap, reserve, incoming_control);
      const auto ref =
          reference(q, wc, ta, incoming, cap, reserve, incoming_control);

      // Agrees with the independent size-based recompute (validates the
      // base-only contiguity shortcut and the control-priority rules).
      check(d.drop_from_back == ref.drop_from_back && d.admit == ref.admit,
            "plan_admit matches size-based reference");

      // Never drops more chunks than exist.
      check(d.drop_from_back <= q.base.size(), "drop count within bounds");

      // Every dropped chunk was fully unsent (base >= write_cursor) AND bulk;
      // the transport was never handed it and control is never evicted.
      bool only_unsent_bulk_dropped = true;
      for (std::size_t k = 0; k < d.drop_from_back; ++k) {
        const std::size_t idx = q.base.size() - 1 - k;
        if (q.base[idx] < wc || q.control[idx]) {
          only_unsent_bulk_dropped = false;
        }
      }
      check(only_unsent_bulk_dropped, "only unsent bulk chunks dropped");

      // Resulting next-free offset after the drops.
      const std::size_t kept = q.base.size() - d.drop_from_back;
      const std::uint64_t appended2 =
          (d.drop_from_back == 0) ? q.appended : q.base[kept];
      check(appended2 >= ta, "no queue underflow after drops");
      const std::uint64_t queued2 = (appended2 - ta) + incoming;

      if (d.admit) {
        // When admitted, the queue (including the new payload) fits the full
        // cap.
        check(queued2 <= cap, "admitted queue within cap");
      } else {
        // When closing, it did not fit the full cap AND no further drop was
        // possible: nothing is left, or the next chunk back is in flight
        // (base < wc) or a control chunk.
        check(queued2 > cap, "closed queue genuinely over cap");
        const bool exhausted = (kept == 0) || (q.base[kept - 1] < wc) ||
                               q.control[kept - 1];
        check(exhausted, "closed only after droppable bulk tail exhausted");
      }
    }
  }

  if (g_failures == 0) {
    std::puts("test_send_queue: all checks passed");
  }
  return g_failures == 0 ? 0 : 1;
}
