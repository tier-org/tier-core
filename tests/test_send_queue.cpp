#include <cstdint>
#include <cstdio>
#include <random>
#include <vector>

#include "tier/net/send_queue.hpp"

// Deterministic coverage of the bounded send-queue admission logic
// (sendq::plan_admit), which Endpoint::Impl::send delegates to. Stalling a real
// peer's flow-control window is racy, so the arithmetic is exercised here
// directly across the full case space: the bulk drop behaviour, the three
// outcomes (admit / reject / close), and the SWIM control-priority rules (a
// control chunk is never dropped; bulk is capped short of the control reserve
// and is rejected rather than allowed to consume it; only an undroppable
// control overrun of the full cap closes the peer).

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::net::sendq::Decision;

bool admitted(const tier::net::sendq::Admission& d) {
  return d.decision == Decision::admit;
}
bool rejected(const tier::net::sendq::Admission& d) {
  return d.decision == Decision::reject;
}
bool closed(const tier::net::sendq::Admission& d) {
  return d.decision == Decision::close;
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

// Independent reference: recompute the drop count and decision by walking the
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
  const std::uint64_t limit = incoming_control ? cap : bulk_cap;
  std::uint64_t appended = q.appended;
  std::size_t n = q.base.size();
  while ((appended - total_acked) + incoming > limit && n > 0 &&
         q.base[n - 1] >= write_cursor && !q.control[n - 1]) {
    appended -= q.size[n - 1];
    --n;
    ++r.drop_from_back;
  }
  if ((appended - total_acked) + incoming <= limit) {
    r.decision = Decision::admit;
  } else if (incoming_control) {
    r.decision = Decision::close;
  } else {
    r.decision = Decision::reject;
  }
  return r;
}

}  // namespace

int main() {
  using tier::net::sendq::kControlReserveBytes;
  using tier::net::sendq::kMaxSendQueueBytes;

  // --- Bulk-only behaviour (reserve 0). Bulk fits the full cap; bulk that does
  //     not fit, and cannot shed enough, is REJECTED (dropped) - never closes. ---

  // 1. Empty queue, payload well under the cap: admitted, nothing dropped.
  {
    const auto q = make_queue(0, {});
    const auto d = run(q, 0, 0, 100, 1000);
    check(admitted(d) && d.drop_from_back == 0, "empty queue admits small payload");
  }

  // 2. Empty queue, payload exactly the cap: admitted (the test is strict `>`).
  {
    const auto q = make_queue(0, {});
    const auto d = run(q, 0, 0, 1000, 1000);
    check(admitted(d) && d.drop_from_back == 0, "payload == cap admitted");
  }

  // 3. Empty queue, single bulk payload one byte over the cap: nothing to drop,
  //    so the bulk frame is rejected (not queued), connection kept.
  {
    const auto q = make_queue(0, {});
    const auto d = run(q, 0, 0, 1001, 1000);
    check(rejected(d) && d.drop_from_back == 0, "oversize bulk on empty is rejected");
  }

  // 4. One fully-unsent chunk; dropping it makes room.
  {
    const auto q = make_queue(0, {800});
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/500, /*cap=*/1000);
    check(admitted(d) && d.drop_from_back == 1, "drop one unsent tail chunk");
  }

  // 5. Several unsent chunks; drop from the back only as many as needed.
  {
    const auto q = make_queue(0, {400, 400, 400});
    const auto d = run(q, 0, 0, 300, 1000);
    check(admitted(d) && d.drop_from_back == 2, "drop just enough unsent chunks");
  }

  // 6. Front chunk partly handed to the transport (write_cursor past its base);
  //    only the chunks at/after write_cursor are droppable.
  {
    const auto q = make_queue(0, {500, 500, 500});  // bases 0, 500, 1000
    const auto d = run(q, /*wc=*/500, /*ta=*/0, /*incoming=*/200, /*cap=*/1000);
    check(admitted(d) && d.drop_from_back == 2,
          "drop only chunks at/after write_cursor");
  }

  // 7. Whole queue in flight (write_cursor == appended), nothing droppable and
  //    already over budget, incoming bulk: rejected (connection kept).
  {
    const auto q = make_queue(0, {2000});
    const auto d = run(q, /*wc=*/2000, /*ta=*/0, /*incoming=*/100, /*cap=*/1000);
    check(rejected(d) && d.drop_from_back == 0, "all in-flight over budget rejects bulk");
  }

  // 8. One in-flight chunk + one unsent: the unsent tail is dropped, but the
  //    in-flight backlog alone still exceeds the cap, so the incoming bulk is
  //    rejected (the connection is not closed on bulk pressure).
  {
    const auto q = make_queue(0, {1500, 1000});  // bases 0 (sent), 1500 (unsent)
    const auto d = run(q, /*wc=*/1500, /*ta=*/0, /*incoming=*/100, /*cap=*/1000);
    check(rejected(d) && d.drop_from_back == 1,
          "drop unsent tail then reject bulk on in-flight backlog");
  }

  // 9. Acknowledgement shrinks the queue enough to fit with no drop.
  {
    const auto q = make_queue(0, {900});
    const auto d = run(q, /*wc=*/900, /*ta=*/500, /*incoming=*/500, /*cap=*/1000);
    check(admitted(d) && d.drop_from_back == 0, "acked bytes make room without drop");
  }

  // 10. Dropping lands the queue exactly on the cap boundary.
  {
    const auto q = make_queue(0, {600});
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/1000, /*cap=*/1000);
    check(admitted(d) && d.drop_from_back == 1, "drop to exactly the cap boundary");
  }

  // 11. The real default cap: a lone gossip frame far below it is admitted.
  {
    const auto q = make_queue(0, {});
    const auto d = run(q, 0, 0, 64 * 1024, kMaxSendQueueBytes);
    check(admitted(d) && d.drop_from_back == 0, "normal frame under default cap");
  }

  // --- SWIM control priority (reserve > 0). ---

  // 12. A control message is admitted alongside bulk that has filled the bulk
  //     budget (cap - reserve), because control sees the full cap. Nothing is
  //     dropped: the reserve was being held free exactly for this.
  {
    const auto q = make_queue(0, {800});  // bulk fills cap-reserve = 800
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/100, /*cap=*/1000,
                       /*reserve=*/200, /*incoming_control=*/true);
    check(admitted(d) && d.drop_from_back == 0,
          "control admitted into the reserve without dropping bulk");
  }

  // 13. A6/A5 core fix: an incoming BULK frame behind a trailing control chunk
  //     is NOT admitted into the reserve. The scan stops at the control chunk
  //     (never evicts it), the frame does not fit the bulk budget, so it is
  //     rejected - the reserve stays free for control. (Before the fix this
  //     wrongly admitted the bulk into the reserve.)
  {
    const auto q = make_queue(0, {500, 50}, {false, true});  // tail is control
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/400, /*cap=*/1000,
                       /*reserve=*/200, /*incoming_control=*/false);
    check(rejected(d) && d.drop_from_back == 0,
          "incoming bulk behind control is rejected, not admitted into reserve");
  }

  // 14. Bulk drops its own trailing bulk chunks but stops at a control chunk
  //     sitting in front of them (lower offset): control is preserved, and once
  //     the droppable tail is gone the frame fits the bulk budget and is admitted.
  {
    // bases 0(control), 50(bulk), 550(bulk); appended 1050.
    const auto q = make_queue(0, {50, 500, 500}, {true, false, false});
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/300, /*cap=*/1000,
                       /*reserve=*/200, /*incoming_control=*/false);
    check(admitted(d) && d.drop_from_back == 2,
          "bulk sheds its tail down to the protected control chunk");
  }

  // 15. A control chunk the transport has not drained cannot be dropped, so if
  //     the in-flight backlog plus that control chunk still exceed the full cap,
  //     an incoming CONTROL message closes the peer (a genuine stall).
  {
    // base 0 (sent, 1500 in flight), base 1500 (unsent control, 50).
    const auto q = make_queue(0, {1500, 50}, {false, true});
    const auto d = run(q, /*wc=*/1500, /*ta=*/0, /*incoming=*/100, /*cap=*/1000,
                       /*reserve=*/200, /*incoming_control=*/true);
    check(closed(d) && d.drop_from_back == 0,
          "stalled peer with undroppable control backlog closes on control");
  }

  // 16. At the production scale, a tiny control probe is admitted even when the
  //     bulk queue is full to the bulk budget.
  {
    const auto q = make_queue(0, {kMaxSendQueueBytes - kControlReserveBytes});
    const auto d = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/64, kMaxSendQueueBytes,
                       kControlReserveBytes, /*incoming_control=*/true);
    check(admitted(d) && d.drop_from_back == 0,
          "control probe admitted under a full bulk queue at real scale");
  }

  // 17. The A5 false-death sequence, now defused. Bulk fills the bulk budget
  //     with a trailing control chunk already queued in the reserve. A further
  //     bulk frame is rejected (does not consume the reserve), and a SWIM probe
  //     that arrives right after is still admitted - no close.
  {
    // bulk 790 then control 10: total 800 = bulk_cap, control sits in reserve.
    const auto q = make_queue(0, {790, 10}, {false, true});
    const auto bulk = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/100, /*cap=*/1000,
                          /*reserve=*/200, /*incoming_control=*/false);
    check(rejected(bulk) && bulk.drop_from_back == 0,
          "A5: extra bulk is rejected, reserve not consumed");
    const auto ping = run(q, /*wc=*/0, /*ta=*/0, /*incoming=*/50, /*cap=*/1000,
                          /*reserve=*/200, /*incoming_control=*/true);
    check(admitted(ping) && ping.drop_from_back == 0,
          "A5: the SWIM probe is still admitted (no false death)");
  }

  // 18. Randomised property sweep. Random contiguous queues with random
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
      check(d.drop_from_back == ref.drop_from_back && d.decision == ref.decision,
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
      const std::uint64_t bulk_cap = cap > reserve ? cap - reserve : 0;
      const std::uint64_t own_limit = incoming_control ? cap : bulk_cap;
      const bool exhausted = (kept == 0) || (q.base[kept - 1] < wc) ||
                             q.control[kept - 1];

      if (admitted(d)) {
        // Fits the payload's own budget (and therefore the full cap).
        check(queued2 <= own_limit, "admitted queue within its budget");
        check(queued2 <= cap, "admitted queue within full cap");
      } else if (rejected(d)) {
        // Only bulk is ever rejected, and only when it cannot fit the bulk
        // budget after shedding all droppable bulk.
        check(!incoming_control, "only bulk is rejected");
        check(queued2 > bulk_cap, "rejected bulk genuinely over its budget");
        check(exhausted, "rejected only after droppable bulk tail exhausted");
      } else {  // closed
        // Only control closes, and only on a genuine overrun of the full cap
        // with nothing left to drop.
        check(incoming_control, "only control closes");
        check(queued2 > cap, "closed queue genuinely over cap");
        check(exhausted, "closed only after droppable bulk tail exhausted");
      }
    }
  }

  if (g_failures == 0) {
    std::puts("test_send_queue: all checks passed");
  }
  return g_failures == 0 ? 0 : 1;
}
