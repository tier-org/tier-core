#ifndef TIER_NET_SEND_QUEUE_HPP
#define TIER_NET_SEND_QUEUE_HPP

#include <cstddef>
#include <cstdint>

// Bound on one connection's outbound send queue, factored out of
// Endpoint::Impl::send so it can be exercised deterministically. Reliably
// stalling a live peer's flow-control window through the real transport is
// racy, but the admission decision is pure arithmetic over the queue's chunk
// offsets, so it lives here and both the endpoint and the unit test drive the
// same code.
namespace tier::net::sendq {

// Cap on bytes queued but not yet acknowledged on one connection's send stream.
// A peer that keeps the connection open but stops extending its flow-control
// window would otherwise let periodic gossip pile up without bound.
inline constexpr std::uint64_t kMaxSendQueueBytes = 4ULL * 1024 * 1024;

// Headroom within the send-queue budget that bulk (membership gossip) traffic
// may not consume, kept free for SWIM control messages (ping/ack/probe). Under
// a gossip backlog that fills the queue, a liveness probe must still get out or
// a live peer is falsely declared dead; the drop logic never evicts control
// chunks and admits bulk only up to `cap - kControlReserveBytes`, so this much
// always remains for control. Control messages are tiny and infrequent, so this
// reserve holds many.
inline constexpr std::uint64_t kControlReserveBytes = 256ULL * 1024;

// Outcome of admitting `incoming` bytes into the bounded queue:
//   drop_from_back - how many trailing chunks to pop before appending. These
//                    are always fully-unsent BULK chunks (base >= write_cursor,
//                    not control), so the transport was never handed them and
//                    freeing them is safe; dropping a stale, unsent gossip
//                    snapshot is harmless because the next one carries fresh
//                    state. A control chunk is never among them.
//   admit          - true: append the payload after the drops. false: even with
//                    the droppable bulk tail gone the remaining backlog (in
//                    flight, or an undroppable control chunk) still exceeds the
//                    full cap, so the connection must be closed and the payload
//                    dropped.
struct Admission {
  std::size_t drop_from_back = 0;
  bool admit = true;
};

// Mirror of the queue-bound logic in Endpoint::Impl::send. The outbound queue
// is a contiguous, oldest-first run of chunks: chunk i occupies
// [base_of(i), base_of(i) + size_i) and base_of(i) + size_i == base_of(i + 1).
// Only the chunk bases are needed - because the run is contiguous, the next
// free offset after dropping a tail chunk is exactly that chunk's base, so the
// sizes never enter the decision.
//
//   chunk_count     - number of queued chunks.
//   base_of(i)      - absolute stream offset of chunk i (0 <= i < chunk_count).
//   is_control(i)   - whether chunk i is a SWIM control message (never dropped).
//   appended        - next free offset (base_of(last) + size_last, or
//                     write_cursor when the queue is empty).
//   write_cursor    - offset already handed to the transport; a chunk with
//                     base >= write_cursor is still entirely unsent.
//   total_acked     - acknowledged offset (<= write_cursor).
//   incoming        - size of the framed payload being admitted.
//   cap             - queue byte budget (kMaxSendQueueBytes in production).
//   control_reserve - budget bulk may not use (kControlReserveBytes in
//                     production); 0 disables the reserve.
//   incoming_is_control - whether the payload being admitted is control.
//
// Bulk is admitted against `cap - control_reserve` so the reserve stays free for
// control; control is admitted against the full `cap`. To make room, only
// fully-unsent bulk chunks are dropped from the back: a control chunk (or a
// chunk already in flight) is never dropped and stops the scan, which preserves
// the contiguous stream. The connection is closed only when the payload still
// does not fit the full `cap` after shedding the droppable bulk tail.
//
// Pure and allocation-free. `base_of`/`is_control` are callables over the index.
template <typename BaseOf, typename IsControl>
inline Admission plan_admit(std::size_t chunk_count, const BaseOf& base_of,
                            const IsControl& is_control, std::uint64_t appended,
                            std::uint64_t write_cursor,
                            std::uint64_t total_acked, std::uint64_t incoming,
                            std::uint64_t cap, std::uint64_t control_reserve,
                            bool incoming_is_control) noexcept {
  Admission result;
  std::size_t n = chunk_count;
  const std::uint64_t bulk_cap =
      cap > control_reserve ? cap - control_reserve : 0;
  const std::uint64_t drop_target = incoming_is_control ? cap : bulk_cap;
  const auto over = [&](std::uint64_t limit) -> bool {
    return (appended - total_acked) + incoming > limit;
  };
  // Drop fully-unsent bulk chunks from the back until the payload fits the drop
  // target. A control chunk, or one already handed to the transport, is never
  // dropped and ends the scan (dropping past it would tear a hole in the
  // contiguous stream).
  while (over(drop_target) && n > 0 && base_of(n - 1) >= write_cursor &&
         !is_control(n - 1)) {
    appended = base_of(n - 1);  // contiguous run: freed down to this offset
    --n;
    ++result.drop_from_back;
  }
  // The reserve only makes bulk shed its own backlog earlier; it never by itself
  // closes a peer. Close only if even the full cap is exceeded.
  result.admit = !over(cap);
  return result;
}

}  // namespace tier::net::sendq

#endif  // TIER_NET_SEND_QUEUE_HPP
