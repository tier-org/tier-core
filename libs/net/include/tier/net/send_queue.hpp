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

// Outcome of admitting `incoming` bytes into the bounded queue:
//   drop_from_back - how many trailing chunks to pop before appending. These
//                    are always fully-unsent chunks (base >= write_cursor), so
//                    the transport was never handed them and freeing them is
//                    safe; dropping a stale, unsent gossip snapshot is harmless
//                    because the next one carries fresh state.
//   admit          - true: append the payload after the drops. false: even with
//                    the whole unsent tail gone the in-flight backlog alone
//                    exceeds the cap, so the connection must be closed and the
//                    payload dropped.
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
//   chunk_count  - number of queued chunks.
//   base_of(i)   - absolute stream offset of chunk i (0 <= i < chunk_count).
//   appended     - next free offset (base_of(last) + size_last, or write_cursor
//                  when the queue is empty).
//   write_cursor - offset already handed to the transport; a chunk with
//                  base >= write_cursor is still entirely unsent.
//   total_acked  - acknowledged offset (<= write_cursor).
//   incoming     - size of the framed payload being admitted.
//   cap          - queue byte budget (kMaxSendQueueBytes in production).
//
// Pure and allocation-free. `base_of` is any callable `std::uint64_t(size_t)`.
template <typename BaseOf>
inline Admission plan_admit(std::size_t chunk_count, const BaseOf& base_of,
                            std::uint64_t appended, std::uint64_t write_cursor,
                            std::uint64_t total_acked, std::uint64_t incoming,
                            std::uint64_t cap) noexcept {
  Admission result;
  std::size_t n = chunk_count;
  const auto over = [&]() -> bool {
    return (appended - total_acked) + incoming > cap;
  };
  // Drop unsent chunks from the back until the payload fits or the unsent tail
  // is exhausted (the next chunk back has been handed to the transport).
  while (over() && n > 0 && base_of(n - 1) >= write_cursor) {
    appended = base_of(n - 1);  // contiguous run: freed down to this offset
    --n;
    ++result.drop_from_back;
  }
  result.admit = !over();
  return result;
}

}  // namespace tier::net::sendq

#endif  // TIER_NET_SEND_QUEUE_HPP
