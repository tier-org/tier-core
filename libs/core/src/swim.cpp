#include "tier/core/swim.hpp"

#include <utility>

#include "tier/core/control.hpp"

namespace tier::core {

FailureDetector::FailureDetector(PeerId self, Membership& membership,
                                 SwimConfig cfg, SendFn send)
    : self_(self), m_(membership), cfg_(cfg), send_(std::move(send)) {}

void FailureDetector::tick(Clock::time_point now,
                           const std::vector<PeerId>& neighbors) {
  refute_if_accused();
  scan_membership(now);
  expire_relays(now);
  check_probe_timeouts(now, neighbors);
  advance_suspicions(now);

  if (!probing_started_ || now - last_probe_ >= cfg_.probe_period) {
    start_probe(now, neighbors);
    last_probe_ = now;
    probing_started_ = true;
  }
}

// A node never lets itself be held suspect or dead: seeing such a report about
// itself, it raises its incarnation above the accusation and re-asserts alive.
// The higher incarnation supersedes the suspicion wherever it is gossiped.
void FailureDetector::refute_if_accused() {
  const auto self = m_.find(self_);
  if (!self || self->liveness == Liveness::alive) {
    return;
  }
  PeerInfo me = *self;
  me.incarnation = self->incarnation + 1;
  me.liveness = Liveness::alive;
  m_.apply(me);
  suspects_.erase(self_);
  dead_since_.erase(self_);
}

// Reconcile detector state with the table, which gossip also mutates: pick up
// suspicions and deaths learned from peers, and drop our own when a higher
// incarnation (a refutation or recovery) has overwritten them.
void FailureDetector::scan_membership(Clock::time_point now) {
  for (const PeerInfo& p : m_.snapshot()) {
    if (p.id == self_) {
      continue;
    }
    switch (p.liveness) {
      case Liveness::suspect: {
        auto [it, inserted] = suspects_.try_emplace(p.id);
        if (inserted || p.incarnation > it->second.incarnation) {
          it->second = Suspicion{now, p.incarnation};  // (re)start the clock
        }
        dead_since_.erase(p.id);
        break;
      }
      case Liveness::dead:
        suspects_.erase(p.id);
        dead_since_.try_emplace(p.id, now);
        break;
      case Liveness::alive: {
        const auto it = suspects_.find(p.id);
        if (it != suspects_.end() && p.incarnation > it->second.incarnation) {
          suspects_.erase(it);  // refuted
        }
        dead_since_.erase(p.id);  // recovered at a higher incarnation
        break;
      }
    }
  }
}

void FailureDetector::expire_relays(Clock::time_point now) {
  for (auto it = relaying_.begin(); it != relaying_.end();) {
    if (now - it->second.when >= cfg_.probe_period) {
      it = relaying_.erase(it);  // the requester's period is over; useless now
    } else {
      ++it;
    }
  }
}

void FailureDetector::check_probe_timeouts(
    Clock::time_point now, const std::vector<PeerId>& neighbors) {
  for (auto it = pending_.begin(); it != pending_.end();) {
    Probe& pr = it->second;
    const auto age = now - pr.sent;
    if (age >= cfg_.probe_period) {
      suspect(pr.target, now);  // no ack, direct or indirect, within the period
      it = pending_.erase(it);
      continue;
    }
    if (!pr.indirect_sent && age >= cfg_.ping_timeout) {
      pr.indirect_sent = true;
      std::size_t sent = 0;
      for (const PeerId& relay : neighbors) {
        if (sent >= cfg_.indirect_probes) {
          break;
        }
        if (relay == pr.target || relay == self_) {
          continue;
        }
        send_(relay, encode_ping_req(it->first, pr.target));
        ++sent;
      }
    }
    ++it;
  }
}

void FailureDetector::suspect(const PeerId& id, Clock::time_point now) {
  const auto cur = m_.find(id);
  if (!cur || cur->liveness != Liveness::alive) {
    return;  // unknown, or already suspect/dead
  }
  PeerInfo s = *cur;
  s.liveness = Liveness::suspect;  // same incarnation: suspect supersedes alive
  m_.apply(s);
  suspects_[id] = Suspicion{now, s.incarnation};
}

void FailureDetector::advance_suspicions(Clock::time_point now) {
  // suspect -> dead once the suspicion has stood long enough unrefuted.
  for (auto it = suspects_.begin(); it != suspects_.end();) {
    const PeerId id = it->first;
    const auto cur = m_.find(id);
    if (!cur || cur->liveness == Liveness::alive) {
      it = suspects_.erase(it);  // removed or refuted
      continue;
    }
    if (cur->liveness == Liveness::dead) {
      dead_since_.try_emplace(id, now);
      it = suspects_.erase(it);
      continue;
    }
    if (now - it->second.since >= cfg_.suspicion_timeout) {
      PeerInfo dead = *cur;
      dead.liveness = Liveness::dead;  // same incarnation: dead supersedes suspect
      m_.apply(dead);
      dead_since_[id] = now;
      it = suspects_.erase(it);
      continue;
    }
    ++it;
  }

  // dead -> removed after the cleanup grace.
  for (auto it = dead_since_.begin(); it != dead_since_.end();) {
    const auto cur = m_.find(it->first);
    if (!cur || cur->liveness != Liveness::dead) {
      it = dead_since_.erase(it);  // gone or recovered
      continue;
    }
    if (now - it->second >= cfg_.dead_cleanup) {
      m_.remove(it->first);
      it = dead_since_.erase(it);
      continue;
    }
    ++it;
  }
}

void FailureDetector::start_probe(Clock::time_point now,
                                  const std::vector<PeerId>& neighbors) {
  const std::size_t n = neighbors.size();
  if (n == 0) {
    return;
  }
  for (std::size_t off = 0; off < n; ++off) {
    const PeerId& cand = neighbors[(rr_ + off) % n];
    if (cand == self_) {
      continue;
    }
    const auto cur = m_.find(cand);
    if (!cur || cur->liveness == Liveness::dead) {
      continue;  // only probe peers we actually know and have not buried
    }
    bool already = false;
    for (const auto& [seq, pr] : pending_) {
      if (pr.target == cand) {
        already = true;
        break;
      }
    }
    if (already) {
      continue;
    }
    const std::uint64_t seq = next_seq_++;
    pending_[seq] = Probe{cand, now, false};
    send_(cand, encode_ping(seq));
    rr_ = (rr_ + off + 1) % n;
    return;
  }
}

bool FailureDetector::handle(Clock::time_point now, const PeerId& from,
                             std::span<const std::uint8_t> msg) {
  const auto type = peek_control_type(msg);
  if (!type) {
    return false;
  }
  switch (*type) {
    case ControlType::ping: {
      const auto p = decode_ping(msg);
      if (p) {
        send_(from, encode_ack(p->seq));
      }
      return true;
    }
    case ControlType::ack: {
      const auto a = decode_ack(msg);
      if (!a) {
        return true;
      }
      if (const auto itp = pending_.find(a->seq); itp != pending_.end()) {
        pending_.erase(itp);  // our probe succeeded
        return true;
      }
      if (const auto itr = relaying_.find(a->seq); itr != relaying_.end()) {
        send_(itr->second.requester, encode_ack(itr->second.orig_seq));
        relaying_.erase(itr);  // relayed the target's ack back to the requester
      }
      return true;
    }
    case ControlType::ping_req: {
      const auto pr = decode_ping_req(msg);
      if (pr) {
        const std::uint64_t relay_seq = next_seq_++;
        relaying_[relay_seq] = Relay{from, pr->seq, now};
        send_(pr->target, encode_ping(relay_seq));
      }
      return true;
    }
    case ControlType::membership:
      return false;  // not ours; the caller runs anti-entropy
  }
  return false;
}

}  // namespace tier::core
