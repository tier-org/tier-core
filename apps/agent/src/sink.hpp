#pragma once

#include <string>

#include "envelope.hpp"

namespace tier::agent {

// A destination for authenticated telemetry. The collector de-duplicates each
// received message once and then fans it out to every configured sink, so a
// sink sees only first-seen, authorized messages. Implementations are the seam
// for pluggable storage: the built-in local file store is one Sink; remote
// sinks (Prometheus remote-write, InfluxDB line protocol, OTLP, ...) are added
// behind this same interface without touching the receive path.
//
// Contract: write() must not block the collector on a slow or unreachable
// backend - a remote sink buffers with a bounded, drop-oldest queue (metrics
// are lossy by design) rather than stalling receive. The local file sink writes
// synchronously, which is fine because it is local disk.
class Sink {
 public:
  Sink() = default;
  Sink(const Sink&) = delete;
  Sink& operator=(const Sink&) = delete;
  Sink(Sink&&) = delete;
  Sink& operator=(Sink&&) = delete;
  virtual ~Sink() = default;

  // Write one authenticated message's batch. `sender_hex` is the authenticated
  // sending user id (hex).
  virtual void write(const std::string& sender_hex, const Envelope& env) = 0;

  // Flush any buffered state to durable storage / the backend. A no-op for a
  // synchronous sink; buffering sinks override it (and call it on an interval
  // and at shutdown).
  virtual void flush() {}
};

}  // namespace tier::agent
