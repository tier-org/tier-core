// tier-agent: a thin application-layer actor over the tierd admin socket. One
// binary, role chosen by config (the serf/consul "agent" model):
//   - agent     : collect line-protocol samples (from stdin, or by running an
//                 `exec` command each interval) and ship them to the collector,
//                 batched one envelope per interval
//   - collector : subscribe to its own user, store received samples (gauges +
//                 events) durably, de-duplicated and authenticated per sender,
//                 and optionally serve a local read socket (`query_socket`)
//   - both      : run a collector (thread) and an agent (main) at once
// It embeds no network node - it drives a running tierd exactly as the messenger
// does (add_user / send_as / subscribe). Nothing in the core changes.
//
// There is also a one-shot read client:
//   tier-agent query <socket> [needle]
// which prints a collector's store snapshot (optionally filtered) and exits.
//
// MVP scope: delivery is best-effort online-only (a send while the collector is
// unreachable is dropped, not spooled - fine for metrics, which are lossy by
// design); guaranteed delivery is a future paid/keeper layer. The collector's
// durable store plus the query socket are the read path. spool-on-offline and
// the keeper HA path are the next increments.
#include <poll.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "admin_client.hpp"
#include "batcher.hpp"
#include "config.hpp"
#include "envelope.hpp"
#include "store.hpp"
#include "tier/app/registry.hpp"
#include "tier/core/address.hpp"
#include "tier/crypto/identity.hpp"

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true); }

std::string to_hex(const tier::core::PeerId& id) {
  static const char* const kHex = "0123456789abcdef";
  std::string out;
  out.reserve(id.size() * 2);
  for (const auto b : id) {
    out += kHex[b >> 4];
    out += kHex[b & 0x0F];
  }
  return out;
}

std::uint64_t now_unix() {
  return static_cast<std::uint64_t>(std::time(nullptr));
}

// Sleep up to `secs`, waking early (within ~200ms) when a stop is requested.
void interruptible_sleep(std::uint32_t secs) {
  for (std::uint32_t i = 0; i < secs * 5 && !g_stop.load(); ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

// Load the 32-byte identity seed from `path`, creating a fresh random one (via
// the system CSPRNG) on first run. Returns false on an I/O error.
bool load_or_create_seed(const std::string& path,
                         std::array<std::uint8_t, 32>& out) {
  std::ifstream in(path, std::ios::binary);
  if (in) {
    std::vector<char> raw((std::istreambuf_iterator<char>(in)),
                          std::istreambuf_iterator<char>());
    if (raw.size() == out.size()) {
      std::memcpy(out.data(), raw.data(), out.size());
      return true;
    }
  }
  const auto id = tier::crypto::NodeIdentity::generate();
  const auto& seed = id.seed();
  std::memcpy(out.data(), seed.data(), out.size());
  std::ofstream of(path, std::ios::binary | std::ios::trunc);
  if (!of) {
    std::fprintf(stderr, "error: cannot write seed file: %s\n", path.c_str());
    return false;
  }
  of.write(reinterpret_cast<const char*>(out.data()),
           static_cast<std::streamsize>(out.size()));
  return static_cast<bool>(of);
}

// --- agent side -----------------------------------------------------------

// Ship whatever is buffered as one envelope. No-op when the buffer is empty.
void flush(tier::agent::AdminClient& client, const tier::core::PeerId& self,
           const tier::core::PeerId& collector, tier::agent::Batcher& batcher,
           std::uint64_t& seq) {
  if (batcher.empty()) return;
  const auto env = batcher.drain(seq++, now_unix());
  const auto status =
      client.send_telemetry(self, collector, tier::agent::encode(env));
  if (status != tier::core::SendStatus::accepted) {
    std::fprintf(stderr, "warn: batch not accepted (%d); %zu sample(s) dropped\n",
                 static_cast<int>(status), env.samples.size());
  }
}

// Split accumulated bytes into complete lines, parse each, and buffer it. Keeps
// the trailing partial line in `carry` for the next read.
void ingest_bytes(std::string& carry, const char* data, std::size_t n,
                  tier::agent::Batcher& batcher) {
  carry.append(data, n);
  std::size_t pos;
  while ((pos = carry.find('\n')) != std::string::npos) {
    const std::string line = carry.substr(0, pos);
    carry.erase(0, pos + 1);
    if (const auto s = tier::agent::parse_sample_line(line)) batcher.add(*s);
  }
}

// Agent mode reading ingest lines from stdin, flushing one envelope per interval
// (or early once the batch fills). poll() owns both reading and the flush timer.
void run_agent_stdin(tier::agent::AdminClient& client,
                     const tier::core::PeerId& self,
                     const tier::agent::Config& cfg) {
  tier::agent::Batcher batcher(cfg.max_batch);
  std::uint64_t seq = 0;
  std::string carry;
  struct pollfd pfd {};
  pfd.fd = STDIN_FILENO;
  pfd.events = POLLIN;
  auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(cfg.interval_secs);
  bool eof = false;
  while (!g_stop.load() && !eof) {
    const auto now = std::chrono::steady_clock::now();
    const int timeout_ms =
        deadline > now
            ? static_cast<int>(
                  std::chrono::duration_cast<std::chrono::milliseconds>(
                      deadline - now)
                      .count())
            : 0;
    const int r = ::poll(&pfd, 1, timeout_ms);
    if (r < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (r > 0 && (pfd.revents & (POLLIN | POLLHUP)) != 0) {
      char buf[4096];
      const ssize_t n = ::read(STDIN_FILENO, buf, sizeof buf);
      if (n > 0) {
        ingest_bytes(carry, buf, static_cast<std::size_t>(n), batcher);
      } else {
        eof = true;  // stdin closed
      }
    }
    if (batcher.full() || std::chrono::steady_clock::now() >= deadline || eof) {
      flush(client, self, cfg.collector, batcher, seq);
      deadline = std::chrono::steady_clock::now() +
                 std::chrono::seconds(cfg.interval_secs);
    }
  }
  flush(client, self, cfg.collector, batcher, seq);  // final drain
}

// Agent mode that runs `cfg.exec` every interval and parses its stdout as ingest
// lines (serf-like: a script that emits the host's current state each tick).
void run_agent_exec(tier::agent::AdminClient& client,
                    const tier::core::PeerId& self,
                    const tier::agent::Config& cfg) {
  tier::agent::Batcher batcher(cfg.max_batch);
  std::uint64_t seq = 0;
  while (!g_stop.load()) {
    FILE* p = ::popen(cfg.exec.c_str(), "r");
    if (p == nullptr) {
      std::fprintf(stderr, "warn: cannot run exec: %s\n", cfg.exec.c_str());
    } else {
      char line[4096];
      while (std::fgets(line, sizeof line, p) != nullptr) {
        std::string l(line);
        if (!l.empty() && l.back() == '\n') l.pop_back();
        if (const auto s = tier::agent::parse_sample_line(l)) batcher.add(*s);
      }
      ::pclose(p);
    }
    flush(client, self, cfg.collector, batcher, seq);
    interruptible_sleep(cfg.interval_secs);
  }
}

void run_agent(tier::agent::AdminClient& client, const tier::core::PeerId& self,
               const tier::agent::Config& cfg) {
  if (!cfg.exec.empty()) {
    run_agent_exec(client, self, cfg);
  } else {
    run_agent_stdin(client, self, cfg);
  }
}

// --- collector side -------------------------------------------------------

// Serve the store over a UNIX socket: each connection sends an optional filter
// line and receives the (filtered) snapshot, one-shot. Access to `store` is
// serialized with `mu` because the collector's receive loop writes concurrently.
void run_query_server(const std::string& path, tier::agent::Store& store,
                      std::mutex& mu) {
  ::unlink(path.c_str());
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    std::perror("query: socket");
    return;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path)) {
    std::fprintf(stderr, "query: socket path too long: %s\n", path.c_str());
    ::close(fd);
    return;
  }
  std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
    std::perror("query: bind");
    ::close(fd);
    return;
  }
  if (::listen(fd, 8) != 0) {
    std::perror("query: listen");
    ::close(fd);
    return;
  }
  struct pollfd pfd {};
  pfd.fd = fd;
  pfd.events = POLLIN;
  while (!g_stop.load()) {
    const int r = ::poll(&pfd, 1, 500);
    if (r < 0) {
      if (errno == EINTR) continue;
      break;
    }
    if (r == 0) continue;
    const int cfd = ::accept(fd, nullptr, nullptr);
    if (cfd < 0) continue;
    std::string needle;
    char b[256];
    const ssize_t n = ::recv(cfd, b, sizeof b, 0);
    if (n > 0) {
      needle.assign(b, static_cast<std::size_t>(n));
      const auto nl = needle.find('\n');
      if (nl != std::string::npos) needle.resize(nl);
    }
    while (!needle.empty() &&
           (needle.back() == '\r' || needle.back() == ' ')) {
      needle.pop_back();
    }
    std::string out;
    {
      std::lock_guard<std::mutex> lk(mu);
      out = store.query(needle);
    }
    ::send(cfd, out.data(), out.size(), MSG_NOSIGNAL);
    ::close(cfd);
  }
  ::close(fd);
  ::unlink(path.c_str());
}

void run_collector(tier::agent::AdminClient& client,
                   const tier::core::PeerId& self,
                   const tier::agent::Config& cfg) {
  tier::agent::Store store(cfg.store_path);
  std::mutex store_mu;

  std::thread qthread;
  if (!cfg.query_socket.empty()) {
    qthread = std::thread(run_query_server, std::cref(cfg.query_socket),
                          std::ref(store), std::ref(store_mu));
  }

  // Subscribe to our own user's stream and keep it alive across tierd restarts:
  // on any drop, re-subscribe on a backoff so telemetry resumes (and our
  // presence enrollment is re-established) once tierd is back. Only a real stop
  // (signal) ends the loop; a stream error must not kill the collector.
  std::array<std::uint8_t, 4096> buf{};
  std::uint32_t backoff = 0;
  while (!g_stop.load()) {
    const int fd = client.open_stream(self);
    if (fd < 0) {
      backoff = backoff ? (backoff < 4 ? backoff * 2 : 4) : 1;
      interruptible_sleep(backoff);  // tierd unreachable: wait and retry
      continue;
    }
    backoff = 0;  // reset after a good subscribe
    tier::agent::StreamParser parser;
    while (!g_stop.load()) {
      const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
      if (n <= 0) break;  // stream dropped -> reconnect
      parser.feed(buf.data(), static_cast<std::size_t>(n));
      for (;;) {
        auto ev = parser.next();
        if (!ev) break;
        if (ev->kind != tier::core::AdminStreamKind::message) continue;
        const auto& m = ev->message;
        if (m.type != static_cast<std::uint16_t>(tier::app::AppType::telemetry)) {
          continue;
        }
        if (!cfg.accept_from.empty()) {
          bool allowed = false;
          for (const auto& a : cfg.accept_from) {
            if (a == m.sender_user) { allowed = true; break; }
          }
          if (!allowed) continue;  // not on the allowlist
        }
        std::lock_guard<std::mutex> lk(store_mu);
        if (!store.first_seen(m.msg_id)) continue;  // duplicate
        const auto env = tier::agent::decode(m.payload.data(), m.payload.size());
        if (!env) continue;  // not a telemetry envelope
        store.apply(to_hex(m.sender_user), *env);
      }
    }
    ::close(fd);
    if (g_stop.load()) break;
    backoff = backoff ? (backoff < 4 ? backoff * 2 : 4) : 1;
    interruptible_sleep(backoff);  // tierd restart/blip: back off, re-subscribe
  }
  g_stop.store(true);
  if (qthread.joinable()) qthread.join();
}

// --- query client ---------------------------------------------------------

// One-shot read client: connect to a collector's query socket, send `needle`,
// print the snapshot it returns. Returns a process exit code.
int run_query_client(const std::string& path, const std::string& needle) {
  const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
  if (fd < 0) {
    std::perror("query: socket");
    return 1;
  }
  sockaddr_un addr{};
  addr.sun_family = AF_UNIX;
  if (path.size() >= sizeof(addr.sun_path)) {
    std::fprintf(stderr, "query: socket path too long: %s\n", path.c_str());
    ::close(fd);
    return 1;
  }
  std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
  if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0) {
    std::fprintf(stderr, "query: cannot connect to %s: %s\n", path.c_str(),
                 std::strerror(errno));
    ::close(fd);
    return 1;
  }
  std::string req = needle;
  req.push_back('\n');
  ::send(fd, req.data(), req.size(), MSG_NOSIGNAL);
  ::shutdown(fd, SHUT_WR);
  char b[4096];
  ssize_t n;
  while ((n = ::recv(fd, b, sizeof b, 0)) > 0) {
    std::fwrite(b, 1, static_cast<std::size_t>(n), stdout);
  }
  ::close(fd);
  return 0;
}

void usage() {
  std::fprintf(stderr,
               "usage:\n"
               "  tier-agent --config <file.toml>     run the daemon\n"
               "  tier-agent query <socket> [needle]  read a collector store\n");
}

}  // namespace

int main(int argc, char** argv) {
  // Read client subcommand: tier-agent query <socket> [needle]
  if (argc >= 2 && std::strcmp(argv[1], "query") == 0) {
    if (argc < 3) {
      usage();
      return 2;
    }
    const std::string sock = argv[2];
    const std::string needle = (argc >= 4) ? argv[3] : "";
    return run_query_client(sock, needle);
  }

  std::string config_path;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--config") == 0 && i + 1 < argc) {
      config_path = argv[++i];
    } else {
      usage();
      return 2;
    }
  }
  if (config_path.empty()) {
    usage();
    return 2;
  }

  std::ifstream cf(config_path);
  if (!cf) {
    std::fprintf(stderr, "error: cannot open config: %s\n", config_path.c_str());
    return 1;
  }
  const std::string text((std::istreambuf_iterator<char>(cf)),
                         std::istreambuf_iterator<char>());
  std::string err;
  const auto cfg = tier::agent::parse_config(text, err);
  if (!cfg) {
    std::fprintf(stderr, "error: config: %s\n", err.c_str());
    return 1;
  }

  const tier::agent::Config& conf = *cfg;

  std::array<std::uint8_t, 32> seed{};
  if (!load_or_create_seed(conf.seed_file, seed)) return 1;

  tier::agent::AdminClient client(conf.admin_socket);

  std::signal(SIGINT, on_signal);
  std::signal(SIGTERM, on_signal);

  // Enroll this actor's identity. add_user is idempotent - tierd persists the
  // user seed and re-hosts it on restart - so retry on a backoff rather than
  // exiting when tierd is not up yet or is restarting: the agent must ride
  // through that transparently.
  tier::core::PeerId self{};
  bool have_user = false;
  for (std::uint32_t backoff = 0; !g_stop.load();) {
    if (const auto u = client.add_user(seed)) {
      self = *u;
      have_user = true;
      break;
    }
    backoff = backoff ? (backoff < 4 ? backoff * 2 : 4) : 1;
    std::fprintf(stderr, "tier-agent: tierd unreachable at %s; retry in %us\n",
                 conf.admin_socket.c_str(), backoff);
    interruptible_sleep(backoff);
  }
  if (!have_user) return 0;  // asked to stop before tierd became reachable
  std::fprintf(stderr, "tier-agent: user %s\n  address: %s\n",
               to_hex(self).c_str(),
               tier::core::address_from_id(self).c_str());

  if (conf.role == tier::agent::Role::collector) {
    run_collector(client, self, conf);
  } else if (conf.role == tier::agent::Role::agent) {
    run_agent(client, self, conf);
  } else {  // both
    std::thread collector(run_collector, std::ref(client), std::cref(self),
                          std::cref(conf));
    run_agent(client, self, conf);
    g_stop.store(true);
    collector.join();
  }
  return 0;
}
