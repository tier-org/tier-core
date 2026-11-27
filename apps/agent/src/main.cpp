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
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "admin_client.hpp"
#include "batcher.hpp"
#include "bootstrap.hpp"
#include "config.hpp"
#include "envelope.hpp"
#include "files.hpp"
#include "socket_io.hpp"
#include "store.hpp"
#include "tier/app/registry.hpp"
#include "tier/core/address.hpp"

namespace {

std::atomic<bool> g_stop{false};

void on_signal(int) { g_stop.store(true); }

// Install SIGINT/SIGTERM via sigaction with no SA_RESTART, so that a signal
// interrupts the blocking syscalls the roles park in (recv in the collector
// subscribe loop, accept in the query server, read on stdin): they return EINTR
// and the loop re-checks g_stop. std::signal() would restart them (glibc gives
// BSD semantics with SA_RESTART set), leaving the process stuck until traffic
// arrives, so Ctrl+C would not stop it.
void install_signal_handlers() {
  struct sigaction sa{};
  sa.sa_handler = on_signal;
  ::sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;  // no SA_RESTART: let blocking syscalls fail with EINTR
  ::sigaction(SIGINT, &sa, nullptr);
  ::sigaction(SIGTERM, &sa, nullptr);
}

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
  for (std::uint64_t i = 0; i < static_cast<std::uint64_t>(secs) * 5 &&
                           !g_stop.load();
       ++i) {
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
  }
}

// --- agent side -----------------------------------------------------------

// Ship whatever is buffered. A batch larger than the admin socket's plaintext
// budget is split into several envelopes rather than dropped whole; only a single
// sample that cannot fit an envelope on its own is dropped (with a warning).
void flush(tier::agent::AdminClient& client, const tier::core::PeerId& self,
           const tier::core::PeerId& collector, tier::agent::Batcher& batcher,
           std::uint64_t& seq) {
  if (batcher.empty()) return;
  const auto env = batcher.drain(seq, now_unix());
  std::size_t dropped = 0;
  auto parts = tier::agent::split(env, tier::agent::kMaxEnvelopeBytes, dropped);
  if (dropped != 0) {
    std::fprintf(stderr, "warn: %zu sample(s) too large to ship, dropped\n",
                 dropped);
  }
  for (auto& part : parts) {
    part.seq = seq++;
    const auto wire = tier::agent::encode(part);
    if (!wire) {  // split() already checked the limits; defensive only
      std::fprintf(stderr, "warn: batch %llu failed to encode, dropped\n",
                   static_cast<unsigned long long>(part.seq));
      continue;
    }
    const auto status = client.send_telemetry(self, collector, *wire);
    if (status != tier::core::SendStatus::accepted) {
      std::fprintf(stderr,
                   "warn: batch %llu not accepted (%d); %zu sample(s) dropped\n",
                   static_cast<unsigned long long>(part.seq),
                   static_cast<int>(status), part.samples.size());
    }
  }
}

// Split accumulated bytes into complete lines, parse each, and buffer it. Keeps
// the trailing partial line in `carry` for the next read.
void ingest_bytes(std::string& carry, const char* data, std::size_t n,
                  tier::agent::Batcher& batcher) {
  carry.append(data, n);
  // A source that never sends a newline must not grow the buffer without bound.
  // No valid ingest line can be this long (see kMaxValueLen).
  if (carry.size() > tier::agent::kMaxValueLen + tier::agent::kMaxKeyLen) {
    std::fprintf(stderr, "warn: ingest line too long, discarded\n");
    carry.clear();
    return;
  }
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
    const auto remaining_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
            .count();
    const int timeout_ms = remaining_ms > 0
                               ? static_cast<int>(std::min<std::uint64_t>(
                                     static_cast<std::uint64_t>(remaining_ms),
                                     1000))
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

// Run `sh -c cmd`, forwarding stdout in chunks, with a hard deadline. popen()
// cannot be bounded: a hung script would block the agent forever (pclose waits
// for it). Fork + poll + kill keeps one bad collector script from wedging the
// agent, and lets a signal stop it promptly.
template <typename OnChunk>
void run_exec_capture(const std::string& cmd, std::uint32_t timeout_secs,
                      OnChunk on_chunk) {
  int fds[2];
  if (::pipe2(fds, O_CLOEXEC) != 0) {
    std::perror("exec: pipe");
    return;
  }
  const pid_t pid = ::fork();
  if (pid < 0) {
    std::perror("exec: fork");
    ::close(fds[0]);
    ::close(fds[1]);
    return;
  }
  if (pid == 0) {
    ::close(fds[0]);
    if (fds[1] != STDOUT_FILENO) {
      if (::dup2(fds[1], STDOUT_FILENO) < 0) ::_exit(127);
      ::close(fds[1]);
    }
    ::execl("/bin/sh", "sh", "-c", cmd.c_str(), nullptr);
    ::_exit(127);
  }
  ::close(fds[1]);

  bool timed_out = false;
  const auto deadline =
      std::chrono::steady_clock::now() + std::chrono::seconds(timeout_secs);
  std::array<char, 4096> buf{};
  while (!g_stop.load()) {
    const auto now = std::chrono::steady_clock::now();
    // Cap each wait so a very large configured interval cannot overflow int.
    const auto remaining_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now)
            .count();
    const int wait_ms = remaining_ms > 0
                            ? static_cast<int>(std::min<std::uint64_t>(
                                  static_cast<std::uint64_t>(remaining_ms),
                                  1000))
                            : 0;
    pollfd pfd{};
    pfd.fd = fds[0];
    pfd.events = POLLIN;
    const int r = ::poll(&pfd, 1, wait_ms);
    if (r < 0) {
      if (errno == EINTR) continue;
      std::perror("exec: poll");
      break;
    }
    if (r == 0) {
      timed_out = true;
      break;
    }
    if ((pfd.revents & (POLLIN | POLLHUP | POLLERR)) == 0) continue;
    const ssize_t n = ::read(fds[0], buf.data(), buf.size());
    if (n > 0) {
      on_chunk(buf.data(), static_cast<std::size_t>(n));
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    break;  // EOF (or a read error): the script is done
  }
  ::close(fds[0]);

  // EOF on stdout is not proof that the script exited: it may have closed fd 1
  // and kept running. Reap with the same deadline instead of blocking forever.
  int status = 0;
  bool reaped = false;
  for (;;) {
    const pid_t r = ::waitpid(pid, &status, WNOHANG);
    if (r == pid) {
      reaped = true;
      break;
    }
    if (r < 0) {
      if (errno == EINTR) continue;
      break;  // ECHILD: nothing left to reap
    }
    if (g_stop.load() || std::chrono::steady_clock::now() >= deadline) {
      ::kill(pid, SIGKILL);
      if (!g_stop.load()) timed_out = true;
      while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {
      }
      break;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(20));
  }

  if (timed_out) {
    std::fprintf(stderr, "warn: exec timed out after %us: %s\n", timeout_secs,
                 cmd.c_str());
  } else if (!g_stop.load() && reaped && WIFEXITED(status) &&
             WEXITSTATUS(status) != 0) {
    std::fprintf(stderr, "warn: exec exited %d: %s\n", WEXITSTATUS(status),
                 cmd.c_str());
  } else if (!g_stop.load() && reaped && !WIFEXITED(status)) {
    std::fprintf(stderr, "warn: exec did not exit cleanly: %s\n", cmd.c_str());
  }
}

// Agent mode that runs `cfg.exec` every interval and parses its stdout as ingest
// lines (serf-like: a script that emits the host's current state each tick).
void run_agent_exec(tier::agent::AdminClient& client,
                    const tier::core::PeerId& self,
                    const tier::agent::Config& cfg) {
  tier::agent::Batcher batcher(cfg.max_batch);
  std::uint64_t seq = 0;
  std::string carry;
  while (!g_stop.load()) {
    run_exec_capture(cfg.exec, cfg.interval_secs,
                     [&](const char* data, std::size_t n) {
                       ingest_bytes(carry, data, n, batcher);
                       if (batcher.full()) flush(client, self, cfg.collector,
                                                 batcher, seq);
                     });
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

// One request line followed by one snapshot, then EOF. The reserved command
// selects JSON. Other requests are the human-readable query's substring filter.
std::string query_response(int fd, const tier::agent::Store& store) {
  std::string request;
  std::array<char, 256> buffer{};
  bool complete = false;
  while (request.size() < buffer.size()) {
    const ssize_t n = ::recv(fd, buffer.data(), buffer.size() - request.size(), 0);
    if (n < 0 && errno == EINTR && !g_stop.load()) continue;
    if (n <= 0) break;
    request.append(buffer.data(), static_cast<std::size_t>(n));
    const auto newline = request.find('\n');
    if (newline != std::string::npos) {
      request.resize(newline);
      complete = true;
      break;
    }
  }
  while (!request.empty() && (request.back() == '\r' || request.back() == ' ')) {
    request.pop_back();
  }
  // A truncated command must not be silently reinterpreted as a filter.
  if (!complete && !request.empty()) return "error: incomplete request\n";

  constexpr std::string_view command = "TIER-QUERY/1";
  if (request == command) return store.snapshot_json();
  constexpr std::string_view prefix = "TIER-QUERY/1 ";
  if (request.starts_with(prefix)) {
    const auto sender = std::string_view(request).substr(prefix.size());
    if (sender.size() == tier::core::PeerId{}.size() * 2 &&
        sender.find_first_not_of("0123456789abcdef") == std::string_view::npos) {
      return store.snapshot_json(sender);
    }
    return "{\"version\":1,\"error\":\"invalid sender ID\"}\n";
  }
  return store.query(request);
}

void run_query_server(const std::string& path, tier::agent::Store& store,
                      std::optional<gid_t> socket_group) {
  tier::agent::create_parent_dirs(path);
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
  if (socket_group &&
      (::chown(path.c_str(), static_cast<uid_t>(-1), *socket_group) != 0 ||
       ::chmod(path.c_str(), 0660) != 0)) {
    std::perror("query: set socket owner or mode");
    ::close(fd);
    ::unlink(path.c_str());
    return;
  }
  if (::listen(fd, 8) != 0) {
    std::perror("query: listen");
    ::close(fd);
    ::unlink(path.c_str());
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
    if (cfd < 0) {
      if (errno != EINTR && !g_stop.load()) {
        std::perror("query: accept");
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
      continue;
    }
    constexpr timeval timeout{2, 0};
    if (tier::agent::set_socket_timeout(cfd, timeout)) {
      const std::string response = query_response(cfd, store);
      if (!tier::agent::send_all(cfd, response)) {
        std::fprintf(stderr, "warn: query: short write to client\n");
      }
    }
    ::close(cfd);
  }
  ::close(fd);
  ::unlink(path.c_str());
}

void run_collector(tier::agent::AdminClient& client,
                   const tier::core::PeerId& self,
                   const tier::agent::Config& cfg,
                   std::optional<gid_t> socket_group) {
  tier::agent::StoreOptions sopts;
  sopts.retention_secs = cfg.retention_secs;
  sopts.max_bytes = cfg.max_bytes;
  sopts.snapshot_interval_secs = cfg.snapshot_interval_secs;
  tier::agent::Store store(cfg.store_path, sopts);

  // Fan out each de-duplicated, authorized message to every configured sink.
  // Today that is just the local file store (which also backs the query
  // socket); remote sinks (Prometheus remote-write, InfluxDB, ...) will be
  // appended here behind the same Sink interface, each with its own buffering so
  // a slow backend cannot stall receive.
  std::vector<tier::agent::Sink*> sinks{&store};

  std::thread qthread;
  if (!cfg.query_socket.empty()) {
    qthread = std::thread(run_query_server, std::cref(cfg.query_socket),
                          std::ref(store), socket_group);
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
      store.maintain();             // keep the snapshot fresh while offline
      continue;
    }
    backoff = 0;  // reset after a good subscribe
    tier::agent::StreamParser parser;
    while (!g_stop.load()) {
      const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
      if (n < 0) {
        if (errno == EINTR) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          store.maintain();  // idle tick: refresh gauges/retention on schedule
          continue;
        }
        std::perror("collector: recv");
        break;
      }
      if (n == 0) break;  // stream dropped -> reconnect
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
        if (!store.first_seen(m.msg_id)) continue;  // duplicate (Store locks)
        const auto env = tier::agent::decode(m.payload.data(), m.payload.size());
        if (!env) continue;  // not a telemetry envelope
        const tier::agent::Envelope& envelope = *env;
        const std::string sender_hex = to_hex(m.sender_user);
        for (tier::agent::Sink* sink : sinks) sink->write(sender_hex, envelope);
      }
    }
    ::close(fd);
    if (g_stop.load()) break;
    backoff = backoff ? (backoff < 4 ? backoff * 2 : 4) : 1;
    interruptible_sleep(backoff);  // tierd restart/blip: back off, re-subscribe
    store.flush();
  }
  g_stop.store(true);
  for (tier::agent::Sink* sink : sinks) sink->flush();  // persist on shutdown
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
  constexpr timeval timeout{2, 0};
  if (!tier::agent::set_socket_timeout(fd, timeout)) {
    std::perror("query: setsockopt");
    ::close(fd);
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
  if (!tier::agent::send_all(fd, req)) {
    std::perror("query: send");
    ::close(fd);
    return 1;
  }
  ::shutdown(fd, SHUT_WR);
  char b[4096];
  for (;;) {
    const ssize_t n = ::recv(fd, b, sizeof b, 0);
    if (n > 0) {
      std::fwrite(b, 1, static_cast<std::size_t>(n), stdout);
      continue;
    }
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) {
      std::perror("query: recv");
      ::close(fd);
      return 1;
    }
    break;
  }
  ::close(fd);
  return 0;
}

void usage() {
  std::fprintf(stderr,
               "usage:\n"
               "  tier-agent --config <file.toml>     run the daemon\n"
               "  tier-agent query <socket> [needle]  read a collector store\n"
               "  tier-agent bootstrap collector [--view]\n"
               "  tier-agent bootstrap client --collector=<address>\n");
}

}  // namespace

int main(int argc, char** argv) {
  if (argc >= 2 && std::strcmp(argv[1], "bootstrap") == 0) {
    return tier::agent::run_bootstrap(argc - 2, argv + 2);
  }
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

  std::optional<gid_t> socket_group;
  if (conf.role != tier::agent::Role::agent && !conf.query_socket_group.empty()) {
    const auto* group = ::getgrnam(conf.query_socket_group.c_str());
    if (group == nullptr) {
      std::fprintf(stderr, "error: cannot resolve query_socket_group: %s\n",
                   conf.query_socket_group.c_str());
      return 1;
    }
    socket_group = group->gr_gid;
  }

  tier::agent::Seed seed{};
  if (!tier::agent::load_or_create_seed(conf.seed_file, seed)) return 1;

  tier::agent::AdminClient client(conf.admin_socket);

  install_signal_handlers();

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
    run_collector(client, self, conf, socket_group);
  } else if (conf.role == tier::agent::Role::agent) {
    run_agent(client, self, conf);
  } else {  // both
    std::thread collector(run_collector, std::ref(client), std::cref(self),
                          std::cref(conf), socket_group);
    run_agent(client, self, conf);
    g_stop.store(true);
    collector.join();
  }
  return 0;
}
