#include <array>
#include <cstdint>
#include <cstdio>
#include <string>

#include "batcher.hpp"
#include "config.hpp"
#include "store.hpp"
#include "tier/core/address.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

using tier::agent::Batcher;
using tier::agent::Config;
using tier::agent::Envelope;
using tier::agent::Kind;
using tier::agent::parse_config;
using tier::agent::parse_sample_line;
using tier::agent::Role;
using tier::agent::Sample;
using tier::agent::Store;

tier::core::PeerId peer(std::uint8_t fill) {
  tier::core::PeerId p{};
  p.fill(fill);
  return p;
}

}  // namespace

int main() {
  const auto cp = peer(0xAB);
  const std::string caddr = tier::core::address_from_id(cp);

  // --- config: agent role ---
  {
    std::string err;
    const std::string text =
        "role = agent\nadmin_socket = \"/run/t.sock\"\n[agent]\ncollector = \"" +
        caddr + "\"\n";
    const auto c = parse_config(text, err);
    check(c.has_value(), "agent config parses");
    if (c) {
      check(c->role == Role::agent, "role is agent");
      check(c->has_collector && c->collector == cp, "collector resolved");
      check(c->admin_socket == "/run/t.sock", "admin_socket parsed");
    }
  }

  // --- config: collector role with allowlist + persistence ---
  {
    const auto a1 = tier::core::address_from_id(peer(0x11));
    const auto a2 = tier::core::address_from_id(peer(0x22));
    std::string err;
    const std::string text = "role = collector\n[collector]\nstore = \"/s.log\"\n"
                             "persistence = \"keeper\"\naccept_from = [\"" +
                             a1 + "\", \"" + a2 + "\"]\n";
    const auto c = parse_config(text, err);
    check(c.has_value(), "collector config parses");
    if (c) {
      check(c->role == Role::collector, "role is collector");
      check(c->store_path == "/s.log", "store path parsed");
      check(c->keeper_persistence, "keeper persistence parsed");
      check(c->accept_from.size() == 2 && c->accept_from[0] == peer(0x11) &&
                c->accept_from[1] == peer(0x22),
            "accept_from allowlist parsed");
    }
  }

  // --- config: error cases ---
  {
    std::string err;
    check(!parse_config("admin_socket = \"/x\"\n", err), "missing role rejected");
    check(!parse_config("role = agent\n", err),
          "agent without collector rejected");
    check(!parse_config("role = bogus\n", err), "bad role rejected");
    check(!parse_config("role = agent\n[agent]\ncollector = \"not-an-addr\"\n",
                        err),
          "bad collector address rejected");
    check(!parse_config("role = agent\nnope = 1\n", err),
          "unknown key rejected");
  }

  // --- config: batching + exec + query_socket keys ---
  {
    std::string err;
    const std::string text =
        "role = agent\n[agent]\ncollector = \"" + caddr +
        "\"\ninterval = 5\nmax_batch = 64\nexec = \"/opt/host-metrics.sh\"\n";
    const auto c = parse_config(text, err);
    check(c.has_value(), "agent batching config parses");
    if (c) {
      check(c->interval_secs == 5, "interval parsed");
      check(c->max_batch == 64, "max_batch parsed");
      check(c->exec == "/opt/host-metrics.sh", "exec parsed");
    }
  }
  {
    std::string err;
    const std::string text =
        "role = collector\n[collector]\nquery_socket = \"/run/t/q.sock\"\n";
    const auto c = parse_config(text, err);
    check(c.has_value(), "collector query_socket config parses");
    if (c) check(c->query_socket == "/run/t/q.sock", "query_socket parsed");
  }
  {
    std::string err;
    check(!parse_config("role = agent\n[agent]\ncollector = \"" + caddr +
                            "\"\ninterval = abc\n",
                        err),
          "non-numeric interval rejected");
    check(!parse_config("role = agent\n[agent]\ncollector = \"" + caddr +
                            "\"\ninterval = 0\n",
                        err),
          "zero interval rejected");
    check(!parse_config("role = agent\n[agent]\ncollector = \"" + caddr +
                            "\"\nmax_batch = 0\n",
                        err),
          "zero max_batch rejected");
    check(!parse_config("role = agent\n[agent]\ncollector = \"" + caddr +
                            "\"\ninterval = 99999999999\n",
                        err),
          "overflow interval rejected");
  }

  // --- batcher: gauge collapse, event append, fill, drain clears ---
  {
    Batcher b(3);
    check(b.empty(), "new batcher is empty");
    b.add({Kind::gauge, "cpu", "1"});
    b.add({Kind::gauge, "cpu", "2"});  // collapses, size stays 1
    check(b.size() == 1, "gauge collapses to one slot");
    check(!b.full(), "not full at 1/3");
    b.add({Kind::event, "boot", "a"});
    b.add({Kind::event, "boot", "b"});  // events do NOT collapse
    check(b.size() == 3, "two events both counted");
    check(b.full(), "full at 3/3");
    b.add({Kind::gauge, "mem", "7"});  // soft cap, still accepts
    check(b.size() == 4, "soft cap does not drop samples");

    const auto env = b.drain(9, 123);
    check(b.empty(), "drain clears the batcher");
    check(env.seq == 9 && env.ts_unix == 123, "drain stamps seq/ts");
    // 2 gauges (cpu latest=2, mem=7) + 2 events, order gauges-then-events.
    check(env.samples.size() == 4, "drain carries all distinct samples");
    std::string cpu_val, mem_val;
    int n_events = 0;
    for (const auto& s : env.samples) {
      if (s.kind == Kind::gauge && s.key == "cpu") cpu_val = s.value;
      if (s.kind == Kind::gauge && s.key == "mem") mem_val = s.value;
      if (s.kind == Kind::event) ++n_events;
    }
    check(cpu_val == "2", "gauge drained with latest value");
    check(mem_val == "7", "second gauge key retained");
    check(n_events == 2, "both events drained");

    const auto empty = b.drain(10, 200);
    check(empty.samples.empty(), "draining an empty batcher yields no samples");
  }

  // --- store: filtered query ---
  {
    Store s("");
    Envelope ea;
    ea.ts_unix = 10;
    ea.samples.push_back({Kind::gauge, "cpu", "5"});
    ea.samples.push_back({Kind::event, "boot", "up"});
    s.apply("aaaa", ea);
    Envelope eb;
    eb.ts_unix = 11;
    eb.samples.push_back({Kind::gauge, "cpu", "6"});
    s.apply("bbbb", eb);

    const auto all = s.query("");
    check(all == s.render(), "empty needle equals render");
    check(all.find("# gauges (2)") != std::string::npos, "two gauges unfiltered");

    const auto by_sender = s.query("aaaa");
    check(by_sender.find("aaaa/cpu 5") != std::string::npos,
          "sender filter keeps its gauge");
    check(by_sender.find("bbbb/cpu 6") == std::string::npos,
          "sender filter drops the other sender");
    check(by_sender.find("# gauges (1)") != std::string::npos,
          "filtered gauge count reflects the filter");
    check(by_sender.find("aaaa/boot up") != std::string::npos,
          "sender filter keeps its event");

    const auto by_key = s.query("cpu");
    check(by_key.find("# gauges (2)") != std::string::npos,
          "key filter keeps both cpu gauges");
    check(by_key.find("# events (0)") != std::string::npos,
          "key filter drops the boot event");

    const auto none = s.query("zzz");
    check(none.find("# gauges (0)") != std::string::npos &&
              none.find("# events (0)") != std::string::npos,
          "non-matching needle yields an empty snapshot");
  }

  // --- line protocol ---
  {
    const auto g = parse_sample_line("gauge cpu.load 0.42");
    check(g && g->kind == Kind::gauge && g->key == "cpu.load" &&
              g->value == "0.42",
          "gauge line");
    const auto e = parse_sample_line("e unit.sshd activating -> active");
    check(e && e->kind == Kind::event && e->key == "unit.sshd" &&
              e->value == "activating -> active",
          "event line keeps spaces in value");
    check(!parse_sample_line(""), "blank line ignored");
    check(!parse_sample_line("# comment"), "comment ignored");
    check(!parse_sample_line("gauge onlykey"), "missing value rejected");
    check(!parse_sample_line("bogus k v"), "unknown kind rejected");
  }

  // --- store: gauge overwrite, event append, dedup ---
  {
    Store s("");  // in-memory
    std::array<std::uint8_t, 16> m1{};
    m1.fill(1);
    check(s.first_seen(m1), "first msg_id is new");
    check(!s.first_seen(m1), "repeat msg_id is a duplicate");

    Envelope e1;
    e1.ts_unix = 100;
    e1.samples.push_back({Kind::gauge, "cpu", "1"});
    e1.samples.push_back({Kind::event, "boot", "up"});
    s.apply("senderA", e1);
    Envelope e2;
    e2.ts_unix = 200;
    e2.samples.push_back({Kind::gauge, "cpu", "2"});  // overwrites
    s.apply("senderA", e2);

    check(s.gauge_count() == 1, "gauge overwritten, not duplicated");
    check(s.event_count() == 1, "event appended");
    const auto r = s.render();
    check(r.find("senderA/cpu 2") != std::string::npos,
          "render shows latest gauge value");
    check(r.find("senderA/boot up") != std::string::npos,
          "render shows the event");
  }

  // --- store: persistence round-trip ---
  {
    const std::string path = "test_agent_store_tmp.log";
    std::remove(path.c_str());
    {
      Store s(path);
      Envelope e;
      e.ts_unix = 55;
      e.samples.push_back({Kind::gauge, "mem", "512"});
      e.samples.push_back({Kind::event, "x", "hello world"});
      s.apply("S", e);
    }
    Store reloaded(path);
    check(reloaded.gauge_count() == 1 && reloaded.event_count() == 1,
          "store reloads gauges and events from the log");
    const auto r = reloaded.render();
    check(r.find("S/mem 512") != std::string::npos, "reloaded gauge value");
    check(r.find("S/x hello world") != std::string::npos,
          "reloaded event value with spaces");
    std::remove(path.c_str());
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
