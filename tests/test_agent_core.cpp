#include <array>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
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
using tier::agent::StoreOptions;

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

  // --- config: retention / size / snapshot units ---
  {
    std::string err;
    const auto c = parse_config(
        "role = collector\n[collector]\nstore = \"/data\"\n"
        "retention = \"7d\"\nmax_bytes = \"2GB\"\nsnapshot_interval = \"30s\"\n",
        err);
    check(c.has_value(), "retention config parses");
    if (c) {
      check(c->retention_secs == 7ULL * 24 * 3600, "7d -> seconds");
      check(c->max_bytes == 2ULL * 1024 * 1024 * 1024, "2GB -> bytes");
      check(c->snapshot_interval_secs == 30, "30s snapshot interval");
    }
    std::uint64_t throwaway = 0;
    (void)throwaway;
    check(!parse_config("role = collector\n[collector]\nretention = \"5x\"\n",
                        err),
          "bad duration unit rejected");
    check(!parse_config("role = collector\n[collector]\nmax_bytes = \"1TB\"\n",
                        err),
          "bad size unit rejected");
    const auto bare = parse_config(
        "role = collector\n[collector]\nretention = \"3600\"\n", err);
    check(bare && bare->retention_secs == 3600, "bare duration is seconds");
  }

  // --- config: query socket access group ---
  {
    std::string err;
    const auto config = parse_config(
        "role = collector\n[collector]\nquery_socket = \"/run/tier-agent/agent-query.sock\"\n"
        "query_socket_group = \"tier-monitor\"\n", err);
    check(config && config->query_socket_group == "tier-monitor", "query socket group parses");
    check(!parse_config("role = collector\n[collector]\nquery_socket_group = \"tier-monitor\"\n",
                        err),
          "query socket group requires a query socket");
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

  // --- store: persistence round-trip (snapshot + segment, directory layout) ---
  {
    namespace fs = std::filesystem;
    const std::string dir = "test_agent_store_tmp.d";
    fs::remove_all(dir);
    {
      Store s(dir);
      Envelope e;
      e.ts_unix = 55;
      e.samples.push_back({Kind::gauge, "mem", "512"});
      e.samples.push_back({Kind::event, "x", "hello world"});
      s.apply("S", e);
      s.flush();  // write the gauge snapshot
    }
    // The gauge went to a snapshot, the event to a segment - not one log.
    check(fs::exists(fs::path(dir) / "gauges.snap"), "gauge snapshot written");
    std::size_t segments = 0;
    for (const auto& de : fs::directory_iterator(dir)) {
      const auto name = de.path().filename().string();
      if (name.rfind("events-", 0) == 0) ++segments;
    }
    check(segments == 1, "one event segment written");

    Store reloaded(dir);
    check(reloaded.gauge_count() == 1 && reloaded.event_count() == 1,
          "store reloads gauges (snapshot) and events (segments)");
    const auto r = reloaded.render();
    check(r.find("S/mem 512") != std::string::npos, "reloaded gauge value");
    check(r.find("S/x hello world") != std::string::npos,
          "reloaded event value with spaces");
    check(reloaded.snapshot_json().find("\"received_unix\":null") != std::string::npos,
          "replayed samples have no collector receipt timestamp");
    fs::remove_all(dir);
  }

  // --- store: structured snapshot with sender filtering and display escaping ---
  {
    Store s("");
    s.set_clock([] { return 123ULL; });
    Envelope e;
    e.ts_unix = 55;
    e.samples = {{Kind::gauge, "state", "on\"\n"},
                 {Kind::event, "host.boot", "готово\xff"}};
    s.apply("A", e);
    s.apply("B", e);
    const auto snapshot = s.snapshot_json("A");
    check(snapshot ==
              "{\"version\":1,\"nodes\":[{\"sender\":\"A\",\"received_unix\":123,"
              "\"gauges\":[{\"key\":\"state\",\"value\":\"on\\\"\\u000a\",\"ts_unix\":55}]}],"
              "\"events\":[{\"sender\":\"A\",\"key\":\"host.boot\","
              "\"value\":\"готово\\ufffd\",\"ts_unix\":55}]}\n",
          "snapshot scopes to one sender and preserves valid UTF-8");
  }

  // --- store: gauge updates do not grow the event log (snapshot, not append) ---
  {
    namespace fs = std::filesystem;
    const std::string dir = "test_agent_store_gauge.d";
    fs::remove_all(dir);
    {
      Store s(dir);
      for (int i = 0; i < 100; ++i) {
        Envelope e;
        e.ts_unix = 1000 + static_cast<std::uint64_t>(i);
        e.samples.push_back({Kind::gauge, "cpu", std::to_string(i)});
        s.apply("S", e);
      }
      s.flush();
    }
    // 100 gauge updates collapse to one snapshot line and zero event segments.
    std::uintmax_t snap_lines = 0;
    {
      std::ifstream in(fs::path(dir) / "gauges.snap");
      std::string line;
      while (std::getline(in, line)) ++snap_lines;
    }
    check(snap_lines == 1, "100 gauge updates -> single snapshot line");
    bool any_segment = false;
    for (const auto& de : fs::directory_iterator(dir)) {
      if (de.path().filename().string().rfind("events-", 0) == 0) {
        any_segment = true;
      }
    }
    check(!any_segment, "gauge-only writes create no event segment");
    Store reloaded(dir);
    check(reloaded.gauge_count() == 1, "reloaded single gauge");
    check(reloaded.render().find("S/cpu 99") != std::string::npos,
          "gauge holds the last value after reload");
    fs::remove_all(dir);
  }

  // --- store: time-based retention drops old event segments ---
  {
    namespace fs = std::filesystem;
    const std::string dir = "test_agent_store_ret.d";
    fs::remove_all(dir);
    std::uint64_t fake_now = 1'000'000;
    StoreOptions opts;
    opts.retention_secs = 3600;    // keep 1h
    opts.segment_secs = 3600;      // 1h segments
    opts.snapshot_interval_secs = 1;
    Store s(dir, opts);
    s.set_clock([&fake_now] { return fake_now; });

    Envelope e1;
    e1.ts_unix = fake_now;
    e1.samples.push_back({Kind::event, "boot", "old"});
    s.apply("S", e1);  // lands in the segment for the current hour

    // Jump 3 hours ahead and write again: old segment is now outside retention.
    fake_now += 3 * 3600;
    Envelope e2;
    e2.ts_unix = fake_now;
    e2.samples.push_back({Kind::event, "boot", "new"});
    s.apply("S", e2);  // maybe_maintain sweeps the stale segment

    std::size_t segments = 0;
    for (const auto& de : fs::directory_iterator(dir)) {
      if (de.path().filename().string().rfind("events-", 0) == 0) ++segments;
    }
    check(segments == 1, "retention dropped the stale segment, kept the fresh");
    fs::remove_all(dir);
  }

  // --- store: size-based retention keeps the active segment ---
  {
    namespace fs = std::filesystem;
    const std::string dir = "test_agent_store_size.d";
    fs::remove_all(dir);
    std::uint64_t fake_now = 2'000'000;
    StoreOptions opts;
    opts.retention_secs = 0;       // time retention off; test size only
    opts.max_bytes = 1;            // tiny cap forces dropping all but active
    opts.segment_secs = 3600;
    opts.snapshot_interval_secs = 1;
    Store s(dir, opts);
    s.set_clock([&fake_now] { return fake_now; });

    for (int h = 0; h < 3; ++h) {
      Envelope e;
      e.ts_unix = fake_now;
      e.samples.push_back({Kind::event, "e", "payload-data"});
      s.apply("S", e);
      fake_now += 3600;  // next hour -> new segment
    }
    s.flush();  // final sweep under the 1-byte cap

    std::size_t segments = 0;
    for (const auto& de : fs::directory_iterator(dir)) {
      if (de.path().filename().string().rfind("events-", 0) == 0) ++segments;
    }
    check(segments == 1, "size cap drops oldest, never the active segment");
    fs::remove_all(dir);
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
