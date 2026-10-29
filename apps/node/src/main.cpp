#include <charconv>
#include <cstdint>
#include <cstdio>
#include <span>
#include <string_view>
#include <system_error>
#include <vector>

#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"
#include "tier/net/endpoint.hpp"

namespace {

void print_hex(const char* label, std::span<const tier::crypto::Byte> bytes) {
  std::fputs(label, stdout);
  for (const auto b : bytes) {
    std::printf("%02x", static_cast<unsigned>(b));
  }
  std::fputc('\n', stdout);
}

int usage() {
  std::fputs(
      "usage:\n"
      "  tier-node listen <port>\n"
      "  tier-node connect <ip> <port>\n",
      stderr);
  return 2;
}

bool parse_port(std::string_view text, std::uint16_t& out) {
  unsigned value = 0;
  const auto* const end = text.data() + text.size();
  const auto result = std::from_chars(text.data(), end, value);
  if (result.ec != std::errc{} || result.ptr != end || value > 65535) {
    return false;
  }
  out = static_cast<std::uint16_t>(value);
  return true;
}

int run_listen(const tier::crypto::NodeIdentity& identity, std::uint16_t port) {
  tier::net::Endpoint ep(identity, "0.0.0.0", port);
  ep.set_auto_echo(true);
  ep.on_handshake([](const tier::net::PeerId& peer) {
    print_hex("peer connected: ", peer);
    std::fflush(stdout);
  });
  ep.on_message([](const tier::net::PeerId&,
                   std::span<const tier::crypto::Byte> payload) {
    std::printf("echoed %zu bytes\n", payload.size());
    std::fflush(stdout);
  });

  print_hex("node id:  ", identity.public_key());
  std::printf("listening on 0.0.0.0:%u\n", static_cast<unsigned>(ep.local_port()));
  std::fflush(stdout);
  for (;;) {
    ep.poll(1000);
  }
}

int run_connect(const tier::crypto::NodeIdentity& identity, const char* ip,
                std::uint16_t port) {
  tier::net::Endpoint ep(identity, "0.0.0.0", 0);
  const std::vector<tier::crypto::Byte> ping{0x70, 0x69, 0x6E, 0x67};  // "ping"
  ep.set_auto_ping(ping);

  bool got_echo = false;
  ep.on_handshake(
      [](const tier::net::PeerId& peer) { print_hex("connected to: ", peer); });
  ep.on_message([&](const tier::net::PeerId&,
                    std::span<const tier::crypto::Byte> payload) {
    print_hex("echo:         ", payload);
    got_echo = true;
  });

  print_hex("node id:      ", identity.public_key());
  ep.connect(ip, port);
  for (int i = 0; i < 5000 && !got_echo; ++i) {
    ep.poll(5);
  }
  if (!got_echo) {
    std::fputs("no echo received\n", stderr);
    return 1;
  }
  std::printf("kex group:    %s\n", ep.last_negotiated_group().c_str());
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc < 2) {
    return usage();
  }

  const auto identity = tier::crypto::NodeIdentity::generate();
  const std::string_view cmd = argv[1];

  if (cmd == "listen") {
    std::uint16_t port = 0;
    if (argc != 3 || !parse_port(argv[2], port)) {
      return usage();
    }
    return run_listen(identity, port);
  }

  if (cmd == "connect") {
    std::uint16_t port = 0;
    if (argc != 4 || !parse_port(argv[3], port)) {
      return usage();
    }
    return run_connect(identity, argv[2], port);
  }

  return usage();
}
