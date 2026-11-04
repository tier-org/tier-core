#include <cstdio>
#include <optional>
#include <vector>

#include "tier/core/admin.hpp"

namespace {

int g_failures = 0;

void check(bool ok, const char* what) {
  if (!ok) {
    std::fprintf(stderr, "FAIL: %s\n", what);
    ++g_failures;
  }
}

tier::core::PeerInfo peer(std::uint8_t tag, tier::core::RoleSet roles,
                          tier::core::Liveness liveness,
                          std::vector<std::string> addresses) {
  tier::core::PeerInfo info;
  info.id.fill(tag);
  info.roles = roles;
  info.incarnation = tag;
  info.liveness = liveness;
  info.addresses = std::move(addresses);
  return info;
}

}  // namespace

int main() {
  using tier::core::AdminOp;
  using tier::core::Liveness;
  using tier::core::Role;

  // Request round-trip and rejection of a bad version / op / trailing byte.
  {
    const auto req = tier::core::encode_admin_request(AdminOp::peers);
    const auto op = tier::core::decode_admin_request(req);
    check(op.has_value() && op->op == AdminOp::peers, "request round-trips");

    check(!tier::core::decode_admin_request({}).has_value(), "empty request rejected");
    std::vector<std::uint8_t> bad_ver{0x01, 0x01};  // version 1 is no longer spoken
    check(!tier::core::decode_admin_request(bad_ver).has_value(),
          "wrong version rejected");
    std::vector<std::uint8_t> bad_op{tier::core::kAdminVersion, 0x7F};
    check(!tier::core::decode_admin_request(bad_op).has_value(), "unknown op rejected");
    auto trailing = req;
    trailing.push_back(0x00);
    check(!tier::core::decode_admin_request(trailing).has_value(),
          "trailing byte in request rejected");

    // inbox request (no params) round-trips.
    const auto inbox_req = tier::core::encode_admin_request(AdminOp::inbox);
    const auto inbox_op = tier::core::decode_admin_request(inbox_req);
    check(inbox_op.has_value() && inbox_op->op == AdminOp::inbox,
          "inbox request round-trips");

    // id request (no params) round-trips.
    const auto id_req = tier::core::encode_admin_request(AdminOp::id);
    const auto id_op = tier::core::decode_admin_request(id_req);
    check(id_op.has_value() && id_op->op == AdminOp::id,
          "id request round-trips");

    // send_user request round-trips like send.
    tier::core::PeerId user{};
    user.fill(0x5A);
    const std::vector<std::uint8_t> up = {1, 2, 3};
    const auto su_req = tier::core::encode_admin_send_user(
        user, 2, std::span<const std::uint8_t>(up.data(), up.size()));
    const auto su_op = tier::core::decode_admin_request(su_req);
    check(su_op.has_value() && su_op->op == AdminOp::send_user &&
              su_op->recipient == user && su_op->suite == 2 &&
              su_op->plaintext == up,
          "send_user request round-trips");
  }

  // id response round-trip: device id only, and device + user id.
  {
    tier::core::PeerId dev{};
    for (std::size_t i = 0; i < dev.size(); ++i) {
      dev[i] = static_cast<std::uint8_t>(i * 7 + 1);
    }
    // No user id.
    {
      tier::core::AdminId id;
      id.device_id = dev;
      const auto reply = tier::core::encode_admin_id_reply(id);
      const auto got = tier::core::decode_admin_id_reply(reply);
      check(got.has_value() && got->device_id == dev && !got->user_id,
            "id reply (device only) round-trips");
      auto trailing_id = reply;
      trailing_id.push_back(0x00);
      check(!tier::core::decode_admin_id_reply(trailing_id).has_value(),
            "id reply with trailing byte rejected");
    }
    // With a user id.
    {
      tier::core::PeerId usr{};
      usr.fill(0xC3);
      tier::core::AdminId id;
      id.device_id = dev;
      id.user_id = usr;
      const auto reply = tier::core::encode_admin_id_reply(id);
      const auto got = tier::core::decode_admin_id_reply(reply);
      check(got.has_value() && got->device_id == dev && got->user_id &&
                *got->user_id == usr,
            "id reply (device + user) round-trips");
      auto truncated = reply;
      truncated.pop_back();
      check(!tier::core::decode_admin_id_reply(truncated).has_value(),
            "truncated id reply rejected");
    }
  }

  // send request round-trip and bounds.
  {
    tier::core::PeerId to{};
    to.fill(0x5A);
    const std::vector<std::uint8_t> body = {'h', 'i'};
    const auto req = tier::core::encode_admin_send(to, 2, body);
    const auto dec = tier::core::decode_admin_request(req);
    check(dec.has_value() && dec->op == AdminOp::send, "send request op");
    check(dec && dec->recipient == to, "send recipient round-trips");
    check(dec && dec->suite == 2, "send suite round-trips");
    check(dec && dec->plaintext == body, "send plaintext round-trips");

    // Truncations are rejected without crashing.
    bool all_rejected = true;
    for (std::size_t n = 0; n < req.size(); ++n) {
      std::vector<std::uint8_t> prefix(req.begin(), req.begin() + static_cast<long>(n));
      if (tier::core::decode_admin_request(prefix).has_value()) {
        all_rejected = false;
        break;
      }
    }
    check(all_rejected, "every truncation of a send request is rejected");

    // An oversize declared length is rejected.
    std::vector<std::uint8_t> oversize = {tier::core::kAdminVersion,
                                          static_cast<std::uint8_t>(AdminOp::send)};
    oversize.insert(oversize.end(), to.begin(), to.end());
    oversize.push_back(2);                       // suite
    oversize.push_back(0xFF);                    // len = 0xFFFFFFFF (huge)
    oversize.push_back(0xFF);
    oversize.push_back(0xFF);
    oversize.push_back(0xFF);
    check(!tier::core::decode_admin_request(oversize).has_value(),
          "oversize send plaintext length rejected");
  }

  // send reply round-trip.
  {
    check(tier::core::decode_admin_send_reply(tier::core::encode_admin_send_reply(true)) ==
              std::optional<bool>(true),
          "send reply ok round-trips");
    check(tier::core::decode_admin_send_reply(tier::core::encode_admin_send_reply(false)) ==
              std::optional<bool>(false),
          "send reply fail round-trips");
  }

  // inbox reply round-trip (two messages, including an empty one).
  {
    std::vector<tier::core::AdminInboxMessage> msgs;
    tier::core::AdminInboxMessage m1;
    m1.sender.fill(0x11);
    m1.suite = 1;
    m1.plaintext = {'a', 'b', 'c'};
    tier::core::AdminInboxMessage m2;
    m2.sender.fill(0x22);
    tier::core::PeerId u2{};
    u2.fill(0x77);
    m2.sender_user = u2;  // this one carries an authenticated user sender
    m2.suite = 3;
    m2.plaintext = {};
    msgs.push_back(m1);
    msgs.push_back(m2);
    const auto enc = tier::core::encode_admin_inbox(msgs);
    const auto dec = tier::core::decode_admin_inbox(enc);
    check(dec.has_value() && dec->size() == 2, "inbox reply count round-trips");
    if (dec && dec->size() == 2) {
      check((*dec)[0].sender == m1.sender && !(*dec)[0].sender_user &&
                (*dec)[0].suite == 1 && (*dec)[0].plaintext == m1.plaintext,
            "inbox message 1 (no user) round-trips");
      check((*dec)[1].sender == m2.sender && (*dec)[1].sender_user &&
                *(*dec)[1].sender_user == u2 && (*dec)[1].suite == 3 &&
                (*dec)[1].plaintext.empty(),
            "inbox message 2 (with user) round-trips");
    }
    auto trailing = enc;
    trailing.push_back(0x00);
    check(!tier::core::decode_admin_inbox(trailing).has_value(),
          "trailing byte in inbox reply rejected");
    bool all_rejected = true;
    for (std::size_t n = 0; n < enc.size(); ++n) {
      std::vector<std::uint8_t> prefix(enc.begin(), enc.begin() + static_cast<long>(n));
      if (tier::core::decode_admin_inbox(prefix).has_value()) {
        all_rejected = false;
        break;
      }
    }
    check(all_rejected, "every truncation of an inbox reply is rejected");
  }

  // Peers response round-trip: three peers, a two-member connected subset.
  std::vector<tier::core::PeerInfo> peers;
  peers.push_back(peer(0x01, tier::core::role_bit(Role::validator) |
                                 tier::core::role_bit(Role::keeper),
                       Liveness::alive, {"1.2.3.4:7777", "[2001:db8::1]:7777"}));
  peers.push_back(peer(0x02, tier::core::role_bit(Role::client), Liveness::suspect,
                       {}));
  peers.push_back(peer(0x03, tier::core::role_bit(Role::transmitter),
                       Liveness::dead, {"[2001:db8::3]:7777"}));
  peers[0].version = "0.2.4";
  peers[1].version = "";  // an older peer that advertised no version
  peers[2].version = "0.3.0";

  std::vector<tier::core::PeerId> connected;
  connected.push_back(peers[0].id);
  connected.push_back(peers[2].id);

  const auto encoded = tier::core::encode_admin_peers("mainnet", peers, connected);
  const auto decoded = tier::core::decode_admin_peers(encoded);
  check(decoded.has_value(), "peers response decodes");
  check(decoded && decoded->network == "mainnet", "network round-trips");
  check(decoded && decoded->peers.size() == peers.size(),
        "peer count round-trips");
  if (decoded && decoded->peers.size() == peers.size()) {
    const auto& dp = decoded->peers;
    for (std::size_t i = 0; i < peers.size(); ++i) {
      check(dp[i].info.id == peers[i].id, "id round-trips");
      check(dp[i].info.roles == peers[i].roles, "roles round-trip");
      check(dp[i].info.liveness == peers[i].liveness, "liveness round-trips");
      check(dp[i].info.addresses == peers[i].addresses, "addresses round-trip");
      check(dp[i].info.version == peers[i].version, "version round-trips");
    }
    check(dp[0].connected, "peer 1 reported connected");
    check(!dp[1].connected, "peer 2 reported not connected");
    check(dp[2].connected, "peer 3 reported connected");
  }

  // A trailing byte is rejected.
  {
    auto trailing = encoded;
    trailing.push_back(0xAA);
    check(!tier::core::decode_admin_peers(trailing).has_value(),
          "trailing byte in response rejected");
  }

  // Every truncation is rejected without crashing.
  {
    bool all_rejected = true;
    for (std::size_t n = 0; n < encoded.size(); ++n) {
      std::vector<std::uint8_t> prefix(encoded.begin(),
                                       encoded.begin() + static_cast<long>(n));
      if (tier::core::decode_admin_peers(prefix).has_value()) {
        all_rejected = false;
        break;
      }
    }
    check(all_rejected, "every truncation of the response is rejected");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
