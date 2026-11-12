#include <array>
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

    // send_as request round-trips: from-user, to-user, suite, plaintext.
    tier::core::PeerId from{};
    from.fill(0x5A);
    tier::core::PeerId to{};
    to.fill(0x6B);
    const std::vector<std::uint8_t> up = {1, 2, 3};
    const auto sa_req = tier::core::encode_admin_send_as(
        from, to, 2, std::span<const std::uint8_t>(up.data(), up.size()));
    const auto sa_op = tier::core::decode_admin_request(sa_req);
    check(sa_op.has_value() && sa_op->op == AdminOp::send_as &&
              sa_op->from_user == from && sa_op->recipient == to &&
              sa_op->suite == 2 && sa_op->plaintext == up,
          "send_as request round-trips");

    // user_list request (no params) round-trips.
    const auto ul_req = tier::core::encode_admin_request(AdminOp::user_list);
    const auto ul_op = tier::core::decode_admin_request(ul_req);
    check(ul_op.has_value() && ul_op->op == AdminOp::user_list,
          "user_list request round-trips");

    // user_add request round-trips, generate (no seed) and import (seed).
    const auto ua_gen_op =
        tier::core::decode_admin_request(tier::core::encode_admin_user_add(std::nullopt));
    check(ua_gen_op.has_value() && ua_gen_op->op == AdminOp::user_add &&
              !ua_gen_op->has_seed,
          "user_add (generate) request round-trips");
    std::array<std::uint8_t, 32> seed{};
    seed.fill(0x44);
    const auto ua_imp_op =
        tier::core::decode_admin_request(tier::core::encode_admin_user_add(seed));
    check(ua_imp_op.has_value() && ua_imp_op->op == AdminOp::user_add &&
              ua_imp_op->has_seed && ua_imp_op->seed == seed,
          "user_add (import) request round-trips");

    // user_remove request round-trips.
    tier::core::PeerId ru{};
    ru.fill(0x9E);
    const auto ur_op =
        tier::core::decode_admin_request(tier::core::encode_admin_user_remove(ru));
    check(ur_op.has_value() && ur_op->op == AdminOp::user_remove &&
              ur_op->recipient == ru,
          "user_remove request round-trips");
  }

  // id response round-trip: device id only.
  {
    tier::core::PeerId dev{};
    for (std::size_t i = 0; i < dev.size(); ++i) {
      dev[i] = static_cast<std::uint8_t>(i * 7 + 1);
    }
    tier::core::AdminId id;
    id.device_id = dev;
    const auto reply = tier::core::encode_admin_id_reply(id);
    const auto got = tier::core::decode_admin_id_reply(reply);
    check(got.has_value() && got->device_id == dev, "id reply round-trips");
    auto trailing_id = reply;
    trailing_id.push_back(0x00);
    check(!tier::core::decode_admin_id_reply(trailing_id).has_value(),
          "id reply with trailing byte rejected");
    auto truncated = reply;
    truncated.pop_back();
    check(!tier::core::decode_admin_id_reply(truncated).has_value(),
          "truncated id reply rejected");
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

  // send_as reply, and the user CRUD replies, round-trip.
  {
    using tier::core::SendStatus;
    for (const auto s : {SendStatus::accepted, SendStatus::failed,
                         SendStatus::recipient_offline}) {
      check(tier::core::decode_admin_send_as_reply(
                tier::core::encode_admin_send_as_reply(s)) ==
                std::optional<SendStatus>(s),
            "send_as reply status round-trips");
    }
    using tier::core::UserPresence;
    for (const auto p : {UserPresence::unknown, UserPresence::online,
                         UserPresence::offline}) {
      check(tier::core::decode_admin_user_status_reply(
                tier::core::encode_admin_user_status_reply(p)) ==
                std::optional<UserPresence>(p),
            "user_status reply round-trips");
    }

    tier::core::AdminUserAddReply rep;
    rep.ok = true;
    rep.user_id.fill(0xAB);
    const auto enc = tier::core::encode_admin_user_add_reply(rep);
    const auto got = tier::core::decode_admin_user_add_reply(enc);
    check(got && got->ok && got->user_id == rep.user_id,
          "user_add reply round-trips");
    auto ua_tr = enc;
    ua_tr.push_back(0x00);
    check(!tier::core::decode_admin_user_add_reply(ua_tr).has_value(),
          "user_add reply trailing byte rejected");

    check(tier::core::decode_admin_user_remove_reply(
              tier::core::encode_admin_user_remove_reply(true)) == std::optional<bool>(true),
          "user_remove reply (existed) round-trips");
    check(tier::core::decode_admin_user_remove_reply(
              tier::core::encode_admin_user_remove_reply(false)) == std::optional<bool>(false),
          "user_remove reply (absent) round-trips");

    std::vector<tier::core::PeerId> users(2);
    users[0].fill(0x01);
    users[1].fill(0x02);
    const auto ul = tier::core::encode_admin_user_list(users);
    const auto ul_got = tier::core::decode_admin_user_list(ul);
    check(ul_got && ul_got->size() == 2 && (*ul_got)[0] == users[0] &&
              (*ul_got)[1] == users[1],
          "user_list reply round-trips");
    auto ul_tr = ul;
    ul_tr.push_back(0x00);
    check(!tier::core::decode_admin_user_list(ul_tr).has_value(),
          "user_list reply trailing byte rejected");
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
    tier::core::PeerId r2{};
    r2.fill(0x33);
    m2.sender_user = u2;     // this one carries an authenticated user sender
    m2.recipient_user = r2;  // and names the local user it was addressed to
    m2.suite = 3;
    m2.plaintext = {};
    msgs.push_back(m1);
    msgs.push_back(m2);
    const auto enc = tier::core::encode_admin_inbox(msgs);
    const auto dec = tier::core::decode_admin_inbox(enc);
    check(dec.has_value() && dec->size() == 2, "inbox reply count round-trips");
    if (dec && dec->size() == 2) {
      check((*dec)[0].sender == m1.sender && !(*dec)[0].sender_user &&
                !(*dec)[0].recipient_user && (*dec)[0].suite == 1 &&
                (*dec)[0].plaintext == m1.plaintext,
            "inbox message 1 (node message, no user) round-trips");
      check((*dec)[1].sender == m2.sender && (*dec)[1].sender_user &&
                *(*dec)[1].sender_user == u2 && (*dec)[1].recipient_user &&
                *(*dec)[1].recipient_user == r2 && (*dec)[1].suite == 3 &&
                (*dec)[1].plaintext.empty(),
            "inbox message 2 (user message, sender + recipient) round-trips");
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

  // --- subscribe request round-trip --------------------------------------
  {
    tier::core::PeerId user{};
    for (std::size_t i = 0; i < user.size(); ++i) user[i] = static_cast<std::uint8_t>(i + 3);
    const auto enc = tier::core::encode_admin_subscribe(user);
    const auto dec = tier::core::decode_admin_request(enc);
    check(dec.has_value(), "subscribe request decodes");
    check(dec && dec->op == tier::core::AdminOp::subscribe, "subscribe op");
    check(dec && dec->recipient == user, "subscribe carries the user id");
    auto trailing = enc;
    trailing.push_back(0x00);
    check(!tier::core::decode_admin_request(trailing).has_value(),
          "trailing byte in subscribe rejected");
  }

  // --- stream message event round-trip -----------------------------------
  {
    tier::core::AdminStreamMessage m;
    for (std::size_t i = 0; i < m.sender_user.size(); ++i)
      m.sender_user[i] = static_cast<std::uint8_t>(0x20 + i);
    m.suite = 2;
    m.type = 0x0001;
    for (std::size_t i = 0; i < m.msg_id.size(); ++i)
      m.msg_id[i] = static_cast<std::uint8_t>(0x40 + i);
    const std::string body = "stream body";
    m.payload.assign(body.begin(), body.end());
    const auto enc = tier::core::encode_admin_stream_message(m);
    const auto ev = tier::core::decode_admin_stream_event(enc);
    check(ev.has_value(), "stream message decodes");
    check(ev && ev->kind == tier::core::AdminStreamKind::message, "kind message");
    check(ev && ev->message.sender_user == m.sender_user, "sender_user round-trips");
    check(ev && ev->message.suite == m.suite, "suite round-trips");
    check(ev && ev->message.type == m.type, "type round-trips");
    check(ev && ev->message.msg_id == m.msg_id, "msg_id round-trips");
    check(ev && ev->message.payload == m.payload, "payload round-trips");
    auto trailing = enc;
    trailing.push_back(0x00);
    check(!tier::core::decode_admin_stream_event(trailing).has_value(),
          "trailing byte in stream message rejected");
  }

  // --- stream receipt event round-trip -----------------------------------
  {
    tier::core::AdminStreamReceipt rr;
    for (std::size_t i = 0; i < rr.msg_id.size(); ++i)
      rr.msg_id[i] = static_cast<std::uint8_t>(0x70 + i);
    const auto enc = tier::core::encode_admin_stream_receipt(rr);
    const auto ev = tier::core::decode_admin_stream_event(enc);
    check(ev.has_value(), "stream receipt decodes");
    check(ev && ev->kind == tier::core::AdminStreamKind::receipt, "kind receipt");
    check(ev && ev->receipt.msg_id == rr.msg_id, "receipt msg_id round-trips");
  }

  if (g_failures == 0) {
    std::puts("ok");
    return 0;
  }
  std::fprintf(stderr, "%d check(s) failed\n", g_failures);
  return 1;
}
