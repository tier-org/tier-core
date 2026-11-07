#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

struct sqlite3;

namespace tier::messenger {

// Message correlation id (the layer-2 frame msg_id), 16 bytes.
using MsgId = std::array<std::uint8_t, 16>;

enum class Direction : std::uint8_t { incoming = 0, outgoing = 1 };

// A counterparty, with an optional human alias. Contacts are created both
// explicitly (the user adds one) and implicitly (anyone who messages the user is
// auto-filed here, alias empty, so they can be named later). `suite` is a
// per-contact crypto override; nullopt means "use the account default". A
// `verified` contact is one whose user id the user has confirmed out of band -
// the only defence against encrypting to an impostor, since the id is the
// fingerprint of the identity key the encryption keys are signed under.
struct Contact {
  std::string user_id;                 // 64 hex chars
  std::string alias;                   // may be empty
  std::optional<std::uint8_t> suite;   // per-contact override of the default
  bool verified = false;               // id confirmed out of band
};

// One chat message as stored. `account` is the local user id this conversation
// belongs to (the identity the user chats as); `peer` is the counterparty.
struct ChatMessage {
  std::int64_t row_id = 0;
  std::string account;
  std::string peer;
  Direction direction = Direction::incoming;
  MsgId msg_id{};
  std::uint8_t suite = 0;
  std::string body;
  std::int64_t ts = 0;    // unix seconds
  bool delivered = false;  // outgoing: a receipt came back
};

// The messenger's local persistent store (SQLite): contacts, aliases for the
// user's own identities, and full chat history with per-message delivery state.
// The node keeps nothing; everything durable lives here. Move-only; one handle
// per process (the connection is shared under SQLITE_THREADSAFE).
class Store {
 public:
  // Open (creating and migrating if needed) the database at `path`. nullopt on
  // failure.
  static std::optional<Store> open(const std::string& path);

  Store(Store&&) noexcept;
  Store& operator=(Store&&) noexcept;
  Store(const Store&) = delete;
  Store& operator=(const Store&) = delete;
  ~Store();

  // --- contacts ----------------------------------------------------------
  // Create or rename a contact (sets the alias). Preserves suite/verified on an
  // existing row.
  void upsert_contact(const std::string& user_id, const std::string& alias);
  // Create a contact only if absent, with an empty alias; never touches an
  // existing row. Used to auto-file an incoming sender.
  void ensure_contact(const std::string& user_id);
  bool remove_contact(const std::string& user_id);
  void set_contact_suite(const std::string& user_id,
                         std::optional<std::uint8_t> suite);
  void set_contact_verified(const std::string& user_id, bool verified);
  [[nodiscard]] std::vector<Contact> contacts() const;
  [[nodiscard]] std::optional<Contact> contact(const std::string& user_id) const;
  [[nodiscard]] std::optional<std::string> alias_of(const std::string& user_id) const;

  // --- the user's own identities (aliases are a local convenience) --------
  void set_account_alias(const std::string& user_id, const std::string& alias);
  [[nodiscard]] std::optional<std::string> account_alias(
      const std::string& user_id) const;

  // --- settings (a simple key/value table) -------------------------------
  [[nodiscard]] std::optional<std::string> get_setting(const std::string& key) const;
  void set_setting(const std::string& key, const std::string& value);
  // The account-wide default crypto suite (1 classical, 2 hybrid, 3 pq);
  // defaults to 2 (hybrid) when unset.
  [[nodiscard]] std::uint8_t default_suite() const;
  void set_default_suite(std::uint8_t suite);

  // --- local device lock (optional, off by default) ----------------------
  // A passphrase stored only as a salted PBKDF2-SHA256 hash. has_password()
  // reports whether a lock is set; set/clear manage it; verify checks an entry.
  [[nodiscard]] bool has_password() const;
  void set_password(const std::string& plaintext);
  void clear_password();
  [[nodiscard]] bool verify_password(const std::string& plaintext) const;

  // --- messages ----------------------------------------------------------
  // Append a message; returns its row id.
  std::int64_t add_message(const ChatMessage& m);
  // Mark the outgoing message with this (account, msg_id) delivered. Returns the
  // number of rows updated (0 if none matched).
  int mark_delivered(const std::string& account, const MsgId& msg_id);
  // Full history for one conversation, oldest first.
  [[nodiscard]] std::vector<ChatMessage> history(const std::string& account,
                                                 const std::string& peer) const;
  // Peers the account has any message with, most-recent conversation first.
  [[nodiscard]] std::vector<std::string> conversations(
      const std::string& account) const;

 private:
  explicit Store(sqlite3* db) : db_(db) {}
  sqlite3* db_ = nullptr;
};

}  // namespace tier::messenger
