#include "store.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <random>
#include <string>
#include <utility>

#include "sqlite3.h"
#include "tier/crypto/kdf.hpp"

namespace tier::messenger {
namespace {

// SQLITE_TRANSIENT expands to a C-style cast, which the project's warning set
// rejects. Capture it once here (the only place the macro is used) so the rest
// of the file stays within -Wold-style-cast.
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wold-style-cast"
// NOLINTNEXTLINE(performance-no-int-to-ptr)
const sqlite3_destructor_type kTransient = SQLITE_TRANSIENT;
#pragma GCC diagnostic pop

// Schema, applied on open (idempotent). Contacts and account aliases are simple
// key/value; messages carry the correlation id as a 16-byte blob so receipts can
// match an outgoing row.
constexpr const char* kSchema =
    "PRAGMA journal_mode=WAL;"
    "CREATE TABLE IF NOT EXISTS contacts("
    "  user_id  TEXT PRIMARY KEY,"
    "  alias    TEXT NOT NULL DEFAULT '',"
    "  suite    INTEGER,"              // NULL = use the account default
    "  verified INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE TABLE IF NOT EXISTS accounts("
    "  user_id TEXT PRIMARY KEY,"
    "  alias   TEXT NOT NULL DEFAULT ''"
    ");"
    "CREATE TABLE IF NOT EXISTS settings("
    "  key   TEXT PRIMARY KEY,"
    "  value TEXT NOT NULL"
    ");"
    "CREATE TABLE IF NOT EXISTS messages("
    "  id        INTEGER PRIMARY KEY AUTOINCREMENT,"
    "  account   TEXT NOT NULL,"
    "  peer      TEXT NOT NULL,"
    "  direction INTEGER NOT NULL,"
    "  msg_id    BLOB NOT NULL,"
    "  suite     INTEGER NOT NULL,"
    "  body      TEXT NOT NULL,"
    "  ts        INTEGER NOT NULL,"
    "  delivered INTEGER NOT NULL DEFAULT 0"
    ");"
    "CREATE INDEX IF NOT EXISTS idx_messages_conv"
    "  ON messages(account, peer, id);"
    "CREATE INDEX IF NOT EXISTS idx_messages_msgid"
    "  ON messages(account, msg_id);";

// Bind a std::string as transient text (SQLite copies it).
void bind_text(sqlite3_stmt* st, int idx, const std::string& s) {
  sqlite3_bind_text(st, idx, s.data(), static_cast<int>(s.size()), kTransient);
}

std::string bytes_to_hex(const std::vector<std::uint8_t>& b) {
  static const char* const hex = "0123456789abcdef";
  std::string out;
  out.reserve(b.size() * 2);
  for (const auto v : b) {
    out += hex[v >> 4];
    out += hex[v & 0x0F];
  }
  return out;
}

// Decode an even-length lowercase/uppercase hex string; empty on malformed.
std::vector<std::uint8_t> hex_to_bytes(const std::string& s) {
  if (s.size() % 2 != 0) {
    return {};
  }
  auto nib = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  std::vector<std::uint8_t> out;
  out.reserve(s.size() / 2);
  for (std::size_t i = 0; i < s.size(); i += 2) {
    const int hi = nib(s[i]);
    const int lo = nib(s[i + 1]);
    if (hi < 0 || lo < 0) {
      return {};
    }
    out.push_back(static_cast<std::uint8_t>((hi << 4) | lo));
  }
  return out;
}

// Work factor for the device-lock passphrase hash. PBKDF2-SHA256 at 200k rounds
// is a few hundred ms - fine for a manual unlock, painful to brute force.
constexpr std::uint32_t kPwIterations = 200000;
constexpr std::size_t kPwSaltLen = 16;
constexpr std::size_t kPwHashLen = 32;

}  // namespace

std::optional<Store> Store::open(const std::string& path) {
  sqlite3* db = nullptr;
  if (sqlite3_open(path.c_str(), &db) != SQLITE_OK) {
    if (db != nullptr) {
      sqlite3_close(db);
    }
    return std::nullopt;
  }
  sqlite3_busy_timeout(db, 2000);
  if (sqlite3_exec(db, kSchema, nullptr, nullptr, nullptr) != SQLITE_OK) {
    sqlite3_close(db);
    return std::nullopt;
  }
  // Bring forward a store written by an older build that predates the
  // per-contact columns. On a fresh database the CREATE TABLE already has them,
  // so ALTER fails with "duplicate column name"; that error is expected and
  // ignored (data is preserved either way).
  sqlite3_exec(db, "ALTER TABLE contacts ADD COLUMN suite INTEGER", nullptr,
               nullptr, nullptr);
  sqlite3_exec(db,
               "ALTER TABLE contacts ADD COLUMN verified INTEGER NOT NULL "
               "DEFAULT 0",
               nullptr, nullptr, nullptr);
  return Store(db);
}

Store::Store(Store&& o) noexcept : db_(o.db_) { o.db_ = nullptr; }

Store& Store::operator=(Store&& o) noexcept {
  if (this != &o) {
    if (db_ != nullptr) {
      sqlite3_close(db_);
    }
    db_ = o.db_;
    o.db_ = nullptr;
  }
  return *this;
}

Store::~Store() {
  if (db_ != nullptr) {
    sqlite3_close(db_);
  }
}

void Store::upsert_contact(const std::string& user_id, const std::string& alias) {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_,
                         "INSERT INTO contacts(user_id, alias) VALUES(?1, ?2) "
                         "ON CONFLICT(user_id) DO UPDATE SET alias=excluded.alias",
                         -1, &st, nullptr) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, user_id);
  bind_text(st, 2, alias);
  sqlite3_step(st);
  sqlite3_finalize(st);
}

void Store::ensure_contact(const std::string& user_id) {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(
          db_, "INSERT OR IGNORE INTO contacts(user_id) VALUES(?1)", -1, &st,
          nullptr) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, user_id);
  sqlite3_step(st);
  sqlite3_finalize(st);
}

bool Store::remove_contact(const std::string& user_id) {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_, "DELETE FROM contacts WHERE user_id=?1", -1, &st,
                         nullptr) != SQLITE_OK) {
    return false;
  }
  bind_text(st, 1, user_id);
  sqlite3_step(st);
  sqlite3_finalize(st);
  return sqlite3_changes(db_) > 0;
}

void Store::set_contact_suite(const std::string& user_id,
                              std::optional<std::uint8_t> suite) {
  ensure_contact(user_id);
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_, "UPDATE contacts SET suite=?2 WHERE user_id=?1",
                         -1, &st, nullptr) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, user_id);
  if (suite.has_value()) {
    sqlite3_bind_int(st, 2, *suite);
  } else {
    sqlite3_bind_null(st, 2);
  }
  sqlite3_step(st);
  sqlite3_finalize(st);
}

void Store::set_contact_verified(const std::string& user_id, bool verified) {
  ensure_contact(user_id);
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_, "UPDATE contacts SET verified=?2 WHERE user_id=?1",
                         -1, &st, nullptr) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, user_id);
  sqlite3_bind_int(st, 2, verified ? 1 : 0);
  sqlite3_step(st);
  sqlite3_finalize(st);
}

namespace {

// Fill a Contact from a row of (user_id, alias, suite, verified).
Contact read_contact_row(sqlite3_stmt* st) {
  Contact c;
  c.user_id = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
  const auto* a = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
  c.alias = a != nullptr ? a : "";
  if (sqlite3_column_type(st, 2) != SQLITE_NULL) {
    c.suite = static_cast<std::uint8_t>(sqlite3_column_int(st, 2));
  }
  c.verified = sqlite3_column_int(st, 3) != 0;
  return c;
}

}  // namespace

std::vector<Contact> Store::contacts() const {
  std::vector<Contact> out;
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_,
                         "SELECT user_id, alias, suite, verified FROM contacts "
                         "ORDER BY (alias='' ) , alias, user_id",
                         -1, &st, nullptr) != SQLITE_OK) {
    return out;
  }
  while (sqlite3_step(st) == SQLITE_ROW) {
    out.push_back(read_contact_row(st));
  }
  sqlite3_finalize(st);
  return out;
}

std::optional<Contact> Store::contact(const std::string& user_id) const {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(
          db_,
          "SELECT user_id, alias, suite, verified FROM contacts "
          "WHERE user_id=?1",
          -1, &st, nullptr) != SQLITE_OK) {
    return std::nullopt;
  }
  bind_text(st, 1, user_id);
  std::optional<Contact> out;
  if (sqlite3_step(st) == SQLITE_ROW) {
    out = read_contact_row(st);
  }
  sqlite3_finalize(st);
  return out;
}

std::optional<std::string> Store::alias_of(const std::string& user_id) const {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_, "SELECT alias FROM contacts WHERE user_id=?1", -1,
                         &st, nullptr) != SQLITE_OK) {
    return std::nullopt;
  }
  bind_text(st, 1, user_id);
  std::optional<std::string> out;
  if (sqlite3_step(st) == SQLITE_ROW) {
    const auto* a = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
    out = a != nullptr ? std::string(a) : std::string();
  }
  sqlite3_finalize(st);
  return out;
}

void Store::set_account_alias(const std::string& user_id,
                              const std::string& alias) {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_,
                         "INSERT INTO accounts(user_id, alias) VALUES(?1, ?2) "
                         "ON CONFLICT(user_id) DO UPDATE SET alias=excluded.alias",
                         -1, &st, nullptr) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, user_id);
  bind_text(st, 2, alias);
  sqlite3_step(st);
  sqlite3_finalize(st);
}

std::optional<std::string> Store::account_alias(const std::string& user_id) const {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_, "SELECT alias FROM accounts WHERE user_id=?1", -1,
                         &st, nullptr) != SQLITE_OK) {
    return std::nullopt;
  }
  bind_text(st, 1, user_id);
  std::optional<std::string> out;
  if (sqlite3_step(st) == SQLITE_ROW) {
    const auto* a = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
    out = a != nullptr ? std::string(a) : std::string();
  }
  sqlite3_finalize(st);
  return out;
}

std::int64_t Store::add_message(const ChatMessage& m) {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(
          db_,
          "INSERT INTO messages(account, peer, direction, msg_id, suite, body, "
          "ts, delivered) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
          -1, &st, nullptr) != SQLITE_OK) {
    return 0;
  }
  bind_text(st, 1, m.account);
  bind_text(st, 2, m.peer);
  sqlite3_bind_int(st, 3, static_cast<int>(m.direction));
  sqlite3_bind_blob(st, 4, m.msg_id.data(), static_cast<int>(m.msg_id.size()),
                    kTransient);
  sqlite3_bind_int(st, 5, m.suite);
  bind_text(st, 6, m.body);
  sqlite3_bind_int64(st, 7, m.ts);
  sqlite3_bind_int(st, 8, m.delivered ? 1 : 0);
  const int rc = sqlite3_step(st);
  sqlite3_finalize(st);
  if (rc != SQLITE_DONE) {
    return 0;
  }
  return sqlite3_last_insert_rowid(db_);
}

int Store::mark_delivered(const std::string& account, const MsgId& msg_id) {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_,
                         "UPDATE messages SET delivered=1 "
                         "WHERE account=?1 AND msg_id=?2 AND direction=1",
                         -1, &st, nullptr) != SQLITE_OK) {
    return 0;
  }
  bind_text(st, 1, account);
  sqlite3_bind_blob(st, 2, msg_id.data(), static_cast<int>(msg_id.size()),
                    kTransient);
  sqlite3_step(st);
  sqlite3_finalize(st);
  return sqlite3_changes(db_);
}

std::vector<ChatMessage> Store::history(const std::string& account,
                                        const std::string& peer) const {
  std::vector<ChatMessage> out;
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(
          db_,
          "SELECT id, direction, msg_id, suite, body, ts, delivered "
          "FROM messages WHERE account=?1 AND peer=?2 ORDER BY id",
          -1, &st, nullptr) != SQLITE_OK) {
    return out;
  }
  bind_text(st, 1, account);
  bind_text(st, 2, peer);
  while (sqlite3_step(st) == SQLITE_ROW) {
    ChatMessage m;
    m.row_id = sqlite3_column_int64(st, 0);
    m.account = account;
    m.peer = peer;
    m.direction = static_cast<Direction>(sqlite3_column_int(st, 1));
    const void* blob = sqlite3_column_blob(st, 2);
    const int blob_len = sqlite3_column_bytes(st, 2);
    if (blob != nullptr && blob_len == static_cast<int>(m.msg_id.size())) {
      std::copy(static_cast<const std::uint8_t*>(blob),
                static_cast<const std::uint8_t*>(blob) + blob_len,
                m.msg_id.begin());
    }
    m.suite = static_cast<std::uint8_t>(sqlite3_column_int(st, 3));
    const auto* body = reinterpret_cast<const char*>(sqlite3_column_text(st, 4));
    m.body = body != nullptr ? body : "";
    m.ts = sqlite3_column_int64(st, 5);
    m.delivered = sqlite3_column_int(st, 6) != 0;
    out.push_back(std::move(m));
  }
  sqlite3_finalize(st);
  return out;
}

std::vector<std::string> Store::conversations(const std::string& account) const {
  std::vector<std::string> out;
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_,
                         "SELECT peer, MAX(id) AS last FROM messages "
                         "WHERE account=?1 GROUP BY peer ORDER BY last DESC",
                         -1, &st, nullptr) != SQLITE_OK) {
    return out;
  }
  bind_text(st, 1, account);
  while (sqlite3_step(st) == SQLITE_ROW) {
    out.emplace_back(reinterpret_cast<const char*>(sqlite3_column_text(st, 0)));
  }
  sqlite3_finalize(st);
  return out;
}

std::optional<std::string> Store::get_setting(const std::string& key) const {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_, "SELECT value FROM settings WHERE key=?1", -1, &st,
                         nullptr) != SQLITE_OK) {
    return std::nullopt;
  }
  bind_text(st, 1, key);
  std::optional<std::string> out;
  if (sqlite3_step(st) == SQLITE_ROW) {
    const auto* v = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
    out = v != nullptr ? std::string(v) : std::string();
  }
  sqlite3_finalize(st);
  return out;
}

void Store::set_setting(const std::string& key, const std::string& value) {
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_,
                         "INSERT INTO settings(key, value) VALUES(?1, ?2) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         -1, &st, nullptr) != SQLITE_OK) {
    return;
  }
  bind_text(st, 1, key);
  bind_text(st, 2, value);
  sqlite3_step(st);
  sqlite3_finalize(st);
}

std::uint8_t Store::default_suite() const {
  const auto v = get_setting("default_suite");
  if (v.has_value()) {
    const int n = std::atoi(v->c_str());
    if (n >= 1 && n <= 3) {
      return static_cast<std::uint8_t>(n);
    }
  }
  return 2;  // hybrid
}

void Store::set_default_suite(std::uint8_t suite) {
  set_setting("default_suite", std::to_string(static_cast<int>(suite)));
}

bool Store::has_password() const {
  return get_setting("pw_hash").has_value();
}

void Store::set_password(const std::string& plaintext) {
  std::vector<std::uint8_t> salt(kPwSaltLen);
  std::random_device rd;
  for (auto& b : salt) {
    b = static_cast<std::uint8_t>(rd());
  }
  const auto pw = reinterpret_cast<const std::uint8_t*>(plaintext.data());
  const auto hash = tier::crypto::pbkdf2_sha256(
      {pw, plaintext.size()}, {salt.data(), salt.size()}, kPwIterations,
      kPwHashLen);
  set_setting("pw_salt", bytes_to_hex(salt));
  set_setting("pw_iter", std::to_string(kPwIterations));
  set_setting("pw_hash", bytes_to_hex(hash));
}

void Store::clear_password() {
  sqlite3_exec(db_,
               "DELETE FROM settings WHERE key IN "
               "('pw_salt','pw_iter','pw_hash')",
               nullptr, nullptr, nullptr);
}

bool Store::verify_password(const std::string& plaintext) const {
  const auto salt_hex = get_setting("pw_salt");
  const auto iter_str = get_setting("pw_iter");
  const auto want_hex = get_setting("pw_hash");
  if (!salt_hex.has_value() || !iter_str.has_value() || !want_hex.has_value()) {
    return false;
  }
  const auto salt = hex_to_bytes(*salt_hex);
  const auto want = hex_to_bytes(*want_hex);
  const auto iter = static_cast<std::uint32_t>(std::strtoul(
      iter_str->c_str(), nullptr, 10));
  if (salt.empty() || want.empty() || iter == 0) {
    return false;
  }
  const auto pw = reinterpret_cast<const std::uint8_t*>(plaintext.data());
  const auto got = tier::crypto::pbkdf2_sha256(
      {pw, plaintext.size()}, {salt.data(), salt.size()}, iter, want.size());
  // Constant-time-ish compare; the hashes are equal length by construction.
  if (got.size() != want.size()) {
    return false;
  }
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < got.size(); ++i) {
    diff |= static_cast<std::uint8_t>(got[i] ^ want[i]);
  }
  return diff == 0;
}

}  // namespace tier::messenger
