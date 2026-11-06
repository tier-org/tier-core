#include "store.hpp"

#include <algorithm>
#include <utility>

#include "sqlite3.h"

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
    "  user_id TEXT PRIMARY KEY,"
    "  alias   TEXT NOT NULL DEFAULT ''"
    ");"
    "CREATE TABLE IF NOT EXISTS accounts("
    "  user_id TEXT PRIMARY KEY,"
    "  alias   TEXT NOT NULL DEFAULT ''"
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

std::vector<Contact> Store::contacts() const {
  std::vector<Contact> out;
  sqlite3_stmt* st = nullptr;
  if (sqlite3_prepare_v2(db_,
                         "SELECT user_id, alias FROM contacts "
                         "ORDER BY (alias='' ) , alias, user_id",
                         -1, &st, nullptr) != SQLITE_OK) {
    return out;
  }
  while (sqlite3_step(st) == SQLITE_ROW) {
    Contact c;
    c.user_id = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
    const auto* a = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
    c.alias = a != nullptr ? a : "";
    out.push_back(std::move(c));
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

}  // namespace tier::messenger
