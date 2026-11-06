#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <optional>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "tier/app/dispatcher.hpp"
#include "tier/app/frame.hpp"
#include "tier/app/handler.hpp"
#include "tier/core/admin.hpp"
#include "tier/core/membership.hpp"
#include "tier/core/seeds.hpp"
#include "tier/core/version.hpp"
#include "tier/core/version_range.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/crypto/primitives.hpp"
#include "tier/msg/sealed.hpp"
#include "tier/net/admin_listener.hpp"
#include "tier/net/endpoint.hpp"
#include "tier/net/node.hpp"
#include "tier/net/subscriber_hub.hpp"

#include "config.hpp"

namespace {

std::string join_addresses(const std::vector<std::string>& addresses) {
  std::string out;
  for (const std::string& addr : addresses) {
    if (!out.empty()) {
      out += ',';
    }
    out += addr;
  }
  return out;
}

const char* role_name(tier::core::Role role) {
  switch (role) {
    case tier::core::Role::client:
      return "client";
    case tier::core::Role::validator:
      return "validator";
    case tier::core::Role::keeper:
      return "keeper";
    case tier::core::Role::transmitter:
      return "transmitter";
    case tier::core::Role::communicator:
      return "communicator";
  }
  return "?";
}

// Render a role set as "client|validator|..." (just "-" if empty).
std::string format_roles(tier::core::RoleSet roles) {
  std::string out;
  for (const tier::core::Role r :
       {tier::core::Role::client, tier::core::Role::validator,
        tier::core::Role::keeper, tier::core::Role::transmitter,
        tier::core::Role::communicator}) {
    if (tier::core::has_role(roles, r)) {
      if (!out.empty()) {
        out += '|';
      }
      out += role_name(r);
    }
  }
  return out.empty() ? "-" : out;
}

// Parse the roles this node holds from TIER_ROLES: role names separated by
// '|', ',' or whitespace, e.g. "transmitter" or "validator|keeper". An unset or
// empty value yields the plain client role, so the default node is an edge node
// (dial-out only) - see docs/topology.md. Returns std::nullopt on an unknown
// name so the caller can fail closed with a diagnostic.
std::optional<tier::core::RoleSet> parse_roles(const char* spec) {
  if (spec == nullptr) {
    return tier::core::role_bit(tier::core::Role::client);
  }
  tier::core::RoleSet roles = 0;
  std::string token;
  const auto flush = [&]() -> bool {
    if (token.empty()) {
      return true;
    }
    bool matched = false;
    for (const tier::core::Role r :
         {tier::core::Role::client, tier::core::Role::validator,
          tier::core::Role::keeper, tier::core::Role::transmitter,
          tier::core::Role::communicator}) {
      if (token == role_name(r)) {
        roles |= tier::core::role_bit(r);
        matched = true;
        break;
      }
    }
    token.clear();
    return matched;
  };
  for (const char c : std::string_view(spec)) {
    if (c == '|' || c == ',' || c == ' ' || c == '\t') {
      if (!flush()) {
        return std::nullopt;
      }
    } else {
      token.push_back(c);
    }
  }
  if (!flush()) {
    return std::nullopt;
  }
  if (roles == 0) {
    roles = tier::core::role_bit(tier::core::Role::client);
  }
  return roles;
}

// Where the node's long-term Ed25519 seed lives. Override with TIER_ID_FILE
// (e.g. /etc/tier-network/id or /var/lib/tier/id for a system daemon);
// otherwise a non-root XDG state path is used.
std::string resolve_id_path() {
  if (const char* const env = std::getenv("TIER_ID_FILE"); env != nullptr) {
    return env;
  }
  if (const char* const xdg = std::getenv("XDG_STATE_HOME"); xdg != nullptr) {
    return std::string(xdg) + "/tier/node_key";
  }
  if (const char* const home = std::getenv("HOME"); home != nullptr) {
    return std::string(home) + "/.local/state/tier/node_key";
  }
  return "tier_node_key";
}

// Where the local admin/diagnostics socket lives. Overridable with
// TIER_ADMIN_SOCK; the default matches the systemd unit's RuntimeDirectory
// (/run/tierd, created for the service user).
std::string resolve_admin_path() {
  if (const char* const env = std::getenv("TIER_ADMIN_SOCK"); env != nullptr) {
    return env;
  }
  return "/run/tierd/tierd.sock";
}

// Load the operator config file. TIER_CONFIG overrides the default path
// (/etc/tier/tierd.toml). A default path that does not exist is not an error -
// the node then runs on environment variables and baked defaults alone. An
// explicit TIER_CONFIG that cannot be read, or a file that fails to parse, is a
// fatal operator error: returns std::nullopt with `error` set. `found` reports
// whether a file was actually loaded (for logging).
std::optional<tier::node::Config> load_node_config(std::string& error,
                                                   bool& found,
                                                   std::string& path_out) {
  found = false;
  bool explicit_path = false;
  std::string path = "/etc/tier/tierd.toml";
  if (const char* const env = std::getenv("TIER_CONFIG");
      env != nullptr && *env != '\0') {
    path = env;
    explicit_path = true;
  }
  path_out = path;

  std::ifstream in(path, std::ios::binary);
  if (!in) {
    if (explicit_path) {
      error = "cannot open config file " + path;
      return std::nullopt;
    }
    return tier::node::Config{};  // no default file: env/baked only
  }
  std::ostringstream buffer;
  buffer << in.rdbuf();
  if (in.bad()) {
    error = "cannot read config file " + path;
    return std::nullopt;
  }
  const std::string text = buffer.str();
  std::string parse_error;
  auto cfg = tier::node::parse_config(text, parse_error);
  if (!cfg) {
    error = path + ": " + parse_error;
    return std::nullopt;
  }
  found = true;
  return cfg;
}

// fsync the directory that holds `path` so a freshly created file is durable
// across a crash (the install below is only guaranteed after the directory
// entry is flushed). Returns false on failure with errno set to the cause, so
// the caller can refuse to proceed rather than claim a durable key it does not
// have.
bool fsync_parent_dir(const std::string& path) {
  const std::filesystem::path p(path);
  const std::string dir =
      p.has_parent_path() ? p.parent_path().string() : std::string(".");
  const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (fd < 0) {
    return false;
  }
  const bool ok = ::fsync(fd) == 0;
  const int saved = errno;  // close() must not clobber the fsync failure cause
  ::close(fd);
  if (!ok) {
    errno = saved;
  }
  return ok;
}

// Outcome of persist_seed. `exists` means another process installed the key
// between our absence check and our install - a creation race we lost, not an
// error: the caller loads the winning key instead.
enum class PersistResult : std::uint8_t { ok, exists, error };

// Atomically persist the 32-byte seed to `path`: write a private, per-process
// temp file (created 0600, before any secret byte is written), flush it, then
// install it with link() - which fails if `path` already exists, so a key that
// appeared after our absence check is never clobbered - and flush the directory.
// Leaves no new key in place on error, and never truncates an existing file.
PersistResult persist_seed(const std::string& path,
                           std::span<const tier::crypto::Byte> seed) {
  // Per-process temp name: two concurrent starts never share a temp path, so
  // neither can unlink or overwrite the other's in-flight file.
  const std::string tmp =
      path + ".tmp." + std::to_string(static_cast<long>(::getpid()));
  ::unlink(tmp.c_str());  // clear our own leftover from a crashed prior run
  const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
  if (fd < 0) {
    std::fprintf(stderr, "cannot create key temp file %s: %s\n", tmp.c_str(),
                 std::strerror(errno));
    return PersistResult::error;
  }
  // Guarantee 0600 regardless of umask, before writing the secret.
  if (::fchmod(fd, 0600) != 0) {
    std::fprintf(stderr, "cannot set key file mode: %s\n", std::strerror(errno));
    ::close(fd);
    ::unlink(tmp.c_str());
    return PersistResult::error;
  }
  std::size_t written = 0;
  while (written < seed.size()) {
    const ssize_t n =
        ::write(fd, seed.data() + written, seed.size() - written);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      std::fprintf(stderr, "cannot write key: %s\n", std::strerror(errno));
      ::close(fd);
      ::unlink(tmp.c_str());
      return PersistResult::error;
    }
    written += static_cast<std::size_t>(n);
  }
  if (::fsync(fd) != 0 || ::close(fd) != 0) {
    std::fprintf(stderr, "cannot flush key file: %s\n", std::strerror(errno));
    ::unlink(tmp.c_str());
    return PersistResult::error;
  }
  // Install without clobbering: link() fails with EEXIST if another process won
  // the creation race, so we never overwrite a key that appeared after our
  // absence check. The key then lives at `path`; drop the temp name.
  if (::link(tmp.c_str(), path.c_str()) != 0) {
    const int e = errno;
    ::unlink(tmp.c_str());
    if (e == EEXIST) {
      return PersistResult::exists;
    }
    std::fprintf(stderr, "cannot install key file %s: %s\n", path.c_str(),
                 std::strerror(e));
    return PersistResult::error;
  }
  ::unlink(tmp.c_str());
  if (!fsync_parent_dir(path)) {
    // The key is linked at `path` but its directory entry may not survive a
    // crash. Refuse rather than report a durability we cannot vouch for; a
    // restart will find the key already present and load it.
    std::fprintf(stderr, "cannot flush key directory for %s: %s\n", path.c_str(),
                 std::strerror(errno));
    return PersistResult::error;
  }
  return PersistResult::ok;
}

// Read the identity from an existing key file. Returns the identity on success;
// std::nullopt otherwise, with `absent` set true only when the file is confirmed
// not to exist (ENOENT) - the one case in which the caller may mint a new key.
// Every present-but-bad case (wrong type or size, unreadable, stat error) is
// diagnosed here, leaves the file untouched, and reports absent == false.
std::optional<tier::crypto::NodeIdentity> read_existing_identity(
    const std::string& path, bool& absent) {
  absent = false;
  struct stat st {};
  if (::stat(path.c_str(), &st) != 0) {
    if (errno == ENOENT) {
      absent = true;
      return std::nullopt;
    }
    // Present but unstattable (e.g. a permission or I/O error): do not mask it
    // by minting a new identity on top of a file we simply cannot see.
    std::fprintf(stderr, "cannot access key file %s: %s\n", path.c_str(),
                 std::strerror(errno));
    return std::nullopt;
  }
  // The file exists: it must be a regular file of exactly the seed size and
  // fully readable, or we stop. We never regenerate over an existing file.
  if (!S_ISREG(st.st_mode)) {
    std::fprintf(stderr, "key file %s is not a regular file\n", path.c_str());
    return std::nullopt;
  }
  if (static_cast<std::uintmax_t>(st.st_size) != tier::crypto::kEd25519SeedSize) {
    std::fprintf(stderr,
                 "key file %s has wrong size (%lld bytes, expected %zu); "
                 "refusing to overwrite - move it aside to mint a new key\n",
                 path.c_str(), static_cast<long long>(st.st_size),
                 static_cast<std::size_t>(tier::crypto::kEd25519SeedSize));
    return std::nullopt;
  }
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    std::fprintf(stderr, "cannot open key file %s: %s\n", path.c_str(),
                 std::strerror(errno));
    return std::nullopt;
  }
  std::array<tier::crypto::Byte, tier::crypto::kEd25519SeedSize> seed{};
  std::size_t got = 0;
  bool read_ok = true;
  while (got < seed.size()) {
    const ssize_t n = ::read(fd, seed.data() + got, seed.size() - got);
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      std::fprintf(stderr, "cannot read key file %s: %s\n", path.c_str(),
                   std::strerror(errno));
      read_ok = false;
      break;
    }
    if (n == 0) {
      break;  // short file despite the size check (raced); treated as an error
    }
    got += static_cast<std::size_t>(n);
  }
  ::close(fd);
  if (!read_ok || got != seed.size()) {
    std::fprintf(stderr, "key file %s could not be fully read; not starting\n",
                 path.c_str());
    return std::nullopt;
  }
  return tier::crypto::NodeIdentity::from_seed(seed);
}

// Load the node identity from a 32-byte seed file, creating (and persisting) a
// fresh one only when the file is confirmed absent. The seed is the node's
// permanent network name, so this fails closed rather than silently minting a
// new identity: a corrupt, wrong-sized, unreadable or otherwise present-but-bad
// file aborts startup and is left untouched, and a new key is not used unless it
// was durably written. Returns std::nullopt on any such error.
std::optional<tier::crypto::NodeIdentity> load_or_create_identity(
    const std::string& path) {
  bool absent = false;
  if (auto existing = read_existing_identity(path, absent)) {
    return existing;
  }
  if (!absent) {
    return std::nullopt;  // present but bad; already diagnosed, left untouched
  }

  // Confirmed absent: create the parent directory (0700) and a fresh identity.
  std::error_code ec;
  const std::filesystem::path file(path);
  if (file.has_parent_path()) {
    std::filesystem::create_directories(file.parent_path(), ec);
    if (ec) {
      std::fprintf(stderr, "cannot create key directory %s: %s\n",
                   file.parent_path().string().c_str(), ec.message().c_str());
      return std::nullopt;
    }
    std::filesystem::permissions(file.parent_path(), std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
  }
  auto identity = tier::crypto::NodeIdentity::generate();
  switch (persist_seed(path, identity.seed())) {
    case PersistResult::ok:
      return identity;
    case PersistResult::exists: {
      // Lost a creation race: another process installed the key first. Load the
      // winner so both processes converge on one identity.
      bool raced_absent = false;
      if (auto winner = read_existing_identity(path, raced_absent)) {
        return winner;
      }
      std::fprintf(stderr,
                   "key file %s appeared during creation but could not be read; "
                   "not starting\n",
                   path.c_str());
      return std::nullopt;
    }
    case PersistResult::error:
      return std::nullopt;  // do not run with an unsaved identity
  }
  return std::nullopt;  // unreachable; keeps the compiler happy
}

void print_hex(const char* label, std::span<const tier::crypto::Byte> bytes) {
  std::fputs(label, stdout);
  for (const auto b : bytes) {
    std::printf("%02x", static_cast<unsigned>(b));
  }
  std::fputc('\n', stdout);
}

// Lowercase hex of an id, for a user's seed-file name.
std::string hex_of(std::span<const tier::crypto::Byte> bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes.size() * 2);
  for (const auto b : bytes) {
    out.push_back(kHex[(b >> 4) & 0x0F]);
    out.push_back(kHex[b & 0x0F]);
  }
  return out;
}

// Where runtime-managed user identities are stored: a `users` directory beside
// the node key. Each hosted user is one <user-id-hex>.seed file (the Ed25519
// seed, 0600), so the set survives a restart. Managed only via tierctl, never
// configuration.
std::string resolve_users_dir() {
  const std::filesystem::path idp(resolve_id_path());
  const auto parent =
      idp.has_parent_path() ? idp.parent_path() : std::filesystem::path(".");
  return (parent / "users").string();
}

// Load every persisted user seed from `dir` and host it on the node.
void load_users(tier::net::Node& node, const std::string& dir) {
  std::error_code ec;
  if (!std::filesystem::is_directory(dir, ec)) {
    return;
  }
  for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
    if (ec) {
      break;
    }
    if (!entry.is_regular_file() || entry.path().extension() != ".seed") {
      continue;
    }
    bool absent = false;
    auto id = read_existing_identity(entry.path().string(), absent);
    if (!id) {
      std::fprintf(stderr, "skipping unreadable user seed %s\n",
                   entry.path().string().c_str());
      continue;
    }
    const auto uid = node.add_user(std::move(*id));
    print_hex("user:     ", uid);
  }
}

// Bridges the application dispatcher (layer 2) to the node and the subscriber
// hub: it delivers chat messages and receipts to a user's live subscribers
// (tier-messenger, `tierctl stream`) and sends frames via the node when a
// handler emits one (e.g. a delivery receipt). See docs/app-protocol.md.
class DaemonAppContext final : public tier::app::AppContext {
 public:
  DaemonAppContext(tier::net::Node& node, tier::net::SubscriberHub& hub)
      : node_(node), hub_(hub) {}

  bool deliver_message(const tier::core::PeerId& local_user,
                       const tier::core::PeerId& sender_user,
                       tier::msg::Suite suite,
                       const tier::app::AppFrame& frame) override {
    tier::core::AdminStreamMessage m;
    m.sender_user = sender_user;
    m.suite = static_cast<std::uint8_t>(suite);
    m.type = static_cast<std::uint16_t>(frame.type);
    m.msg_id = frame.msg_id;
    m.payload = frame.payload;
    const auto rec = tier::core::encode_admin_stream_message(m);
    return hub_.publish(local_user,
                        std::span<const std::uint8_t>(rec.data(), rec.size())) > 0;
  }

  bool deliver_receipt(
      const tier::core::PeerId& local_user,
      const std::array<std::uint8_t, tier::app::kMsgIdLen>& msg_id) override {
    tier::core::AdminStreamReceipt r;
    r.msg_id = msg_id;
    const auto rec = tier::core::encode_admin_stream_receipt(r);
    return hub_.publish(local_user,
                        std::span<const std::uint8_t>(rec.data(), rec.size())) > 0;
  }

  void send_as(const tier::core::PeerId& from_user,
               const tier::core::PeerId& to_user, tier::msg::Suite suite,
               const tier::app::AppFrame& frame) override {
    const auto bytes = tier::app::encode_app_frame(frame);
    (void)node_.send_as_user(
        from_user, to_user, suite,
        std::span<const tier::crypto::Byte>(bytes.data(), bytes.size()));
  }

 private:
  tier::net::Node& node_;
  tier::net::SubscriberHub& hub_;
};

int usage() {
  std::fputs(
      "usage:\n"
      "  tierd run <port> [<seed_ip> <seed_port>]\n"
      "  tierd listen <port>\n"
      "  tierd connect <ip> <port>\n"
      "  tierd networks            list the baked per-network version policy\n",
      stderr);
  return 2;
}

// Print the per-network version policy baked into this binary (from the
// top-level networks/ files). Read-only, needs no identity; lets an operator
// see what version each public network admits before joining.
int run_networks() {
  std::string err;
  if (!tier::core::validate_baked_networks(&err)) {
    std::fprintf(stderr, "baked networks table invalid: %s\n", err.c_str());
    return 1;
  }
  std::printf("%-20s  %s\n", "NETWORK", "VERSION POLICY");
  for (const auto& n : tier::core::baked_networks()) {
    std::printf("%-20s  %s\n", n.name.c_str(),
                tier::core::to_string(n.range).c_str());
  }
  std::fputs(
      "\nPrivate networks have no baked policy (unconstrained); set "
      "TIER_VERSION_RANGE to pin one.\n",
      stdout);
  return 0;
}

// Long-lived participant: gossips membership and logs every peer it learns of.
int run_node(const tier::crypto::NodeIdentity& identity, std::uint16_t port,
             const char* seed_ip, std::uint16_t seed_port, bool has_seed) {
  // Operator config file (TIER_CONFIG or /etc/tier/tierd.toml). It is the
  // canonical home for the knobs below; an environment variable, when set,
  // overrides the file for its knob, and a command-line argument overrides the
  // environment. A missing default file is fine (env/baked only); a bad file is
  // a fatal operator error.
  std::string config_error;
  bool config_found = false;
  std::string config_path;
  const auto config = load_node_config(config_error, config_found, config_path);
  if (!config) {
    std::fprintf(stderr, "%s\n", config_error.c_str());
    return 2;
  }
  if (config_found) {
    std::printf("config: %s\n", config_path.c_str());
  }
  const auto join = [](const std::vector<std::string>& v, char sep) {
    std::string out;
    for (const auto& s : v) {
      if (!out.empty()) {
        out.push_back(sep);
      }
      out += s;
    }
    return out;
  };

  // Resolve the network (cluster) this node joins. TIER_NETWORK selects it;
  // unset means the config file, then mainnet. Networks are isolated at the
  // handshake, so a typo would silently strand the node on a cluster of one -
  // validate and fail fast.
  std::string network(tier::core::kDefaultNetwork);
  if (config->network) {
    network = *config->network;
  }
  if (const char* const env = std::getenv("TIER_NETWORK");
      env != nullptr && *env != '\0') {
    network = env;
  }
  if (!tier::core::is_valid_network_name(network)) {
    std::fprintf(stderr,
                 "invalid TIER_NETWORK '%s' (expected [a-z0-9-], 1..32 chars)\n",
                 network.c_str());
    return 2;
  }
  std::printf("network: %s\n", network.c_str());

  // Resolve this network's software-version policy: the baked per-network
  // default, overridden by TIER_VERSION_RANGE ("min,max", min inclusive, max
  // exclusive). The range is local policy, never sent on the wire. A malformed
  // override is an operator error - fail fast rather than join unconstrained.
  tier::core::VersionRange version_range =
      tier::core::network_version_range(network);
  std::optional<std::string> version_range_spec;
  if (config->version_range) {
    version_range_spec = *config->version_range;
  }
  if (const char* const env = std::getenv("TIER_VERSION_RANGE");
      env != nullptr && *env != '\0') {
    version_range_spec = env;
  }
  if (version_range_spec) {
    const auto parsed = tier::core::parse_version_range(*version_range_spec);
    if (!parsed) {
      std::fprintf(stderr,
                   "invalid version_range '%s' (expected \"min,max\", "
                   "min inclusive and max exclusive, e.g. \"1.4.0,1.5.0\")\n",
                   version_range_spec->c_str());
      return 2;
    }
    version_range = *parsed;
  }
  // Self-check: refuse to join a network this build is not allowed on, so an
  // out-of-policy node fails closed instead of being silently ignored by peers.
  if (!tier::core::version_admitted(version_range, tier::core::version())) {
    std::fprintf(stderr,
                 "version %.*s is not allowed on network %s (policy %s)\n",
                 static_cast<int>(tier::core::version().size()),
                 tier::core::version().data(), network.c_str(),
                 tier::core::to_string(version_range).c_str());
    return 2;
  }
  if (!version_range.unconstrained()) {
    std::printf("version policy: %s\n",
                tier::core::to_string(version_range).c_str());
  }

  // Roles this node holds (config `roles`, overridable by TIER_ROLES; default
  // plain client). A client is an edge node - dial-out only; any other role
  // makes it reachable infrastructure (docs/topology.md). Fail fast on an
  // unknown name rather than start with a silently wrong role set.
  std::string roles_spec;
  bool roles_set = false;
  if (config->roles) {
    roles_spec = join(*config->roles, '|');
    roles_set = true;
  }
  if (const char* const env = std::getenv("TIER_ROLES");
      env != nullptr && *env != '\0') {
    roles_spec = env;
    roles_set = true;
  }
  const auto roles = parse_roles(roles_set ? roles_spec.c_str() : nullptr);
  if (!roles) {
    std::fprintf(stderr,
                 "invalid roles '%s' (expected names from "
                 "client|validator|keeper|transmitter|communicator, e.g. "
                 "\"transmitter\" or \"validator|keeper\")\n",
                 roles_spec.c_str());
    return 2;
  }
  std::printf("roles: %s\n", format_roles(*roles).c_str());

  // Bind the IPv6 wildcard: the endpoint's socket is dual-stack, so "::" serves
  // both IPv6 and IPv4 (v4-mapped) peers. "0.0.0.0" would bind the v4 side only.
  tier::net::Node node(identity, *roles, "::", port, {}, network,
                       version_range);

  // User identities are hosted at runtime via tierctl (user add / ls / rm), not
  // via configuration or environment. Load any previously added users from the
  // node's state directory so they survive a restart; new ones are persisted
  // there on add (see docs/multi-identity.md).
  const std::string users_dir = resolve_users_dir();
  load_users(node, users_dir);

  // Application layer (layer 2, see docs/app-protocol.md). The hub holds live
  // subscriber connections; the dispatcher routes incoming user messages to the
  // built-in handlers through the daemon context. Node (device-to-device)
  // messages are untouched: they stay in the node inbox for `tierctl inbox`.
  tier::net::SubscriberHub hub;
  tier::app::AppDispatcher dispatcher;
  dispatcher.register_handler(tier::app::make_text_handler());
  dispatcher.register_handler(tier::app::make_receipt_handler());
  DaemonAppContext app_ctx(node, hub);
  // A user message is not buffered on the node; it arrives here and is enqueued
  // for the dispatcher, which delivers it to the recipient user's subscribers or
  // drops it (online-only). A plain node message carries no sender_user and is
  // ignored here (it is in the inbox already).
  node.on_message_received(
      [&dispatcher](const tier::net::Node::ReceivedMessage& m) {
        if (!m.sender_user || !m.recipient_user) {
          return;
        }
        tier::app::RawUserMessage raw;
        raw.sender_user = *m.sender_user;
        raw.recipient_user = *m.recipient_user;
        raw.suite = m.suite;
        raw.frame_bytes = m.plaintext;
        dispatcher.enqueue(std::move(raw));
      });

  const tier::core::PeerId self = node.peer_id();
  node.on_membership_change([self](const tier::core::PeerInfo& peer) {
    if (peer.id == self) {
      // Our own entry changed: we adopted a reachable address from a peer.
      std::printf("advertising addr=%s\n", join_addresses(peer.addresses).c_str());
      std::fflush(stdout);
      return;
    }
    std::fputs("discovered peer ", stdout);
    for (const auto b : peer.id) {
      std::printf("%02x", static_cast<unsigned>(b));
    }
    std::printf(" roles=%s addr=%s\n", format_roles(peer.roles).c_str(),
                join_addresses(peer.addresses).c_str());
    std::fflush(stdout);
  });

  print_hex("node id:  ", node.peer_id());
  std::printf("listening on [::]:%u\n", static_cast<unsigned>(node.local_port()));

  // Join via the preconfigured seeds baked into the binary. One reachable seed
  // is enough; the rest of the membership arrives by anti-entropy. A node that
  // is itself a seed skips its own address.
  //
  // The config `seeds` list, or TIER_SEEDS when set, FULLY replaces the baked
  // list (private networks, localnet, e2e tests): the node then dials only those
  // addresses and never the production seeds. An override that parses to nothing
  // is honored as an isolated node rather than silently falling back, so a test
  // net can never leak onto the real network. Env overrides the config file.
  std::vector<std::string> seeds;
  if (const char* const env = std::getenv("TIER_SEEDS");
      env != nullptr && *env != '\0') {
    seeds = tier::core::parse_seed_list(env);
    std::printf("TIER_SEEDS override: %zu seed address(es)\n", seeds.size());
  } else if (config->seeds) {
    seeds = tier::core::parse_seed_list(join(*config->seeds, ' '));
    std::printf("config seeds: %zu seed address(es)\n", seeds.size());
  } else {
    seeds = tier::core::seed_addresses(network);
    std::printf("dialing %zu preconfigured seed address(es) for %s\n",
                seeds.size(), network.c_str());
  }
  node.bootstrap(seeds);

  // An optional explicit seed on the command line is dialed in addition.
  if (has_seed) {
    std::printf("dialing seed %s:%u\n", seed_ip, static_cast<unsigned>(seed_port));
    node.connect(seed_ip, seed_port);
  }
  std::fflush(stdout);

  // Local admin/diagnostics socket for tierctl. Optional: if it cannot be set
  // up (e.g. the runtime directory is missing outside systemd) the node runs
  // without it rather than failing. The handler answers from the live view.
  std::optional<tier::net::AdminListener> admin;
  const std::string admin_path = resolve_admin_path();
  try {
    admin.emplace(admin_path);
    std::printf("admin socket: %s\n", admin_path.c_str());
  } catch (const std::exception& e) {
    std::printf("admin socket disabled (%s)\n", e.what());
  }
  std::fflush(stdout);
  const auto admin_handler =
      [&node, &users_dir](
          const tier::core::AdminRequest& req) -> std::vector<std::uint8_t> {
    switch (req.op) {
      case tier::core::AdminOp::id: {
        tier::core::AdminId id;
        id.device_id = node.peer_id();
        return tier::core::encode_admin_id_reply(id);
      }
      case tier::core::AdminOp::peers:
        return tier::core::encode_admin_peers(node.network(),
                                              node.membership().snapshot(),
                                              node.connected_peers());
      case tier::core::AdminOp::send: {
        if (!tier::msg::is_known_suite(req.suite)) {
          return tier::core::encode_admin_send_reply(false);
        }
        const auto result = node.send_message(
            req.recipient, static_cast<tier::msg::Suite>(req.suite),
            std::span<const tier::crypto::Byte>(req.plaintext.data(),
                                                req.plaintext.size()));
        // Accepted for delivery whether sent now or queued pending discovery;
        // only an outright failure (e.g. unknown suite, self-send) is false.
        const bool accepted =
            result != tier::net::Node::SendResult::failed;
        return tier::core::encode_admin_send_reply(accepted);
      }
      case tier::core::AdminOp::send_as: {
        if (!tier::msg::is_known_suite(req.suite)) {
          return tier::core::encode_admin_send_as_reply(false);
        }
        const auto result = node.send_as_user(
            req.from_user, req.recipient,
            static_cast<tier::msg::Suite>(req.suite),
            std::span<const tier::crypto::Byte>(req.plaintext.data(),
                                                req.plaintext.size()));
        return tier::core::encode_admin_send_as_reply(
            result != tier::net::Node::SendResult::failed);
      }
      case tier::core::AdminOp::user_add: {
        tier::crypto::NodeIdentity ident =
            req.has_seed
                ? tier::crypto::NodeIdentity::from_seed(tier::crypto::ByteSpan(
                      req.seed.data(), req.seed.size()))
                : tier::crypto::NodeIdentity::generate();
        const auto seed = ident.seed();  // copy before the identity is moved
        tier::core::AdminUserAddReply rep;
        rep.user_id = node.add_user(std::move(ident));
        // Persist so the user survives a restart.
        std::error_code ec;
        std::filesystem::create_directories(users_dir, ec);
        const std::string path =
            users_dir + "/" + hex_of(rep.user_id) + ".seed";
        rep.ok = persist_seed(path, tier::crypto::ByteSpan(
                                         seed.data(), seed.size())) !=
                 PersistResult::error;
        return tier::core::encode_admin_user_add_reply(rep);
      }
      case tier::core::AdminOp::user_list:
        return tier::core::encode_admin_user_list(node.user_ids());
      case tier::core::AdminOp::user_remove: {
        const bool existed = node.remove_user(req.recipient);
        if (existed) {
          std::error_code ec;
          std::filesystem::remove(
              users_dir + "/" + hex_of(req.recipient) + ".seed", ec);
        }
        return tier::core::encode_admin_user_remove_reply(existed);
      }
      case tier::core::AdminOp::inbox: {
        std::vector<tier::core::AdminInboxMessage> out;
        for (auto& m : node.take_inbox()) {
          tier::core::AdminInboxMessage im;
          im.sender = m.sender;
          im.sender_user = m.sender_user;
          im.recipient_user = m.recipient_user;
          im.suite = static_cast<std::uint8_t>(m.suite);
          im.plaintext = std::move(m.plaintext);
          out.push_back(std::move(im));
        }
        return tier::core::encode_admin_inbox(out);
      }
      case tier::core::AdminOp::subscribe:
        // Handled by the subscribe hook (the connection is kept open); if it
        // ever reaches here, close the connection with no reply.
        return {};
    }
    return {};
  };

  // Periodically report how many peers we know of versus how many we actually
  // hold a connection to, so mesh formation is visible at a glance.
  // A subscribe request's connection is kept open and handed to the hub, keyed
  // by the local user it streams. A user hosted here can be subscribed to even
  // before it is added; delivery just finds no subscriber until one attaches.
  const auto subscribe_hook = [&hub](const tier::core::AdminRequest& req,
                                     int fd) -> bool {
    hub.add(req.recipient, fd);
    return true;
  };

  auto last_status = std::chrono::steady_clock::now();
  for (;;) {
    node.poll(200);
    // Route any user messages that arrived during the poll to their handlers
    // (delivering to live subscribers, emitting receipts). Sequential for now.
    dispatcher.drain(app_ctx);
    if (admin) {
      admin->serve(admin_handler, subscribe_hook);
    }
    const auto now = std::chrono::steady_clock::now();
    if (now - last_status >= std::chrono::seconds(2)) {
      std::printf("status: known=%zu connected=%zu\n", node.membership().size(),
                  node.connected_peers().size());
      std::fflush(stdout);
      last_status = now;
    }
  }
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
  tier::net::Endpoint ep(identity, "::", port);
  ep.on_handshake(
      [](tier::net::ConnId, bool, const tier::net::PeerId& peer) {
        print_hex("peer connected: ", peer);
        std::fflush(stdout);
      });
  ep.on_message([&ep](tier::net::ConnId conn, const tier::net::PeerId&,
                      std::span<const tier::crypto::Byte> payload) {
    ep.send(conn, payload);  // echo
    std::printf("echoed %zu bytes\n", payload.size());
    std::fflush(stdout);
  });

  print_hex("node id:  ", identity.public_key());
  std::printf("listening on [::]:%u\n", static_cast<unsigned>(ep.local_port()));
  std::fflush(stdout);
  for (;;) {
    ep.poll(1000);
  }
}

int run_connect(const tier::crypto::NodeIdentity& identity, const char* ip,
                std::uint16_t port) {
  tier::net::Endpoint ep(identity, "::", 0);
  const std::vector<tier::crypto::Byte> ping{0x70, 0x69, 0x6E, 0x67};  // "ping"

  bool got_echo = false;
  ep.on_handshake([&ep, &ping](tier::net::ConnId conn, bool initiator,
                               const tier::net::PeerId& peer) {
    print_hex("connected to: ", peer);
    if (initiator) {
      ep.send(conn, ping);
    }
  });
  ep.on_message([&got_echo](tier::net::ConnId, const tier::net::PeerId&,
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

  // Read-only diagnostics that need no node identity (so they do not create a
  // key file as a side effect).
  if (std::string_view(argv[1]) == "networks") {
    if (argc != 2) {
      return usage();
    }
    return run_networks();
  }

  const std::string id_path = resolve_id_path();
  const auto identity_opt = load_or_create_identity(id_path);
  if (!identity_opt) {
    return 2;  // identity could not be loaded or safely created
  }
  const tier::crypto::NodeIdentity& identity = *identity_opt;
  std::printf("id file:  %s\n", id_path.c_str());
  const std::string_view cmd = argv[1];

  if (cmd == "run") {
    std::uint16_t port = 0;
    if ((argc != 3 && argc != 5) || !parse_port(argv[2], port)) {
      return usage();
    }
    if (argc == 5) {
      std::uint16_t seed_port = 0;
      if (!parse_port(argv[4], seed_port)) {
        return usage();
      }
      return run_node(identity, port, argv[3], seed_port, true);
    }
    return run_node(identity, port, nullptr, 0, false);
  }

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
