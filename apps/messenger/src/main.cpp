#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "node_client.hpp"
#include "store.hpp"
#include "ui.hpp"
#include "util.hpp"

namespace {

std::string resolve_sock(const std::string& override_path) {
  if (!override_path.empty()) {
    return override_path;
  }
  if (const char* const env = std::getenv("TIER_ADMIN_SOCK"); env != nullptr && *env != '\0') {
    return env;
  }
  return "/run/tierd/tierd.sock";
}

std::string resolve_db(const std::string& override_path) {
  if (!override_path.empty()) {
    return override_path;
  }
  if (const char* const env = std::getenv("TIER_MESSENGER_DB"); env != nullptr && *env != '\0') {
    return env;
  }
  std::filesystem::path base;
  if (const char* const xdg = std::getenv("XDG_DATA_HOME"); xdg != nullptr && *xdg != '\0') {
    base = xdg;
  } else if (const char* const home = std::getenv("HOME"); home != nullptr && *home != '\0') {
    base = std::filesystem::path(home) / ".local" / "share";
  } else {
    base = ".";
  }
  return (base / "tier-messenger" / "store.db").string();
}

int usage() {
  std::fputs(
      "usage: tier-messenger [--sock <path>] [--db <path>] [--as <user-id>]\n"
      "  connects to the local tierd admin socket and opens an interactive\n"
      "  messenger. --as selects which hosted user identity to chat as; without\n"
      "  it, the sole identity is used, or one is created if none exist.\n"
      "  Esc or Ctrl-C quits.\n",
      stderr);
  return 2;
}

}  // namespace

int main(int argc, char** argv) {
  std::string sock_override;
  std::string db_override;
  std::string as_hex;
  for (int i = 1; i < argc; ++i) {
    const std::string_view a = argv[i];
    if ((a == "--sock" || a == "--db" || a == "--as") && i + 1 < argc) {
      const std::string v = argv[++i];
      if (a == "--sock") sock_override = v;
      else if (a == "--db") db_override = v;
      else as_hex = v;
    } else {
      return usage();  // unknown flag, or -h/--help
    }
  }

  const std::string sock = resolve_sock(sock_override);
  const std::string db_path = resolve_db(db_override);

  std::error_code ec;
  std::filesystem::create_directories(std::filesystem::path(db_path).parent_path(), ec);
  auto store_opt = tier::messenger::Store::open(db_path);
  if (!store_opt.has_value()) {
    std::fprintf(stderr, "cannot open store at %s\n", db_path.c_str());
    return 1;
  }
  tier::messenger::Store& store = *store_opt;

  tier::messenger::NodeClient client(sock);
  const auto users_opt = client.list_users();
  if (!users_opt.has_value()) {
    std::fprintf(stderr, "cannot reach tierd at %s (is it running?)\n", sock.c_str());
    return 1;
  }
  const std::vector<tier::core::PeerId>& users = *users_opt;

  // Choose the identity to act as.
  tier::core::PeerId account{};
  if (!as_hex.empty()) {
    const auto id = tier::messenger::from_hex(as_hex);
    if (!id.has_value()) {
      std::fprintf(stderr, "invalid --as user id (expected 64 hex chars)\n");
      return 1;
    }
    const tier::core::PeerId wanted = *id;
    bool hosted = false;
    for (const auto& u : users) {
      if (u == wanted) hosted = true;
    }
    if (!hosted) {
      std::fprintf(stderr, "user %s is not hosted on this node (tierctl user ls)\n",
                   as_hex.c_str());
      return 1;
    }
    account = wanted;
  } else if (users.size() == 1) {
    account = users[0];
  } else if (users.empty()) {
    std::fputs("no user identity on this node; creating one...\n", stderr);
    const auto created = client.add_user(std::nullopt);
    if (!created.has_value()) {
      std::fprintf(stderr, "could not create a user identity\n");
      return 1;
    }
    account = *created;
    std::fprintf(stderr, "created user %s\n", tier::messenger::to_hex(account).c_str());
  } else {
    std::fputs("several identities are hosted; choose one to chat as:\n", stderr);
    for (std::size_t i = 0; i < users.size(); ++i) {
      const auto hex = tier::messenger::to_hex(users[i]);
      const auto alias = store.account_alias(hex);
      std::string line = hex.substr(0, 16);
      if (alias.has_value() && !alias->empty()) {
        line += "  " + *alias;
      }
      std::fprintf(stderr, "  [%zu] %s\n", i, line.c_str());
    }
    std::fprintf(stderr, "number (or re-run with --as <user-id>): ");
    std::fflush(stderr);
    int choice = -1;
    if (std::scanf("%d", &choice) != 1 || choice < 0 ||
        choice >= static_cast<int>(users.size())) {
      std::fprintf(stderr, "no valid selection\n");
      return 1;
    }
    account = users[static_cast<std::size_t>(choice)];
  }

  return tier::messenger::run_ui(client, store, account);
}
