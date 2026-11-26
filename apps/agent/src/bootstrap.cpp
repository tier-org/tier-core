#include "bootstrap.hpp"

#include <grp.h>
#include <spawn.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "admin_client.hpp"
#include "config.hpp"
#include "files.hpp"
#include "socket_io.hpp"
#include "tier/core/address.hpp"
#include "tier/crypto/identity.hpp"
#include "tier/msg/user.hpp"

extern char** environ;

namespace tier::agent {
namespace {

using namespace std::literals::chrono_literals;
using namespace std::literals::string_view_literals;

constexpr auto kConfigDirectory = "/etc/tier/"sv;
constexpr auto kTemplateDirectory = "/usr/share/tier/agent/"sv;
constexpr auto kCollectorSocket = "/run/tier-agent/agent-query.sock"sv;
constexpr auto kViewerGroup = "tier-monitor"sv;
constexpr auto kCollectorPlaceholder = "@COLLECTOR_ADDRESS@"sv;
constexpr const char* kSystemctl = "/usr/bin/systemctl";
constexpr const char* kViewerService = "tier-agent-view.service";

struct Options {
  Role role = Role::collector;
  bool view = false;
  tier::core::PeerId collector{};
};

void usage(FILE* out) {
  std::fputs("usage:\n"
             "  tier-agent bootstrap collector [--view]\n"
             "  tier-agent bootstrap client --collector=<address>\n", out);
}

std::optional<Options> parse_options(int argc, char* const argv[]) {
  const std::string_view role = argc >= 1 ? argv[0] : "";
  if (role == "collector") {
    if (argc == 1) return Options{};
    if (argc == 2 && std::string_view(argv[1]) == "--view") {
      return Options{.view = true};
    }
  } else if (role == "client") {
    constexpr auto prefix = "--collector="sv;
    std::string_view address;
    if (argc == 2 && std::string_view(argv[1]).starts_with(prefix)) {
      address = std::string_view(argv[1]).substr(prefix.size());
    } else if (argc == 3 && std::string_view(argv[1]) == "--collector") {
      address = argv[2];
    }
    if (!address.empty()) {
      const auto id = tier::core::id_from_address(address);
      if (id) return Options{.role = Role::agent, .collector = *id};
      std::fprintf(stderr, "bootstrap: invalid collector address: %.*s\n",
                   static_cast<int>(address.size()), address.data());
    }
  }
  return std::nullopt;
}

bool run_command(std::vector<std::string> arguments) {
  std::vector<char*> args;
  args.reserve(arguments.size() + 1);
  for (auto& argument : arguments) args.push_back(argument.data());
  args.push_back(nullptr);

  // Keep stdout available for the collector address, including when the
  // operator captures it with command substitution.
  posix_spawn_file_actions_t actions;
  if (::posix_spawn_file_actions_init(&actions) != 0) return false;
  int error = ::posix_spawn_file_actions_adddup2(&actions, STDERR_FILENO, STDOUT_FILENO);
  pid_t child = 0;
  if (error == 0) error = ::posix_spawn(&child, args.front(), &actions, nullptr, args.data(), environ);
  ::posix_spawn_file_actions_destroy(&actions);
  if (error != 0) {
    std::fprintf(stderr, "bootstrap: cannot run %s: %s\n", args.front(), std::strerror(error));
    return false;
  }
  int status = 0;
  pid_t waited = 0;
  do {
    waited = ::waitpid(child, &status, 0);
  } while (waited < 0 && errno == EINTR);
  return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

std::optional<std::string> read_config_text(const std::string& path) {
  std::error_code ec;
  if (!std::filesystem::is_regular_file(path, ec)) return std::nullopt;
  std::ifstream config(path);
  if (!config) return std::nullopt;
  return std::string(std::istreambuf_iterator<char>(config), std::istreambuf_iterator<char>());
}

std::optional<Config> checked_config(const Options& options, const std::string& path,
                                    const std::string& text) {
  std::string error;
  auto config = parse_config(text, error);
  if (!config) {
    std::fprintf(stderr, "bootstrap: %s: %s\n", path.c_str(), error.c_str());
    return std::nullopt;
  }
  if (config->role != options.role) {
    std::fprintf(stderr, "bootstrap: %s has a different role. Review the config and rerun.\n",
                 path.c_str());
    return std::nullopt;
  }
  if (options.role == Role::agent && config->collector != options.collector) {
    const auto configured = tier::core::address_from_id_prefixed(config->collector);
    const auto requested = tier::core::address_from_id_prefixed(options.collector);
    std::fprintf(stderr, "bootstrap: %s uses collector %s. Edit it explicitly to switch to %s, "
                         "then restart tier-agent@agent.service.\n",
                 path.c_str(), configured.c_str(), requested.c_str());
    return std::nullopt;
  }
  if (options.role == Role::agent && config->exec.empty()) {
    std::fprintf(stderr, "bootstrap: set [agent] exec in %s to run the agent under systemd.\n",
                 path.c_str());
    return std::nullopt;
  }
  if (options.view && (config->query_socket != kCollectorSocket ||
                       config->query_socket_group != kViewerGroup)) {
    std::fprintf(stderr, "bootstrap: to use the default viewer, set query_socket = \"%s\" "
                         "and query_socket_group = \"%s\" in [collector] in %s. "
                         "If the collector is running, restart it after editing.\n",
                 kCollectorSocket.data(), kViewerGroup.data(), path.c_str());
    return std::nullopt;
  }
  return config;
}

std::optional<Config> load_existing(const Options& options, const std::string& path) {
  auto text = read_config_text(path);
  if (!text) {
    std::fprintf(stderr, "bootstrap: cannot read %s\n", path.c_str());
    return std::nullopt;
  }
  return checked_config(options, path, *text);
}

std::optional<Config> prepare_config(const Options& options, const char* name) {
  const std::string path = std::string(kConfigDirectory) + name + ".toml";
  struct stat info {};
  if (::lstat(path.c_str(), &info) == 0) return load_existing(options, path);
  if (errno != ENOENT) {
    std::fprintf(stderr, "bootstrap: cannot inspect %s: %s\n", path.c_str(), std::strerror(errno));
    return std::nullopt;
  }

  const std::string source = std::string(kTemplateDirectory) + name + ".toml";
  auto text = read_config_text(source);
  if (!text) {
    std::fprintf(stderr, "bootstrap: missing packaged template %s\n", source.c_str());
    return std::nullopt;
  }
  if (options.role == Role::agent) {
    const auto position = text->find(kCollectorPlaceholder);
    if (position == std::string::npos) {
      std::fprintf(stderr, "bootstrap: missing collector placeholder in %s\n", source.c_str());
      return std::nullopt;
    }
    text->replace(position, kCollectorPlaceholder.size(),
                  tier::core::address_from_id_prefixed(options.collector));
  } else {
    // The packaged collector template ends in [collector]. Reserve the group
    // on first setup so --view can be enabled later using the same config.
    text->append("\nquery_socket_group = \"tier-monitor\"\n");
  }
  auto config = checked_config(options, source, *text);
  if (!config) return std::nullopt;

  std::error_code ec;
  std::filesystem::create_directories(kConfigDirectory, ec);
  const auto result = ec ? FileResult::error : create_private_file(path, *text);
  if (result == FileResult::exists) return load_existing(options, path);
  if (result != FileResult::ok) {
    std::fprintf(stderr, "bootstrap: cannot create %s\n", path.c_str());
    return std::nullopt;
  }
  std::fprintf(stderr, "bootstrap: created %s\n", path.c_str());
  return config;
}

bool ensure_socket_group(const Config& config) {
  if (config.query_socket_group.empty() ||
      ::getgrnam(config.query_socket_group.c_str()) != nullptr) {
    return true;
  }
  if (config.query_socket_group == kViewerGroup) {
    run_command({"/usr/sbin/groupadd", "--system", std::string(kViewerGroup)});
    if (::getgrnam(kViewerGroup.data()) != nullptr) return true;
  }
  std::fprintf(stderr, "bootstrap: query socket group is unavailable: %s\n",
               config.query_socket_group.c_str());
  return false;
}

bool query_socket_ready(const std::string& path) {
  if (path.empty()) return true;
  constexpr timeval timeout{1, 0};
  const int fd = connect_unix(path, &timeout);
  if (fd < 0) return false;
  send_all(fd, "TIER-QUERY/1 probe\n");
  ::close(fd);
  return true;
}

bool viewer_socket_access(const Config& config) {
  const auto* group = ::getgrnam(kViewerGroup.data());
  struct stat info {};
  if (group != nullptr && ::stat(config.query_socket.c_str(), &info) == 0 &&
      S_ISSOCK(info.st_mode) && info.st_gid == group->gr_gid && (info.st_mode & S_IWGRP) != 0) {
    return true;
  }
  std::fputs("bootstrap: restart tier-agent@collector.service to apply the query socket group.\n",
             stderr);
  return false;
}

std::optional<tier::core::PeerId> wait_until_ready(AdminClient& admin, const Config& config) {
  const auto deadline = std::chrono::steady_clock::now() + 15s;
  std::optional<tier::core::PeerId> id;
  do {
    if (!id) {
      Seed seed{};
      const auto result = read_seed_file(config.seed_file, seed);
      if (result == FileResult::error) return std::nullopt;
      if (result == FileResult::ok) {
        id = tier::msg::user_id_of(tier::crypto::NodeIdentity::from_seed(seed).public_key());
      }
    }
    if (id) {
      const auto users = admin.local_users();
      if (users && std::ranges::find(*users, *id) != users->end() &&
          (config.role == Role::agent || query_socket_ready(config.query_socket))) {
        return id;
      }
    }
    std::this_thread::sleep_for(250ms);
  } while (std::chrono::steady_clock::now() < deadline);
  return std::nullopt;
}

bool start_service(const std::string& service) {
  if (run_command({kSystemctl, "enable", "--now", service})) return true;
  std::fprintf(stderr, "bootstrap: could not enable and start %s. See: systemctl status %s\n",
               service.c_str(), service.c_str());
  return false;
}

}  // namespace

int run_bootstrap(int argc, char* const argv[]) {
  if (argc == 1 && (std::string_view(argv[0]) == "--help" ||
                    std::string_view(argv[0]) == "-h")) {
    usage(stdout);
    return 0;
  }
  const auto options = parse_options(argc, argv);
  if (!options) {
    usage(stderr);
    return 2;
  }
  if (::geteuid() != 0) {
    std::fputs("bootstrap: run this command with sudo to configure the system service.\n", stderr);
    return 1;
  }

  const char* name = options->role == Role::collector ? "collector" : "agent";
  const auto config = prepare_config(*options, name);
  if (!config) return 1;
  AdminClient admin(config->admin_socket);
  if (!admin.local_users()) {
    std::fprintf(stderr, "bootstrap: local tierd is unavailable at %s. Start tierd and rerun.\n",
                 config->admin_socket.c_str());
    return 1;
  }
  Seed seed{};
  if (read_seed_file(config->seed_file, seed) == FileResult::error) {
    std::fprintf(stderr, "bootstrap: cannot read the existing 32-byte seed at %s.\n",
                 config->seed_file.c_str());
    return 1;
  }
  if (options->role == Role::collector && !ensure_socket_group(*config)) return 1;

  const std::string service = std::string("tier-agent@") + name + ".service";
  if (!start_service(service)) return 1;
  const auto id = wait_until_ready(admin, *config);
  if (!id || !run_command({kSystemctl, "is-active", "--quiet", service})) {
    std::fprintf(stderr, "bootstrap: %s did not become ready. See: journalctl -u %s\n",
                 service.c_str(), service.c_str());
    return 1;
  }
  if (options->view && (!viewer_socket_access(*config) || !start_service(kViewerService))) {
    return 1;
  }

  if (options->role == Role::collector) {
    std::fprintf(stderr, "bootstrap: collector ready%s.\n", options->view ? ", viewer enabled" : "");
    const auto address = tier::core::address_from_id_prefixed(*id);
    std::fprintf(stderr, "  Configure storage, retention and allowed agents in /etc/tier/collector.toml.\n"
                         "  To enroll a monitored host, run there:\n"
                         "    sudo tier-agent bootstrap client --collector=%s\n",
                 address.c_str());
    if (!config->query_socket.empty()) {
      std::fprintf(stderr, "  Inspect samples with sudo tier-agent query using this socket: %s\n",
                   config->query_socket.c_str());
    }
    if (options->view) {
      std::fputs("  Default panel: http://127.0.0.1:8080/ on the collector. "
                 "Use an SSH tunnel for remote access.\n", stderr);
    }
    std::printf("%s\n", address.c_str());
  } else {
    std::fprintf(stderr, "bootstrap: %s is ready and configured for collector %s.\n",
                 service.c_str(), tier::core::address_from_id_prefixed(options->collector).c_str());
    std::fputs("  Configure the source and reporting interval in /etc/tier/agent.toml under [agent].\n"
               "  To add metrics, set exec to your own command. Emit one sample per line on stdout:\n"
               "    gauge app.queue_depth 42\n"
               "    event app.backup completed\n"
               "  See /usr/libexec/tier/host-metrics.sh for the packaged example.\n", stderr);
  }
  std::fprintf(stderr, "  After editing the config: sudo systemctl restart %s\n", service.c_str());
  return 0;
}

}  // namespace tier::agent
