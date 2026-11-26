#include <arpa/inet.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>

#include "socket_io.hpp"
#include "view_assets.hpp"

namespace {

using tier::agent::send_all;
using tier::agent::set_socket_timeout;
using namespace std::literals::string_view_literals;

constexpr std::size_t kMaxHeaders = std::size_t{16} * 1024;
constexpr std::size_t kMaxSnapshot = std::size_t{16} * 1024 * 1024;
constexpr std::size_t kMaxConfig = std::size_t{1024} * 1024;
constexpr auto kNodesPath = "/nodes/"sv;
constexpr auto kSenderQuery = "sender="sv;

class Socket {
 public:
  explicit Socket(int fd) : fd_(fd) {}
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  ~Socket() {
    if (fd_ >= 0) ::close(fd_);
  }
  [[nodiscard]] int fd() const { return fd_; }

 private:
  int fd_;
};

struct Options {
  std::string socket = "/run/tier-agent/agent-query.sock";
  std::string config_path;
  std::uint16_t port = 8080;
};

void usage(FILE* out) {
  std::fputs("usage: tier-agent-view [--socket PATH] [--port PORT] [--config FILE]\n"
             "Read-only fleet dashboard for the local tier-agent collector.\n", out);
}

std::optional<Options> parse_options(int argc, char* argv[]) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string_view argument(argv[i]);
    const auto equals = argument.find('=');
    const auto option = argument.substr(0, equals);
    if (equals == std::string_view::npos && ++i == argc) return std::nullopt;
    const std::string_view value = equals == std::string_view::npos
                                       ? std::string_view(argv[i])
                                       : argument.substr(equals + 1);
    if (value.empty() || value.starts_with("--")) return std::nullopt;
    if (option == "--socket") {
      options.socket = value;
    } else if (option == "--config") {
      options.config_path = value;
    } else if (option == "--port") {
      const auto* end = value.data() + value.size();
      const auto [pos, ec] = std::from_chars(value.data(), end, options.port);
      if (ec != std::errc{} || pos != end || options.port == 0) return std::nullopt;
    } else {
      return std::nullopt;
    }
  }
  return options;
}

bool is_sender_id(std::string_view sender) {
  return sender.size() == 64 &&
         sender.find_first_not_of("0123456789abcdef") == std::string_view::npos;
}

std::optional<std::string> load_config(const std::string& path) {
  if (path.empty()) return "{}";
  std::error_code ec;
  if (!std::filesystem::is_regular_file(path, ec)) return std::nullopt;
  std::ifstream stream(path, std::ios::binary);
  if (!stream) return std::nullopt;
  std::string data(kMaxConfig + 1, '\0');
  stream.read(data.data(), static_cast<std::streamsize>(data.size()));
  const auto size = static_cast<std::size_t>(stream.gcount());
  if (size > kMaxConfig || stream.bad()) return std::nullopt;
  data.resize(size);
  const auto start = data.find_first_not_of(" \t\r\n");
  if (start == std::string::npos || data[start] != '{' ||
      data[data.find_last_not_of(" \t\r\n")] != '}') {
    return std::nullopt;
  }
  return data;
}

std::optional<std::string> read_snapshot(const std::string& path, std::string_view sender) {
  constexpr timeval timeout{3, 0};
  const Socket connection(tier::agent::connect_unix(path, &timeout));
  if (connection.fd() < 0) return std::nullopt;
  std::string request = "TIER-QUERY/1";
  if (!sender.empty()) request.append(" ").append(sender);
  request.push_back('\n');
  if (!send_all(connection.fd(), request)) return std::nullopt;
  ::shutdown(connection.fd(), SHUT_WR);

  std::string data;
  std::array<char, 8192> buffer{};
  while (true) {
    const ssize_t n = ::recv(connection.fd(), buffer.data(), buffer.size(), 0);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) return std::nullopt;
    if (n == 0) break;
    const auto count = static_cast<std::size_t>(n);
    if (count > kMaxSnapshot - data.size()) return std::nullopt;
    data.append(buffer.data(), count);
  }
  if (data.empty() || data.front() != '{' || data.back() != '\n') return std::nullopt;
  return data;
}

std::optional<std::string> read_headers(int fd) {
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  std::array<char, 2048> buffer{};
  std::string data;
  while (data.size() < kMaxHeaders && std::chrono::steady_clock::now() < deadline) {
    const auto size = std::min(buffer.size(), kMaxHeaders - data.size());
    const ssize_t n = ::recv(fd, buffer.data(), size, 0);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    data.append(buffer.data(), static_cast<std::size_t>(n));
    if (const auto end = data.find("\r\n\r\n"); end != std::string::npos) {
      data.resize(end + 2);
      return data;
    }
  }
  return std::nullopt;
}

std::string_view next_line(std::string_view& headers) {
  const auto end = headers.find("\r\n");
  const auto line = headers.substr(0, end);
  headers.remove_prefix(end == std::string_view::npos ? headers.size() : end + 2);
  return line;
}

std::string_view host_header(std::string_view headers) {
  std::string_view host;
  bool seen = false;
  while (!headers.empty()) {
    const auto line = next_line(headers);
    const auto colon = line.find(':');
    if (colon != 4 || ::strncasecmp(line.data(), "Host", 4) != 0) continue;
    if (seen) return {};
    seen = true;
    const auto value = line.substr(colon + 1);
    const auto start = value.find_first_not_of(" \t");
    if (start == std::string_view::npos) return {};
    host = value.substr(start, value.find_last_not_of(" \t") - start + 1);
  }
  return host.substr(0, host.find(':'));
}

void reply(int fd, std::string_view status, std::string_view type, std::string_view body) {
  std::string headers = "HTTP/1.0 ";
  headers.append(status).append("\r\nContent-Type: ").append(type);
  headers.append("\r\nContent-Length: ").append(std::to_string(body.size()));
  headers.append("\r\nConnection: close\r\nCache-Control: no-store"
                 "\r\nX-Content-Type-Options: nosniff"
                 "\r\nContent-Security-Policy: default-src 'none'; script-src 'self'; "
                 "connect-src 'self'; style-src 'unsafe-inline'; frame-ancestors 'none'\r\n\r\n");
  if (send_all(fd, headers)) send_all(fd, body);
}

void serve_request(int fd, const Options& options, std::string_view config) {
  if (!set_socket_timeout(fd, timeval{2, 0})) return;
  constexpr auto text = "text/plain; charset=utf-8"sv;
  constexpr auto json = "application/json"sv;
  const auto request = read_headers(fd);
  if (!request) return;
  std::string_view headers(*request);
  const auto line = next_line(headers);
  const auto first = line.find(' ');
  const auto last = line.rfind(' ');
  const auto version = last == std::string_view::npos ? ""sv : line.substr(last + 1);
  if (first == last || (version != "HTTP/1.1" && version != "HTTP/1.0")) {
    reply(fd, "400 Bad Request", text, "Invalid request\n");
    return;
  }
  const auto host = host_header(headers);
  if (host != "127.0.0.1" && host != "localhost") {
    reply(fd, "400 Bad Request", text, "Use the loopback address\n");
    return;
  }
  if (line.substr(0, first) != "GET") {
    reply(fd, "405 Method Not Allowed", text, "Use GET\n");
    return;
  }
  const auto target = line.substr(first + 1, last - first - 1);
  const auto delimiter = target.find('?');
  const auto path = target.substr(0, delimiter);
  if (path == "/" || (path.starts_with(kNodesPath) && is_sender_id(path.substr(kNodesPath.size())))) {
    reply(fd, "200 OK", "text/html; charset=utf-8", tier::agent::view::kPage);
  } else if (path == "/view.js") {
    reply(fd, "200 OK", "text/javascript; charset=utf-8", tier::agent::view::kScript);
  } else if (path == "/api/config") {
    reply(fd, "200 OK", json, config);
  } else if (path == "/api/snapshot") {
    std::string_view sender;
    if (delimiter != std::string_view::npos) {
      const auto query = target.substr(delimiter + 1);
      if (!query.starts_with(kSenderQuery) || !is_sender_id(query.substr(kSenderQuery.size()))) {
        reply(fd, "400 Bad Request", text, "Invalid sender ID\n");
        return;
      }
      sender = query.substr(kSenderQuery.size());
    }
    const auto snapshot = read_snapshot(options.socket, sender);
    if (snapshot) {
      reply(fd, "200 OK", json, *snapshot);
    } else {
      reply(fd, "503 Service Unavailable", text, "Check the collector query socket\n");
    }
  } else {
    reply(fd, "404 Not Found", text, "Page not found\n");
  }
}

bool notify_systemd_ready() {
  const char* value = std::getenv("NOTIFY_SOCKET");
  if (value == nullptr) return true;
  const std::string_view path(value);
  sockaddr_un address{};
  address.sun_family = AF_UNIX;
  if (path.empty() || path.size() >= sizeof(address.sun_path) ||
      (path.front() != '/' && path.front() != '@')) {
    return false;
  }
  std::memcpy(address.sun_path, path.data(), path.size());
  std::size_t length = offsetof(sockaddr_un, sun_path) + path.size() + 1;
  if (path.front() == '@') {
    address.sun_path[0] = '\0';
    --length;
  }
  const Socket notification(::socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0));
  if (notification.fd() < 0) return false;
  constexpr auto ready = "READY=1"sv;
  return ::sendto(notification.fd(), ready.data(), ready.size(), MSG_NOSIGNAL,
                  reinterpret_cast<sockaddr*>(&address), static_cast<socklen_t>(length)) ==
         static_cast<ssize_t>(ready.size());
}

int serve(const Options& options, std::string_view config) {
  const Socket listener(::socket(AF_INET, SOCK_STREAM, 0));
  if (listener.fd() < 0) {
    std::perror("view: socket");
    return 1;
  }
  constexpr int reuse = 1;
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_port = htons(options.port);
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  if (::setsockopt(listener.fd(), SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0 ||
      ::bind(listener.fd(), reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0 ||
      ::listen(listener.fd(), 8) < 0) {
    std::perror("view: listen");
    return 1;
  }
  std::printf("Tier fleet at http://127.0.0.1:%u/\n", static_cast<unsigned>(options.port));
  std::fflush(stdout);
  if (!notify_systemd_ready()) {
    std::fputs("view: cannot notify systemd that the listener is ready\n", stderr);
    return 1;
  }
  while (true) {
    const Socket client(::accept(listener.fd(), nullptr, nullptr));
    if (client.fd() < 0) {
      if (errno == EINTR) continue;
      std::perror("view: accept");
      return 1;
    }
    serve_request(client.fd(), options, config);
  }
}

}  // namespace

int main(int argc, char* argv[]) {
  if (argc == 2 && (std::string_view(argv[1]) == "--help" ||
                    std::string_view(argv[1]) == "-h")) {
    usage(stdout);
    return 0;
  }
  const auto options = parse_options(argc, argv);
  if (!options || options->socket.size() >= sizeof(sockaddr_un::sun_path)) {
    usage(stderr);
    return 2;
  }
  const auto config = load_config(options->config_path);
  if (!config) {
    std::fprintf(stderr, "view: expected a JSON object in %s (max 1 MiB)\n",
                 options->config_path.c_str());
    return 2;
  }
  return serve(*options, *config);
}
