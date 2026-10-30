#include "tier/net/endpoint.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <deque>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_wolfssl.h>

#include "tier/crypto/ed25519.hpp"
#include "tier/crypto/identity.hpp"

namespace tier::net {

using Byte = tier::crypto::Byte;

namespace {

constexpr std::size_t kCidLen = 16;
constexpr char kAlpn[] = "tier/0";  // wire ALPN identifier for v0
constexpr std::size_t kMaxUdpPayload = 1452;

// Application framing: a 4-byte big-endian length prefix followed by the
// payload. The cap bounds a single frame from an untrusted peer (this decoder
// is a prime fuzz target).
constexpr std::uint32_t kMaxFrameLen = 65536;

void append_frame(std::vector<Byte>& out, std::span<const Byte> payload) {
  const auto len = static_cast<std::uint32_t>(payload.size());
  out.push_back(static_cast<Byte>((len >> 24) & 0xFFU));
  out.push_back(static_cast<Byte>((len >> 16) & 0xFFU));
  out.push_back(static_cast<Byte>((len >> 8) & 0xFFU));
  out.push_back(static_cast<Byte>(len & 0xFFU));
  out.insert(out.end(), payload.begin(), payload.end());
}

// ngtcp2 timeline is monotonic nanoseconds.
ngtcp2_tstamp timestamp() noexcept {
  const auto now = std::chrono::steady_clock::now().time_since_epoch();
  return static_cast<ngtcp2_tstamp>(
      std::chrono::duration_cast<std::chrono::nanoseconds>(now).count());
}

PeerId extract_peer_id(WOLFSSL* ssl) {
  PeerId id{};
  WOLFSSL_X509* const cert = wolfSSL_get_peer_certificate(ssl);
  if (cert == nullptr) {
    return id;
  }
  std::array<unsigned char, 256> buf{};
  int sz = static_cast<int>(buf.size());
  // The SubjectPublicKeyInfo of an Ed25519 certificate ends with the 32-byte
  // raw public key, which is the peer's identity.
  if (wolfSSL_X509_get_pubkey_buffer(cert, buf.data(), &sz) == WOLFSSL_SUCCESS &&
      sz >= static_cast<int>(tier::crypto::kEd25519PublicKeySize)) {
    const auto offset = static_cast<std::size_t>(sz) - tier::crypto::kEd25519PublicKeySize;
    std::copy_n(buf.begin() + static_cast<std::ptrdiff_t>(offset),
                tier::crypto::kEd25519PublicKeySize, id.begin());
  }
  wolfSSL_X509_free(cert);
  return id;
}

bool sockaddr_equal(const sockaddr_storage& a, socklen_t alen,
                    const sockaddr_storage& b, socklen_t blen) noexcept {
  return alen == blen && std::memcmp(&a, &b, alen) == 0;
}

// Render a connection's remote address as a dialable "ip:port" string. The
// socket is dual-stack, so the stored address is always AF_INET6; an IPv4 peer
// arrives as a v4-mapped address and is printed in plain v4 form so the string
// round-trips back through fill_sockaddr unchanged.
std::string format_remote(const sockaddr_storage& ss) {
  const auto* const sin6 = reinterpret_cast<const sockaddr_in6*>(&ss);
  const unsigned port = ntohs(sin6->sin6_port);
  if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
    in_addr v4{};
    std::memcpy(&v4, sin6->sin6_addr.s6_addr + 12, sizeof(v4));
    std::array<char, INET_ADDRSTRLEN> buf{};
    if (inet_ntop(AF_INET, &v4, buf.data(), buf.size()) == nullptr) {
      return {};
    }
    return std::string(buf.data()) + ":" + std::to_string(port);
  }
  std::array<char, INET6_ADDRSTRLEN> buf{};
  if (inet_ntop(AF_INET6, &sin6->sin6_addr, buf.data(), buf.size()) == nullptr) {
    return {};
  }
  return "[" + std::string(buf.data()) + "]:" + std::to_string(port);
}

int accept_verify_cb(int /*preverify_ok*/, WOLFSSL_X509_STORE_CTX* /*ctx*/) {
  // Self-signed node certificates never chain to a CA. Identity is checked out
  // of band from the key in the certificate, so accept the chain here.
  return 1;
}

}  // namespace

struct Endpoint::Impl {
  struct Connection {
    Impl* ep = nullptr;
    ConnId id = 0;
    ngtcp2_conn* conn = nullptr;
    WOLFSSL* ssl = nullptr;
    ngtcp2_crypto_conn_ref conn_ref{};
    sockaddr_storage remote{};
    socklen_t remotelen = 0;
    bool server = false;
    bool handshake_done = false;
    bool closing = false;
    PeerId peer_id{};

    // One application stream per connection in v0. Outbound bytes live in a
    // queue of immovable chunks: ngtcp2 does not copy stream data when we hand
    // it over, it holds the pointer until the bytes are acknowledged (for
    // retransmission), so an in-flight chunk must never be moved or freed. Each
    // send appends a new chunk (never touching existing ones), and a chunk is
    // dropped only once fully acked. `base` is the chunk's absolute offset in
    // the stream.
    std::int64_t stream_id = -1;
    struct OutChunk {
      std::uint64_t base = 0;
      std::vector<Byte> data;
    };
    std::deque<OutChunk> out;          // queued/in-flight outbound chunks
    std::uint64_t appended = 0;        // absolute offset for the next chunk
    std::uint64_t write_cursor = 0;    // absolute offset handed to ngtcp2
    std::uint64_t total_acked = 0;     // absolute offset acknowledged
    std::vector<Byte> in_buf;          // inbound reassembly buffer

    Connection() = default;
    ~Connection() {
      if (conn != nullptr) {
        ngtcp2_conn_del(conn);
      }
      if (ssl != nullptr) {
        wolfSSL_free(ssl);
      }
    }
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    Connection(Connection&&) = delete;
    Connection& operator=(Connection&&) = delete;
  };

  Impl(const tier::crypto::NodeIdentity& identity, const std::string& ip,
       std::uint16_t port);
  ~Impl();
  Impl(const Impl&) = delete;
  Impl& operator=(const Impl&) = delete;

  void connect(const std::string& ip, std::uint16_t port);
  void poll(int timeout_ms);

  std::uint16_t local_port() const noexcept;

  // --- internals ---
  void setup_tls(Connection& c, bool server);
  ngtcp2_path make_path(Connection& c) noexcept;
  Connection* find_by_remote(const sockaddr_storage& ra, socklen_t ral) noexcept;
  void drain_reads();
  void route_packet(const std::uint8_t* data, std::size_t len,
                    const sockaddr_storage& ra, socklen_t ral);
  Connection* accept_server(const std::uint8_t* data, std::size_t len,
                            const sockaddr_storage& ra, socklen_t ral);
  void flush_writes();
  void handle_expiry();
  void arm_timer();
  void reap_closed();
  void note_handshake(Connection& c);
  void handle_message(Connection& c, std::span<const Byte> payload);

  // ngtcp2 callbacks that need the (private) Connection type live as static
  // members so they can name it; the rest are free functions below.
  static ngtcp2_conn* get_conn_cb(ngtcp2_crypto_conn_ref* ref);
  static int handshake_completed_cb(ngtcp2_conn* conn, void* user_data);
  static int recv_stream_data_cb(ngtcp2_conn* conn, std::uint32_t flags,
                                 std::int64_t stream_id, std::uint64_t offset,
                                 const std::uint8_t* data, std::size_t datalen,
                                 void* user_data, void* stream_user_data);
  static int acked_stream_data_offset_cb(ngtcp2_conn* conn,
                                         std::int64_t stream_id,
                                         std::uint64_t offset,
                                         std::uint64_t datalen, void* user_data,
                                         void* stream_user_data);
  static ngtcp2_callbacks make_callbacks(bool server);

  int udp_fd = -1;
  int epoll_fd = -1;
  int timer_fd = -1;
  sockaddr_storage local_addr{};
  socklen_t local_addrlen = 0;

  WOLFSSL_CTX* server_ctx = nullptr;
  WOLFSSL_CTX* client_ctx = nullptr;
  std::vector<Byte> cert_der;
  std::vector<Byte> key_der;

  Connection* find_by_id(ConnId id) noexcept;
  void send(ConnId id, std::span<const Byte> payload);
  void broadcast(std::span<const Byte> payload);
  std::vector<std::pair<ConnId, PeerId>> connections() const;
  std::optional<std::string> remote_address(ConnId id) const;

  std::vector<std::unique_ptr<Connection>> conns;
  std::function<void(ConnId, bool, const PeerId&)> on_handshake;
  std::function<void(ConnId, const PeerId&, std::span<const Byte>)> on_message;
  ConnId next_conn_id = 1;
  std::size_t completed = 0;
  std::string last_group;
};

namespace {

void rand_cb(std::uint8_t* dest, std::size_t destlen, const ngtcp2_rand_ctx*) {
  wolfSSL_RAND_bytes(dest, static_cast<int>(destlen));
}

int get_new_connection_id_cb(ngtcp2_conn*, ngtcp2_cid* cid,
                             ngtcp2_stateless_reset_token* token, std::size_t cidlen,
                             void*) {
  if (wolfSSL_RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  cid->datalen = cidlen;
  if (wolfSSL_RAND_bytes(reinterpret_cast<unsigned char*>(token),
                         NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
    return NGTCP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

// Grant enough stream/flow-control budget that a peer can open an application
// stream and send frames; defaults leave these at zero.
void set_stream_limits(ngtcp2_transport_params& params) noexcept {
  params.initial_max_streams_bidi = 8;
  params.initial_max_streams_uni = 8;
  params.initial_max_stream_data_bidi_local = 256 * 1024;
  params.initial_max_stream_data_bidi_remote = 256 * 1024;
  params.initial_max_stream_data_uni = 256 * 1024;
  params.initial_max_data = 1024 * 1024;
}

// Build an IPv6 sockaddr for the dual-stack socket. Accepts native IPv6, the
// wildcards "", "0.0.0.0" and "::" (bind any), and IPv4 literals (encoded as
// IPv4-mapped IPv6, ::ffff:a.b.c.d, so v4 peers are reachable too).
void fill_sockaddr(sockaddr_storage& ss, socklen_t& len, const std::string& ip,
                   std::uint16_t port) {
  std::memset(&ss, 0, sizeof(ss));
  auto* const sin6 = reinterpret_cast<sockaddr_in6*>(&ss);
  sin6->sin6_family = AF_INET6;
  sin6->sin6_port = htons(port);
  len = sizeof(sockaddr_in6);

  if (ip.empty() || ip == "0.0.0.0" || ip == "::") {
    sin6->sin6_addr = in6addr_any;
    return;
  }
  if (inet_pton(AF_INET6, ip.c_str(), &sin6->sin6_addr) == 1) {
    return;
  }
  in_addr v4{};
  if (inet_pton(AF_INET, ip.c_str(), &v4) == 1) {
    auto* const bytes = sin6->sin6_addr.s6_addr;
    bytes[10] = 0xFF;
    bytes[11] = 0xFF;
    std::memcpy(bytes + 12, &v4, sizeof(v4));
    return;
  }
  throw std::runtime_error("invalid IP address: " + ip);
}

WOLFSSL_CTX* make_ctx(bool server, const std::vector<Byte>& cert_der,
                      const std::vector<Byte>& key_der) {
  WOLFSSL_CTX* const ctx = wolfSSL_CTX_new(
      server ? wolfTLSv1_3_server_method() : wolfTLSv1_3_client_method());
  if (ctx == nullptr) {
    throw std::runtime_error("wolfSSL_CTX_new failed");
  }

  const int cfg_rc = server ? ngtcp2_crypto_wolfssl_configure_server_context(ctx)
                            : ngtcp2_crypto_wolfssl_configure_client_context(ctx);
  if (cfg_rc != 0) {
    wolfSSL_CTX_free(ctx);
    throw std::runtime_error("ngtcp2_crypto_wolfssl_configure_*_context failed");
  }

  // Post-quantum key exchange: hybrid X25519 + ML-KEM-768. Classical X25519 is
  // offered as a fallback so a peer without ML-KEM can still connect.
  if (wolfSSL_CTX_set1_groups_list(ctx, "X25519MLKEM768:X25519") != WOLFSSL_SUCCESS) {
    wolfSSL_CTX_free(ctx);
    throw std::runtime_error("wolfSSL_CTX_set1_groups_list failed");
  }

  if (wolfSSL_CTX_use_certificate_buffer(ctx, cert_der.data(),
                                         static_cast<long>(cert_der.size()),
                                         WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS ||
      wolfSSL_CTX_use_PrivateKey_buffer(ctx, key_der.data(),
                                        static_cast<long>(key_der.size()),
                                        WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
    wolfSSL_CTX_free(ctx);
    throw std::runtime_error("loading node certificate/key into wolfSSL failed");
  }

  if (server) {
    // Request the peer's certificate (mutual auth); the key in it is the
    // identity. The chain itself is self-signed, so accept it unconditionally.
    wolfSSL_CTX_set_verify(
        ctx, WOLFSSL_VERIFY_PEER | WOLFSSL_VERIFY_FAIL_IF_NO_PEER_CERT,
        accept_verify_cb);
  } else {
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_NONE, nullptr);
  }

  return ctx;
}

}  // namespace

ngtcp2_conn* Endpoint::Impl::get_conn_cb(ngtcp2_crypto_conn_ref* ref) {
  return static_cast<Connection*>(ref->user_data)->conn;
}

int Endpoint::Impl::handshake_completed_cb(ngtcp2_conn*, void* user_data) {
  auto* const c = static_cast<Connection*>(user_data);
  c->ep->note_handshake(*c);
  return 0;
}

int Endpoint::Impl::recv_stream_data_cb(ngtcp2_conn* conn, std::uint32_t,
                                        std::int64_t stream_id, std::uint64_t,
                                        const std::uint8_t* data,
                                        std::size_t datalen, void* user_data,
                                        void*) {
  auto* const c = static_cast<Connection*>(user_data);
  ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
  ngtcp2_conn_extend_max_offset(conn, datalen);

  // A server replies on the same client-initiated stream.
  if (c->server && c->stream_id < 0) {
    c->stream_id = stream_id;
  }

  c->in_buf.insert(c->in_buf.end(), data, data + datalen);

  // Extract whole length-prefixed frames.
  for (;;) {
    if (c->in_buf.size() < 4) {
      break;
    }
    const std::uint32_t len = (static_cast<std::uint32_t>(c->in_buf[0]) << 24) |
                              (static_cast<std::uint32_t>(c->in_buf[1]) << 16) |
                              (static_cast<std::uint32_t>(c->in_buf[2]) << 8) |
                              static_cast<std::uint32_t>(c->in_buf[3]);
    if (len > kMaxFrameLen) {
      c->closing = true;  // oversized frame from an untrusted peer
      return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    if (c->in_buf.size() < 4 + len) {
      break;
    }
    std::vector<Byte> payload(c->in_buf.begin() + 4,
                              c->in_buf.begin() + 4 + static_cast<std::ptrdiff_t>(len));
    c->in_buf.erase(c->in_buf.begin(),
                    c->in_buf.begin() + 4 + static_cast<std::ptrdiff_t>(len));
    c->ep->handle_message(*c, payload);
  }
  return 0;
}

ngtcp2_callbacks Endpoint::Impl::make_callbacks(bool server) {
  ngtcp2_callbacks cb{};
  if (server) {
    cb.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
  } else {
    cb.client_initial = ngtcp2_crypto_client_initial_cb;
    cb.recv_retry = ngtcp2_crypto_recv_retry_cb;
  }
  cb.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
  cb.encrypt = ngtcp2_crypto_encrypt_cb;
  cb.decrypt = ngtcp2_crypto_decrypt_cb;
  cb.hp_mask = ngtcp2_crypto_hp_mask_cb;
  cb.recv_stream_data = recv_stream_data_cb;
  cb.acked_stream_data_offset = acked_stream_data_offset_cb;
  cb.rand = rand_cb;
  cb.update_key = ngtcp2_crypto_update_key_cb;
  cb.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
  cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
  cb.version_negotiation = ngtcp2_crypto_version_negotiation_cb;
  cb.handshake_completed = handshake_completed_cb;
  cb.get_new_connection_id2 = get_new_connection_id_cb;
  cb.get_path_challenge_data2 = ngtcp2_crypto_get_path_challenge_data2_cb;
  return cb;
}

Endpoint::Impl::Impl(const tier::crypto::NodeIdentity& identity,
                     const std::string& ip, std::uint16_t port)
    : cert_der(identity.self_signed_certificate_der()),
      key_der(identity.private_key_pkcs8_der()) {
  // One AF_INET6 dual-stack socket: with IPV6_V6ONLY off it serves native IPv6
  // and IPv4 (as v4-mapped addresses) at once.
  udp_fd = ::socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
  if (udp_fd < 0) {
    throw std::runtime_error("socket() failed");
  }
  int v6only = 0;
  ::setsockopt(udp_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));

  sockaddr_storage bind_ss{};
  socklen_t bind_len = 0;
  fill_sockaddr(bind_ss, bind_len, ip, port);
  if (::bind(udp_fd, reinterpret_cast<sockaddr*>(&bind_ss), bind_len) != 0) {
    ::close(udp_fd);
    throw std::runtime_error("bind() failed");
  }

  local_addrlen = sizeof(local_addr);
  if (::getsockname(udp_fd, reinterpret_cast<sockaddr*>(&local_addr),
                    &local_addrlen) != 0) {
    ::close(udp_fd);
    throw std::runtime_error("getsockname() failed");
  }

  epoll_fd = ::epoll_create1(0);
  timer_fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (epoll_fd < 0 || timer_fd < 0) {
    if (timer_fd >= 0) ::close(timer_fd);
    if (epoll_fd >= 0) ::close(epoll_fd);
    ::close(udp_fd);
    throw std::runtime_error("epoll/timerfd creation failed");
  }

  epoll_event ev{};
  ev.events = EPOLLIN;
  ev.data.fd = udp_fd;
  ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, udp_fd, &ev);
  ev.data.fd = timer_fd;
  ::epoll_ctl(epoll_fd, EPOLL_CTL_ADD, timer_fd, &ev);

  server_ctx = make_ctx(true, cert_der, key_der);
  client_ctx = make_ctx(false, cert_der, key_der);
}

Endpoint::Impl::~Impl() {
  conns.clear();  // delete ngtcp2 conns / wolfSSL sessions before contexts
  if (client_ctx != nullptr) wolfSSL_CTX_free(client_ctx);
  if (server_ctx != nullptr) wolfSSL_CTX_free(server_ctx);
  if (timer_fd >= 0) ::close(timer_fd);
  if (epoll_fd >= 0) ::close(epoll_fd);
  if (udp_fd >= 0) ::close(udp_fd);
}

std::uint16_t Endpoint::Impl::local_port() const noexcept {
  const auto* const sin6 = reinterpret_cast<const sockaddr_in6*>(&local_addr);
  return ntohs(sin6->sin6_port);
}

ngtcp2_path Endpoint::Impl::make_path(Connection& c) noexcept {
  ngtcp2_path path{};
  path.local.addr = reinterpret_cast<sockaddr*>(&local_addr);
  path.local.addrlen = local_addrlen;
  path.remote.addr = reinterpret_cast<sockaddr*>(&c.remote);
  path.remote.addrlen = c.remotelen;
  return path;
}

void Endpoint::Impl::setup_tls(Connection& c, bool server) {
  c.ssl = wolfSSL_new(server ? server_ctx : client_ctx);
  if (c.ssl == nullptr) {
    throw std::runtime_error("wolfSSL_new failed");
  }
  wolfSSL_set_app_data(c.ssl, &c.conn_ref);
  if (server) {
    wolfSSL_set_accept_state(c.ssl);
  } else {
    wolfSSL_set_connect_state(c.ssl);
  }
  wolfSSL_UseALPN(c.ssl, const_cast<char*>(kAlpn),
                  static_cast<unsigned int>(std::strlen(kAlpn)),
                  WOLFSSL_ALPN_FAILED_ON_MISMATCH);
  wolfSSL_set_quic_transport_version(c.ssl, 0x39);  // QUIC v1 transport params
  ngtcp2_conn_set_tls_native_handle(c.conn, c.ssl);
}

void Endpoint::Impl::connect(const std::string& ip, std::uint16_t port) {
  auto c = std::make_unique<Connection>();
  c->ep = this;
  c->id = next_conn_id++;
  c->server = false;
  fill_sockaddr(c->remote, c->remotelen, ip, port);

  ngtcp2_cid dcid{};
  ngtcp2_cid scid{};
  dcid.datalen = kCidLen;
  scid.datalen = kCidLen;
  wolfSSL_RAND_bytes(dcid.data, static_cast<int>(kCidLen));
  wolfSSL_RAND_bytes(scid.data, static_cast<int>(kCidLen));

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp();

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  set_stream_limits(params);

  ngtcp2_callbacks cb = make_callbacks(false);
  c->conn_ref.get_conn = get_conn_cb;
  c->conn_ref.user_data = c.get();

  ngtcp2_path path = make_path(*c);
  const int rv = ngtcp2_conn_client_new(&c->conn, &dcid, &scid, &path,
                                        NGTCP2_PROTO_VER_V1, &cb, &settings,
                                        &params, nullptr, c.get());
  if (rv != 0) {
    throw std::runtime_error(std::string("ngtcp2_conn_client_new: ") +
                             ngtcp2_strerror(rv));
  }

  setup_tls(*c, false);
  conns.push_back(std::move(c));
}

Endpoint::Impl::Connection* Endpoint::Impl::find_by_remote(
    const sockaddr_storage& ra, socklen_t ral) noexcept {
  for (auto& c : conns) {
    if (!c->closing && sockaddr_equal(c->remote, c->remotelen, ra, ral)) {
      return c.get();
    }
  }
  return nullptr;
}

Endpoint::Impl::Connection* Endpoint::Impl::accept_server(
    const std::uint8_t* data, std::size_t len, const sockaddr_storage& ra,
    socklen_t ral) {
  ngtcp2_version_cid vcid{};
  if (ngtcp2_pkt_decode_version_cid(&vcid, data, len, kCidLen) != 0) {
    return nullptr;  // not a long-header packet we can start a connection from
  }
  ngtcp2_pkt_hd hd{};
  if (ngtcp2_accept(&hd, data, len) != 0) {
    return nullptr;  // not an acceptable Initial
  }

  auto c = std::make_unique<Connection>();
  c->ep = this;
  c->id = next_conn_id++;
  c->server = true;
  std::memcpy(&c->remote, &ra, ral);
  c->remotelen = ral;

  ngtcp2_cid scid{};
  scid.datalen = kCidLen;
  wolfSSL_RAND_bytes(scid.data, static_cast<int>(kCidLen));

  ngtcp2_cid dcid{};
  ngtcp2_cid_init(&dcid, vcid.scid, vcid.scidlen);

  ngtcp2_settings settings;
  ngtcp2_settings_default(&settings);
  settings.initial_ts = timestamp();

  ngtcp2_transport_params params;
  ngtcp2_transport_params_default(&params);
  set_stream_limits(params);
  ngtcp2_cid_init(&params.original_dcid, vcid.dcid, vcid.dcidlen);
  params.original_dcid_present = 1;

  ngtcp2_callbacks cb = make_callbacks(true);
  c->conn_ref.get_conn = get_conn_cb;
  c->conn_ref.user_data = c.get();

  ngtcp2_path path = make_path(*c);
  if (ngtcp2_conn_server_new(&c->conn, &dcid, &scid, &path, vcid.version, &cb,
                             &settings, &params, nullptr, c.get()) != 0) {
    return nullptr;
  }

  setup_tls(*c, true);
  Connection* const raw = c.get();
  conns.push_back(std::move(c));
  return raw;
}

void Endpoint::Impl::route_packet(const std::uint8_t* data, std::size_t len,
                                  const sockaddr_storage& ra, socklen_t ral) {
  Connection* c = find_by_remote(ra, ral);
  if (c == nullptr) {
    c = accept_server(data, len, ra, ral);
    if (c == nullptr) {
      return;
    }
  }

  ngtcp2_path path = make_path(*c);
  const int rv =
      ngtcp2_conn_read_pkt(c->conn, &path, nullptr, data, len, timestamp());
  if (rv != 0) {
    c->closing = true;
  }
}

void Endpoint::Impl::drain_reads() {
  for (;;) {
    sockaddr_storage ra{};
    socklen_t ral = sizeof(ra);
    std::array<std::uint8_t, 2048> buf{};
    const ssize_t nread = ::recvfrom(udp_fd, buf.data(), buf.size(), 0,
                                     reinterpret_cast<sockaddr*>(&ra), &ral);
    if (nread < 0) {
      break;  // EAGAIN / EWOULDBLOCK: socket drained
    }
    route_packet(buf.data(), static_cast<std::size_t>(nread), ra, ral);
  }
}

void Endpoint::Impl::flush_writes() {
  for (auto& c : conns) {
    if (c->closing) {
      continue;
    }
    // Drop chunks ngtcp2 has fully acknowledged; it no longer references them.
    while (!c->out.empty() &&
           c->out.front().base + c->out.front().data.size() <= c->total_acked) {
      c->out.pop_front();
    }
    for (;;) {
      ngtcp2_path_storage ps;
      ngtcp2_path_storage_zero(&ps);
      std::array<std::uint8_t, kMaxUdpPayload> buf{};

      // Feed the first chunk that still has bytes past the write cursor. The
      // pointer stays valid until the chunk is acked and popped above.
      ngtcp2_vec datav{};
      std::int64_t stream_id = -1;
      std::size_t veccnt = 0;
      if (c->stream_id >= 0) {
        for (auto& ch : c->out) {
          const std::uint64_t ch_end = ch.base + ch.data.size();
          if (c->write_cursor < ch_end) {
            const auto within = static_cast<std::size_t>(c->write_cursor - ch.base);
            datav.base = ch.data.data() + within;
            datav.len = ch.data.size() - within;
            stream_id = c->stream_id;
            veccnt = 1;
            break;
          }
        }
      }

      ngtcp2_ssize ndatalen = 0;
      const ngtcp2_ssize nwrite = ngtcp2_conn_writev_stream(
          c->conn, &ps.path, nullptr, buf.data(), buf.size(), &ndatalen,
          NGTCP2_WRITE_STREAM_FLAG_NONE, stream_id,
          veccnt > 0 ? &datav : nullptr, veccnt, timestamp());
      if (nwrite < 0) {
        if (nwrite != NGTCP2_ERR_STREAM_DATA_BLOCKED) {
          c->closing = true;
        }
        break;
      }
      if (ndatalen > 0) {
        c->write_cursor += static_cast<std::uint64_t>(ndatalen);
      }
      if (nwrite == 0) {
        break;
      }
      ngtcp2_conn_update_pkt_tx_time(c->conn, timestamp());
      ::sendto(udp_fd, buf.data(), static_cast<std::size_t>(nwrite), 0,
               reinterpret_cast<sockaddr*>(&c->remote), c->remotelen);
    }
  }
}

void Endpoint::Impl::handle_expiry() {
  const ngtcp2_tstamp now = timestamp();
  for (auto& c : conns) {
    if (c->closing) {
      continue;
    }
    if (ngtcp2_conn_handle_expiry(c->conn, now) != 0) {
      c->closing = true;
    }
  }
}

void Endpoint::Impl::arm_timer() {
  ngtcp2_tstamp earliest = UINT64_MAX;
  for (auto& c : conns) {
    if (c->closing) {
      continue;
    }
    earliest = std::min(earliest, ngtcp2_conn_get_expiry2(c->conn));
  }

  itimerspec its{};
  if (earliest != UINT64_MAX) {
    const ngtcp2_tstamp now = timestamp();
    const ngtcp2_tstamp delta = earliest <= now ? 1 : earliest - now;
    its.it_value.tv_sec = static_cast<time_t>(delta / 1000000000ULL);
    its.it_value.tv_nsec = static_cast<long>(delta % 1000000000ULL);
  }
  ::timerfd_settime(timer_fd, 0, &its, nullptr);  // all-zero disarms
}

void Endpoint::Impl::reap_closed() {
  std::erase_if(conns, [](const std::unique_ptr<Connection>& c) {
    return c->closing;
  });
}

void Endpoint::Impl::note_handshake(Connection& c) {
  if (c.handshake_done) {
    return;
  }
  c.handshake_done = true;
  c.peer_id = extract_peer_id(c.ssl);
  const char* const group = wolfSSL_get_curve_name(c.ssl);
  last_group = group != nullptr ? group : "";
  ++completed;

  if (on_handshake) {
    on_handshake(c.id, !c.server, c.peer_id);
  }
}

void Endpoint::Impl::handle_message(Connection& c, std::span<const Byte> payload) {
  if (on_message) {
    on_message(c.id, c.peer_id, payload);
  }
}

int Endpoint::Impl::acked_stream_data_offset_cb(ngtcp2_conn*, std::int64_t,
                                                std::uint64_t offset,
                                                std::uint64_t datalen,
                                                void* user_data, void*) {
  auto* const c = static_cast<Connection*>(user_data);
  const std::uint64_t acked_to = offset + datalen;
  if (acked_to > c->total_acked) {
    c->total_acked = acked_to;
  }
  return 0;
}

Endpoint::Impl::Connection* Endpoint::Impl::find_by_id(ConnId id) noexcept {
  for (auto& c : conns) {
    if (c->id == id && !c->closing) {
      return c.get();
    }
  }
  return nullptr;
}

void Endpoint::Impl::send(ConnId id, std::span<const Byte> payload) {
  Connection* const c = find_by_id(id);
  if (c == nullptr) {
    return;
  }
  // Open our own bidi stream on first send if none is associated yet (the
  // initiator case; a responder already learned the stream from the peer).
  if (c->stream_id < 0) {
    std::int64_t stream_id = -1;
    if (ngtcp2_conn_open_bidi_stream(c->conn, &stream_id, nullptr) != 0) {
      return;
    }
    c->stream_id = stream_id;
  }
  // Queue the framed payload as a fresh chunk. Appending never touches chunks
  // already handed to ngtcp2, so their bytes stay put until acknowledged.
  Connection::OutChunk chunk;
  chunk.base = c->appended;
  append_frame(chunk.data, payload);
  c->appended += chunk.data.size();
  c->out.push_back(std::move(chunk));
}

void Endpoint::Impl::broadcast(std::span<const Byte> payload) {
  for (auto& c : conns) {
    if (!c->closing && c->handshake_done) {
      send(c->id, payload);
    }
  }
}

std::vector<std::pair<ConnId, PeerId>> Endpoint::Impl::connections() const {
  std::vector<std::pair<ConnId, PeerId>> out;
  for (const auto& c : conns) {
    if (!c->closing && c->handshake_done) {
      out.emplace_back(c->id, c->peer_id);
    }
  }
  return out;
}

std::optional<std::string> Endpoint::Impl::remote_address(ConnId id) const {
  for (const auto& c : conns) {
    if (c->id == id && !c->closing) {
      return format_remote(c->remote);
    }
  }
  return std::nullopt;
}

void Endpoint::Impl::poll(int timeout_ms) {
  std::array<epoll_event, 2> events{};
  const int n = ::epoll_wait(epoll_fd, events.data(),
                             static_cast<int>(events.size()), timeout_ms);
  bool timer_fired = false;
  for (int i = 0; i < n; ++i) {
    if (events[static_cast<std::size_t>(i)].data.fd == timer_fd) {
      std::uint64_t expirations = 0;
      const ssize_t r = ::read(timer_fd, &expirations, sizeof(expirations));
      static_cast<void>(r);
      timer_fired = true;
    }
  }

  drain_reads();
  if (timer_fired) {
    handle_expiry();
  }
  flush_writes();
  reap_closed();
  arm_timer();
}

Endpoint::Endpoint(const tier::crypto::NodeIdentity& identity,
                   const std::string& ip, std::uint16_t port)
    : impl_(std::make_unique<Impl>(identity, ip, port)) {}

Endpoint::~Endpoint() = default;

std::uint16_t Endpoint::local_port() const noexcept { return impl_->local_port(); }

void Endpoint::connect(const std::string& ip, std::uint16_t port) {
  impl_->connect(ip, port);
}

void Endpoint::poll(int timeout_ms) { impl_->poll(timeout_ms); }

std::size_t Endpoint::completed_handshakes() const noexcept {
  return impl_->completed;
}

std::vector<std::pair<ConnId, PeerId>> Endpoint::connections() const {
  return impl_->connections();
}

std::optional<std::string> Endpoint::remote_address(ConnId conn) const {
  return impl_->remote_address(conn);
}

std::string Endpoint::last_negotiated_group() const { return impl_->last_group; }

void Endpoint::on_handshake(
    std::function<void(ConnId, bool, const PeerId&)> callback) {
  impl_->on_handshake = std::move(callback);
}

void Endpoint::on_message(
    std::function<void(ConnId, const PeerId&, std::span<const tier::crypto::Byte>)>
        callback) {
  impl_->on_message = std::move(callback);
}

void Endpoint::send(ConnId conn, std::span<const tier::crypto::Byte> payload) {
  impl_->send(conn, payload);
}

void Endpoint::broadcast(std::span<const tier::crypto::Byte> payload) {
  impl_->broadcast(payload);
}

}  // namespace tier::net
