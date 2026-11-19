// tier-vanity: brute-force an Ed25519 identity whose bech32m address starts
// and/or ends with chosen characters. A purely client-side grind - it touches
// no network and changes nothing on chain. Every attempt is a fresh, full-
// entropy keypair from the system CSPRNG (never a split-key scheme), so a found
// identity is as strong as any other; the only cost is the discarded keypairs.
// Expected work is ~32^(|prefix|+|suffix|) attempts, so 3-6 total characters are
// practical and 7+ wants real hardware. The grind runs on all cores by default;
// --threads overrides. The printed 32-byte seed reconstructs the identity.
//
// The suffix lands on the 6-char bech32m checksum tail, but that is fine: for a
// random keypair the whole address (data + checksum) is pseudo-random, so a tail
// match has the same 32^-len odds as a head match.
//
// Verify an address by its FULL id, never by a shared prefix: a vanity look-alike
// only controls the leading characters, so prefix-only checks invite poisoning.

#include <atomic>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "tier/core/address.hpp"
#include "tier/core/membership.hpp"
#include "tier/crypto/hash.hpp"
#include "tier/crypto/identity.hpp"

namespace {

constexpr char kCharset[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

bool in_charset(char c) { return std::strchr(kCharset, c) != nullptr; }

std::string to_hex(const std::uint8_t* p, std::size_t n) {
  static const char* const kHex = "0123456789abcdef";
  std::string out;
  out.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) {
    out += kHex[p[i] >> 4];
    out += kHex[p[i] & 0x0F];
  }
  return out;
}

void usage() {
  std::fprintf(
      stderr,
      "usage: tier-vanity [<prefix>] [--prefix S] [--suffix S]\n"
      "                   [--count N] [--threads N] [--max N]\n"
      "  <prefix>     desired leading characters (same as --prefix)\n"
      "  --prefix S   match addresses that start with S\n"
      "  --suffix S   match addresses that end with S\n"
      "               (both use the bech32 charset; it excludes 1 b i o)\n"
      "  --count N    stop after finding N matches (default: 1)\n"
      "  --threads N  worker threads (default: all cores)\n"
      "  --max N      give up after N total attempts (default: unlimited)\n");
}

// Lower-case in place and verify every character is in the bech32 charset.
bool normalize(std::string& s, const char* what) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  for (const char c : s) {
    if (!in_charset(c)) {
      std::fprintf(stderr,
                   "error: %s character '%c' is not bech32 "
                   "(the charset excludes 1 b i o)\n",
                   what, c);
      return false;
    }
  }
  return true;
}

struct Options {
  std::string prefix;
  std::string suffix;
  std::uint64_t count = 1;
  std::uint64_t max_tries = 0;  // 0 = unlimited
  unsigned threads = 0;         // 0 = resolve to hardware_concurrency
};

// Shared across workers.
std::atomic<std::uint64_t> g_tries{0};
std::atomic<std::uint64_t> g_found{0};
std::atomic<bool> g_stop{false};
std::mutex g_print_mutex;

void worker(const Options& opt) {
  while (!g_stop.load(std::memory_order_relaxed)) {
    if (opt.max_tries != 0 &&
        g_tries.load(std::memory_order_relaxed) >= opt.max_tries) {
      return;
    }
    g_tries.fetch_add(1, std::memory_order_relaxed);

    const tier::crypto::NodeIdentity identity =
        tier::crypto::NodeIdentity::generate();
    const tier::core::PeerId id = tier::crypto::sha256(identity.public_key());
    const std::string address = tier::core::address_from_id(id);

    if (!opt.prefix.empty() &&
        address.compare(0, opt.prefix.size(), opt.prefix) != 0) {
      continue;
    }
    if (!opt.suffix.empty() &&
        address.compare(address.size() - opt.suffix.size(), opt.suffix.size(),
                        opt.suffix) != 0) {
      continue;
    }

    // Claim a result slot; slots past --count mean another thread already
    // completed the run, so drop this match.
    const std::uint64_t slot = g_found.fetch_add(1) + 1;
    if (slot > opt.count) {
      g_found.fetch_sub(1);
      return;
    }

    {
      const std::lock_guard<std::mutex> lock(g_print_mutex);
      std::printf("found %llu/%llu after %llu attempts\n",
                  static_cast<unsigned long long>(slot),
                  static_cast<unsigned long long>(opt.count),
                  static_cast<unsigned long long>(
                      g_tries.load(std::memory_order_relaxed)));
      std::printf("seed:     %s\n",
                  to_hex(identity.seed().data(), identity.seed().size()).c_str());
      std::printf("id:       %s\n", to_hex(id.data(), id.size()).c_str());
      std::printf("address:  %s\n", address.c_str());
      std::printf("prefixed: %s\n\n",
                  tier::core::address_from_id_prefixed(id).c_str());
      std::fflush(stdout);
    }

    if (slot >= opt.count) {
      g_stop.store(true, std::memory_order_relaxed);
      return;
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  Options opt;
  for (int i = 1; i < argc; ++i) {
    const std::string a = argv[i];
    if (a == "--prefix" && i + 1 < argc) {
      opt.prefix = argv[++i];
    } else if (a == "--suffix" && i + 1 < argc) {
      opt.suffix = argv[++i];
    } else if (a == "--count" && i + 1 < argc) {
      opt.count = std::strtoull(argv[++i], nullptr, 10);
    } else if (a == "--threads" && i + 1 < argc) {
      opt.threads =
          static_cast<unsigned>(std::strtoul(argv[++i], nullptr, 10));
    } else if (a == "--max" && i + 1 < argc) {
      opt.max_tries = std::strtoull(argv[++i], nullptr, 10);
    } else if (!a.empty() && a[0] != '-' && opt.prefix.empty()) {
      opt.prefix = a;  // positional prefix, for backward compatibility
    } else {
      usage();
      return 2;
    }
  }

  if (opt.prefix.empty() && opt.suffix.empty()) {
    std::fprintf(stderr, "error: give at least a --prefix or a --suffix\n\n");
    usage();
    return 2;
  }
  if (opt.count == 0) {
    std::fprintf(stderr, "error: --count must be at least 1\n");
    return 2;
  }
  if (!normalize(opt.prefix, "prefix") || !normalize(opt.suffix, "suffix")) {
    return 2;
  }

  // The body is 58 characters; a prefix and suffix cannot overlap or overflow.
  if (opt.prefix.size() + opt.suffix.size() > 58) {
    std::fprintf(stderr, "error: prefix + suffix exceed the 58-char address\n");
    return 2;
  }

  if (opt.threads == 0) {
    opt.threads = std::thread::hardware_concurrency();
    if (opt.threads == 0) opt.threads = 1;
  }

  const double expected = std::pow(
      32.0, static_cast<double>(opt.prefix.size() + opt.suffix.size()));
  std::fprintf(stderr,
               "grinding prefix \"%s\" suffix \"%s\" x%llu on %u thread(s) "
               "(~%.0f attempts each)...\n",
               opt.prefix.c_str(), opt.suffix.c_str(),
               static_cast<unsigned long long>(opt.count), opt.threads,
               expected);

  std::vector<std::thread> pool;
  pool.reserve(opt.threads);
  for (unsigned i = 0; i < opt.threads; ++i) {
    pool.emplace_back(worker, std::cref(opt));
  }
  for (std::thread& t : pool) t.join();

  const std::uint64_t found = g_found.load();
  if (found >= opt.count) return 0;

  std::fprintf(stderr, "no match: found %llu/%llu in %llu attempts\n",
               static_cast<unsigned long long>(found),
               static_cast<unsigned long long>(opt.count),
               static_cast<unsigned long long>(g_tries.load()));
  return 1;
}
