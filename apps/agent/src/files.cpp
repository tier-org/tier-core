#include "files.hpp"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>

#include "tier/crypto/identity.hpp"

namespace tier::agent {

FileResult create_private_file(const std::string& path, std::string_view data) {
  std::string temporary = path + ".tmp.XXXXXX";
  const int fd = ::mkostemp(temporary.data(), O_CLOEXEC);
  if (fd < 0) return FileResult::error;
  bool ok = ::fchmod(fd, 0600) == 0;
  while (ok && !data.empty()) {
    const ssize_t n = ::write(fd, data.data(), data.size());
    if (n < 0 && errno == EINTR) continue;
    ok = n > 0;
    if (ok) data.remove_prefix(static_cast<std::size_t>(n));
  }
  if (ok) ok = ::fsync(fd) == 0;
  if (::close(fd) != 0) ok = false;
  FileResult result = FileResult::error;
  if (ok) {
    if (::link(temporary.c_str(), path.c_str()) == 0) {
      result = FileResult::ok;
    } else if (errno == EEXIST) {
      result = FileResult::exists;
    }
  }
  ::unlink(temporary.c_str());
  return result;
}

FileResult read_seed_file(const std::string& path, Seed& seed) {
  const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0) return errno == ENOENT ? FileResult::absent : FileResult::error;
  struct stat info {};
  const bool regular = ::fstat(fd, &info) == 0 && S_ISREG(info.st_mode);
  std::array<std::uint8_t, Seed{}.size() + 1> bytes{};
  std::size_t size = 0;
  while (regular && size < bytes.size()) {
    const ssize_t n = ::read(fd, bytes.data() + size, bytes.size() - size);
    if (n < 0 && errno == EINTR) continue;
    if (n < 0) {
      ::close(fd);
      return FileResult::error;
    }
    if (n == 0) break;
    size += static_cast<std::size_t>(n);
  }
  ::close(fd);
  if (size != seed.size()) return FileResult::error;
  std::copy_n(bytes.begin(), seed.size(), seed.begin());
  return FileResult::ok;
}

bool load_or_create_seed(const std::string& path, Seed& seed) {
  auto result = read_seed_file(path, seed);
  if (result == FileResult::absent) {
    seed = tier::crypto::NodeIdentity::generate().seed();
    const std::string_view data(reinterpret_cast<const char*>(seed.data()), seed.size());
    result = create_private_file(path, data);
    if (result == FileResult::exists) result = read_seed_file(path, seed);
  }
  if (result == FileResult::ok) return true;
  std::fprintf(stderr, "error: cannot read or create a 32-byte seed at %s\n", path.c_str());
  return false;
}

}  // namespace tier::agent
