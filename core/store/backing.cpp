// SPDX-License-Identifier: Apache-2.0
#include "store/backing.h"

#include <cerrno>
#include <cstdio>
#include <string>
#include <vector>

#include <fcntl.h>
#include <sys/file.h>
#include <sys/mman.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/vfs.h>
#endif
#include <unistd.h>

namespace miracache::store {
namespace {

struct Mapping {
  std::byte* base = nullptr;
  std::size_t len = 0;
  int fd = -1;
};

class MapSet {
 public:
  MapSet() = default;
  MapSet(const MapSet&) = delete;
  MapSet& operator=(const MapSet&) = delete;
  ~MapSet() {
    for (auto& m : maps_) {
      if (m.base) ::munmap(m.base, m.len);
      if (m.fd >= 0) ::close(m.fd);  // drops the flock
    }
  }
  Mapping* find(std::uint32_t seg) { return seg < maps_.size() && maps_[seg].base ? &maps_[seg] : nullptr; }
  Mapping& slot(std::uint32_t seg) {
    if (seg >= maps_.size()) maps_.resize(seg + 1);
    return maps_[seg];
  }

 private:
  std::vector<Mapping> maps_;
};

class AnonBacking final : public Backing {
 public:
  Expected<std::span<std::byte>> map(std::uint32_t seg, std::size_t len) override {
    if (auto* m = maps_.find(seg)) {
      if (m->len != len) return Error{ErrorCode::InvalidArgument, "backing: remap with different length"};
      return std::span<std::byte>(m->base, m->len);
    }
    void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
    if (p == MAP_FAILED) return Error{ErrorCode::ResourceExhausted, "backing: anon mmap"};
    auto& m = maps_.slot(seg);
    m.base = static_cast<std::byte*>(p);
    m.len = len;
    return std::span<std::byte>(m.base, m.len);
  }
  Status sync(std::uint32_t, std::size_t, std::size_t) override { return {}; }
  BackingKind kind() const noexcept override { return BackingKind::Anon; }

 private:
  MapSet maps_;
};

[[maybe_unused]] constexpr long kHugetlbfsMagic = 0x958458f6;

class FileBacking final : public Backing {
 public:
  FileBacking(BackingKind kind, std::string dir, bool require_1g)
      : kind_(kind), dir_(std::move(dir)), require_1g_(require_1g) {}

  Expected<std::span<std::byte>> map(std::uint32_t seg, std::size_t len) override {
    if (auto* m = maps_.find(seg)) {
      if (m->len != len) return Error{ErrorCode::InvalidArgument, "backing: remap with different length"};
      return std::span<std::byte>(m->base, m->len);
    }
#ifndef __linux__
    if (kind_ == BackingKind::Hugetlbfs) return Error{ErrorCode::Unsupported, "backing: hugetlbfs is Linux only"};
#endif
    char name[32];
    std::snprintf(name, sizeof name, "/segment-%04u", seg);
    const std::string path = dir_ + name;
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd < 0) return Error{ErrorCode::NotFound, "backing: open"};
    auto fail = [&](Error e) -> Expected<std::span<std::byte>> { ::close(fd); return e; };
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0)
      return fail(Error{errno == EWOULDBLOCK ? ErrorCode::Busy : ErrorCode::AccessDenied, "backing: flock"});
#ifdef __linux__
    if (kind_ == BackingKind::Hugetlbfs) {
      struct statfs fs {};
      if (::fstatfs(fd, &fs) != 0) return fail(Error{ErrorCode::AccessDenied, "backing: fstatfs"});
      if (static_cast<long>(fs.f_type) != kHugetlbfsMagic)
        return fail(Error{ErrorCode::InvalidArgument, "backing: dir is not hugetlbfs"});
      const auto psz = static_cast<std::uint64_t>(fs.f_bsize);
      if (require_1g_ && psz != (std::uint64_t{1} << 30))
        return fail(Error{ErrorCode::InvalidArgument, "backing: hugetlbfs page size is not 1 GiB"});
      if (len % psz != 0) return fail(Error{ErrorCode::InvalidArgument, "backing: segment not page multiple"});
    }
#endif
    struct stat st {};
    if (::fstat(fd, &st) != 0) return fail(Error{ErrorCode::AccessDenied, "backing: fstat"});
    if (static_cast<std::uint64_t>(st.st_size) != len) {
      if (st.st_size != 0) return fail(Error{ErrorCode::InvalidArgument, "backing: existing file has a different size"});
      if (::ftruncate(fd, static_cast<off_t>(len)) != 0)
        return fail(Error{ErrorCode::ResourceExhausted, "backing: ftruncate"});
    }
    void* p = ::mmap(nullptr, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (p == MAP_FAILED) return fail(Error{ErrorCode::ResourceExhausted, "backing: mmap"});
#if defined(__linux__) && defined(MADV_POPULATE_WRITE)
    if (kind_ == BackingKind::Hugetlbfs) (void)::madvise(p, len, MADV_POPULATE_WRITE);
#endif
    auto& m = maps_.slot(seg);
    m.base = static_cast<std::byte*>(p);
    m.len = len;
    m.fd = fd;
    return std::span<std::byte>(m.base, m.len);
  }

  Status sync(std::uint32_t seg, std::size_t off, std::size_t len) override {
    auto* m = maps_.find(seg);
    if (!m || off > m->len || len > m->len - off) return Error{ErrorCode::InvalidArgument, "backing: sync range"};
    constexpr std::size_t kPage = 4096;
    const std::size_t a = off & ~(kPage - 1);
    if (::msync(m->base + a, off + len - a, MS_SYNC) != 0) return Error{ErrorCode::Aborted, "backing: msync"};
    return {};
  }
  BackingKind kind() const noexcept override { return kind_; }

 private:
  BackingKind kind_;
  std::string dir_;
  bool require_1g_;
  MapSet maps_;
};

}  // namespace

std::unique_ptr<Backing> make_backing(const StoreConfig& cfg) {
  if (cfg.backing == BackingKind::Anon) return std::make_unique<AnonBacking>();
  return std::make_unique<FileBacking>(cfg.backing, cfg.dir, cfg.require_1g);
}

}  // namespace miracache::store
