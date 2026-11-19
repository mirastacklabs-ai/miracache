// SPDX-License-Identifier: Apache-2.0
#include "server/lab_tickets.h"

#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <vector>

namespace miracache::server {

Status write_lab_tickets(Server& srv, const std::string& identity, const std::string& path, std::uint32_t count) {
  static const char* names[] = {"control", "fetch", "ingest"};
  std::vector<std::vector<proto::Ticket>> all;
  for (std::uint8_t cls = 0; cls < 3; ++cls) {
    auto t = srv.issue_ticket(identity, static_cast<fabric::EpClass>(cls), 0, count);
    if (!t) return t.error();  // keep the old file: an incomplete one would lock clients out of a class
    all.push_back(std::move(*t));
  }
  const std::string tmp = path + ".tmp";
  (void)::unlink(tmp.c_str());  // O_EXCL below: never write through a pre-planted file or link
  const int fd = ::open(tmp.c_str(), O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
  if (fd < 0) return Error{ErrorCode::Aborted, "lab: cannot create the ticket tmp file"};
  std::FILE* f = ::fdopen(fd, "w");
  if (!f) {
    ::close(fd);
    (void)::unlink(tmp.c_str());
    return Error{ErrorCode::Aborted, "lab: fdopen failed"};
  }
  for (std::uint8_t cls = 0; cls < 3; ++cls)
    for (const auto& tk : all[cls]) {
      std::fprintf(f, "%s 0 ", names[cls]);
      for (auto b : tk.id) std::fprintf(f, "%02x", b);
      std::fputc('\n', f);
    }
  const bool ok = std::fflush(f) == 0 && !std::ferror(f);
  if (std::fclose(f) != 0 || !ok || std::rename(tmp.c_str(), path.c_str()) != 0) {
    (void)::unlink(tmp.c_str());
    return Error{ErrorCode::Aborted, "lab: cannot write the ticket file"};
  }
  return {};
}

}  // namespace miracache::server
