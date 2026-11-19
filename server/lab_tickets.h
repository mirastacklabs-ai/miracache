// SPDX-License-Identifier: Apache-2.0
// Lab bring-up ticket file (design/03 R22): one "class rail hex-id" line per ticket.
// Tickets are bearer secrets: the file is created 0600.
#pragma once

#include <cstdint>
#include <string>

#include "server/server.h"
#include "util/expected.h"

namespace miracache::server {

// Issues `count` rail-0 tickets per class (control, fetch, ingest) for `identity` and replaces
// `path` atomically (0600 tmp file + rename). If any issue fails, nothing is written and the
// old file stays; the error says why (the caller logs it).
Status write_lab_tickets(Server& srv, const std::string& identity, const std::string& path, std::uint32_t count);

}  // namespace miracache::server
