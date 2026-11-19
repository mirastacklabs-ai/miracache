// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

#include "util/error.h"
#include "util/expected.h"

// Public client types shared by the config loader, the C++ API and (later) the C ABI.
namespace miracache {

using NodeId = std::uint32_t;

// RDMA transport selection. `Auto` picks per NIC (RoCE v2 where available, else iWARP).
enum class FabricProtocol : std::uint8_t { Auto, Roce, Iwarp };

// Where scope secrets come from. Only `Static` (one pre-shared secret) exists today.
enum class ScopeProviderKind : std::uint8_t { Static };

// Per-key outcome reported in a Completion. The data path never raises: failure is a status.
enum class KeyStatus : std::uint8_t { Hit, Miss, Committed, Skipped, Refused, Aborted, Timeout };

// Opaque handle for a submitted job. Ids are unique per runtime and start at 1; 0 is invalid.
struct Ticket {
  std::uint64_t id = 0;
  friend constexpr bool operator==(Ticket a, Ticket b) noexcept { return a.id == b.id; }
};

const char* to_string(KeyStatus s) noexcept;
const char* to_string(FabricProtocol p) noexcept;
const char* to_string(ScopeProviderKind k) noexcept;

}  // namespace miracache
