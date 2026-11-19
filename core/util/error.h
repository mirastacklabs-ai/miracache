// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>

namespace miracache {

enum class ErrorCode : std::uint8_t {
  InvalidArgument,
  NotImplemented,
  NotFound,
  Busy,
  AccessDenied,
  Timeout,
  LinkDown,
  Aborted,
  Corrupt,
  Unsupported,
  ResourceExhausted,  // e.g. completion queue overflow
};

// Error carries a code plus a static, human-readable context string.
// The string must have static storage duration; no allocation on error paths.
struct Error {
  ErrorCode code;
  const char* context = "";

  friend constexpr bool operator==(const Error& a, const Error& b) noexcept {
    return a.code == b.code;
  }
};

const char* to_string(ErrorCode code) noexcept;

}  // namespace miracache
