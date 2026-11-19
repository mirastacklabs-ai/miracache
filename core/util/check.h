// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string>

#include "util/log.h"

namespace miracache {

// Unconditional (release builds too) fatal misuse check. Core code is built with
// -fno-exceptions, so contract violations by the caller trap instead of throwing.
[[noreturn]] inline void check_failed(const char* expr, const char* file, int line) noexcept {
  log::write(log::Level::Fatal, "core", "check failed",
             {{"expr", expr}, {"file", file}, {"line", std::to_string(line)}});
  __builtin_trap();
}

}  // namespace miracache

#define MIRACACHE_CHECK(cond) \
  ((cond) ? static_cast<void>(0) : ::miracache::check_failed(#cond, __FILE__, __LINE__))
