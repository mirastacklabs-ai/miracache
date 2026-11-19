// SPDX-License-Identifier: Apache-2.0
#include "util/error.h"

namespace miracache {

const char* to_string(ErrorCode code) noexcept {
  switch (code) {
    case ErrorCode::InvalidArgument: return "InvalidArgument";
    case ErrorCode::NotImplemented: return "NotImplemented";
    case ErrorCode::NotFound: return "NotFound";
    case ErrorCode::Busy: return "Busy";
    case ErrorCode::AccessDenied: return "AccessDenied";
    case ErrorCode::Timeout: return "Timeout";
    case ErrorCode::LinkDown: return "LinkDown";
    case ErrorCode::Aborted: return "Aborted";
    case ErrorCode::Corrupt: return "Corrupt";
    case ErrorCode::Unsupported: return "Unsupported";
    case ErrorCode::ResourceExhausted: return "ResourceExhausted";
  }
  return "Unknown";
}

}  // namespace miracache
