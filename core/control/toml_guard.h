// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string_view>

namespace miracache::control {

// Screens TOML text before the real parse. toml++ 3.4.0 reaches TOML_UNREACHABLE (undefined
// behaviour) on non-ASCII bytes in places where it expects whitespace (found by the fuzzer).
// UTF-8 is legitimate inside strings and comments, so: if `text` has non-ASCII bytes, they are
// replaced by '@' (invalid TOML everywhere except inside a string or comment) and that ASCII-only
// copy must parse. If it does, every non-ASCII byte of the original sits in a string or comment.
bool toml_text_ok(std::string_view text);

}  // namespace miracache::control
