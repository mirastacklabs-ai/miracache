// SPDX-License-Identifier: Apache-2.0
#include "control/toml_guard.h"

#include <string>

#include <toml++/toml.hpp>

namespace miracache::control {

bool toml_text_ok(std::string_view text) {
  bool ascii = true;
  for (const char c : text) ascii = ascii && static_cast<unsigned char>(c) < 0x80;
  if (ascii) return true;
  std::string copy(text);
  for (char& c : copy) {
    if (static_cast<unsigned char>(c) >= 0x80) c = '@';
  }
  return static_cast<bool>(toml::parse(copy));
}

}  // namespace miracache::control
