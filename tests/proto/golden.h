// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <gtest/gtest.h>

#include <cctype>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

namespace miracache::golden {

// Reads proto/golden/<name>: hex digits, whitespace ignored.
inline std::vector<std::byte> load(const std::string& name) {
  std::ifstream f(std::string(MIRACACHE_GOLDEN_DIR) + "/" + name);
  std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  std::vector<std::byte> out;
  int hi = -1;
  for (char c : text) {
    if (std::isspace(static_cast<unsigned char>(c))) continue;
    const int v = std::isdigit(static_cast<unsigned char>(c)) ? c - '0' : std::tolower(c) - 'a' + 10;
    if (hi < 0) hi = v;
    else { out.push_back(static_cast<std::byte>(hi * 16 + v)); hi = -1; }
  }
  return out;
}

// Lower-case hex, 16 bytes per line, trailing newline: the exact .hex file format.
inline std::string hex(std::span<const std::byte> b) {
  static const char* d = "0123456789abcdef";
  std::string s;
  for (std::size_t i = 0; i < b.size(); ++i) {
    s += d[static_cast<unsigned>(b[i]) >> 4];
    s += d[static_cast<unsigned>(b[i]) & 15];
    s += (i % 16 == 15 || i + 1 == b.size()) ? '\n' : ' ';
  }
  return s;
}

// Compares `actual` with the golden file. On mismatch the failure message carries
// "GOLDEN <name>" followed by the hex of `actual`, to paste into proto/golden/<name>
// AFTER a hand-written byte-placement test has confirmed the bytes are right.
inline ::testing::AssertionResult matches(const std::string& name, std::span<const std::byte> actual) {
  const auto g = load(name);
  if (g.size() == actual.size() && std::equal(g.begin(), g.end(), actual.begin())) {
    return ::testing::AssertionSuccess();
  }
  return ::testing::AssertionFailure() << "GOLDEN " << name << " (" << actual.size() << " B)\n" << hex(actual) << "ENDGOLDEN";
}

}  // namespace miracache::golden
