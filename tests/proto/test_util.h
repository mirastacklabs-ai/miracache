// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <vector>

namespace miracache::testutil {

using Bytes = std::vector<std::byte>;

inline Bytes bytes(std::initializer_list<int> v) {
  Bytes b;
  for (int x : v) b.push_back(static_cast<std::byte>(x));
  return b;
}
inline Bytes zeros(std::size_t n) { return Bytes(n, std::byte{0}); }
// n bytes: start, start+1, ... (wrapping)
inline Bytes ramp(std::size_t n, int start) {
  Bytes b;
  for (std::size_t i = 0; i < n; ++i) b.push_back(static_cast<std::byte>((start + i) & 0xff));
  return b;
}
inline Bytes cat(std::initializer_list<Bytes> parts) {
  Bytes b;
  for (const auto& p : parts) b.insert(b.end(), p.begin(), p.end());
  return b;
}

}  // namespace miracache::testutil

namespace miracache::testutil {

// Hand-placed 32 B frame header for the shared test header values:
// credits 3, request_id 0x1122334455667788, epoch 0xA1B2C3D4, bundle_gen_lo 0xBEEF.
inline Bytes hand_header(int type, int flags, int body_len) {
  return cat({bytes({0x4D, 0x41, 0x52, 0x4D}),            // 0  magic "MARM"
              bytes({0, 0}),                              // 4  ver_major, ver_minor
              bytes({type & 0xff, type >> 8}),            // 6  type
              bytes({flags & 0xff, flags >> 8}),          // 8  flags
              bytes({3, 0}),                              // 10 credits
              bytes({body_len & 0xff, body_len >> 8, 0, 0}),  // 12 body_len
              bytes({0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11}),  // 16 request_id
              bytes({0xD4, 0xC3, 0xB2, 0xA1}),            // 24 epoch
              bytes({0xEF, 0xBE, 0, 0})});                // 28 bundle_gen_lo
}

}  // namespace miracache::testutil
