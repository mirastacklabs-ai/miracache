// SPDX-License-Identifier: Apache-2.0
// Frame header codec (32 B) and TLV tail walker. Versioning rules: plan section 3.
#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "proto/wire.h"

namespace miracache::proto {

struct FrameHeader {
  std::uint8_t ver_major = kVerMajor;
  std::uint8_t ver_minor = kVerMinor;
  std::uint16_t type = 0;
  std::uint16_t flags = 0;
  std::uint16_t credits = 0;  // delta of newly posted receives (D10)
  std::uint32_t body_len = 0;
  std::uint64_t request_id = 0;
  std::uint32_t epoch = 0;
  std::uint32_t bundle_gen_lo = 0;
};

struct Frame {
  FrameHeader h;
  std::span<const std::byte> body;  // borrows the input
};

// Parses one whole received frame (header + body; in.size() is the received length).
//   bad magic, body_len > 8160, body_len != in.size() - 32  -> Corrupt (close_qp)
//   ver_major != 0                                          -> Unsupported (close_qp)
//   unknown flag bit                                        -> Malformed
// ver_minor is accepted whatever its value (D12); the opcode is NOT checked here (see
// check_opcode). Frames shorter than 32 B are Corrupt.
WireResult<Frame> decode_frame(std::span<const std::byte> in);

// Unknown opcode -> Unsupported (QP stays up).
WireStatusResult check_opcode(std::uint16_t type);

// Writes header (body_len taken from body.size()) + body into out; returns bytes written.
// Fails with Malformed if body > 8160, unknown flag bits, or out is too small.
WireResult<std::size_t> encode_frame(const FrameHeader& h, std::span<const std::byte> body,
                                     std::span<std::byte> out);

struct Tlv {
  std::uint16_t tag = 0;
  std::span<const std::byte> value;
  bool critical() const { return (tag & kTlvCriticalBit) != 0; }
};

// Walks a TLV tail. next() yields entries until the tail is exhausted; truncated or
// ill-formed entries (value overruns the tail, non-zero padding) -> Malformed.
class TlvReader {
 public:
  explicit TlvReader(std::span<const std::byte> tail) : rest_(tail) {}
  bool done() const { return rest_.empty(); }
  WireResult<Tlv> next();

 private:
  std::span<const std::byte> rest_;
};

// Validates a whole tail per section 3: ill-formed -> Malformed; D11 (CRITICAL_EXT set
// iff a critical TLV is present) violated -> Malformed; critical TLV present (none is
// known in v0) -> Unsupported. Unknown non-critical TLVs are skipped.
WireStatusResult check_tlv_tail(std::uint16_t frame_flags, std::span<const std::byte> tail);

// Appends one TLV (value padded with zeros to 8 B) at out[0..]; returns bytes written
// or Malformed if it does not fit.
WireResult<std::size_t> encode_tlv(std::uint16_t tag, std::span<const std::byte> value,
                                   std::span<std::byte> out);

}  // namespace miracache::proto
