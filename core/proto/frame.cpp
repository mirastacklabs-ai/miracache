// SPDX-License-Identifier: Apache-2.0
#include "proto/frame.h"

#include <algorithm>
#include <cstring>

#include "proto/le.h"

namespace miracache::proto {
namespace {

WireError err(WireStatus s, const char* ctx, bool close = false) { return WireError{s, ctx, close}; }

std::size_t pad8(std::size_t n) { return (n + 7) & ~std::size_t{7}; }

}  // namespace

WireResult<Frame> decode_frame(std::span<const std::byte> in) {
  if (in.size() < kFrameHeaderSize) return err(WireStatus::Corrupt, "frame: short", true);
  if (get_le<std::uint32_t>(in, fh::magic) != kFrameMagicLe) {
    return err(WireStatus::Corrupt, "frame: bad magic", true);
  }
  Frame f;
  f.h.body_len = get_le<std::uint32_t>(in, fh::body_len);
  if (f.h.body_len > kMaxBodyLen || f.h.body_len != in.size() - kFrameHeaderSize) {
    return err(WireStatus::Corrupt, "frame: body_len", true);
  }
  f.h.ver_major = get_le<std::uint8_t>(in, fh::ver_major);
  if (f.h.ver_major != kVerMajor) return err(WireStatus::Unsupported, "frame: major", true);
  f.h.ver_minor = get_le<std::uint8_t>(in, fh::ver_minor);
  f.h.type = get_le<std::uint16_t>(in, fh::type);
  f.h.flags = get_le<std::uint16_t>(in, fh::flags);
  if ((f.h.flags & ~flag::kKnown) != 0) return err(WireStatus::Malformed, "frame: unknown flag");
  f.h.credits = get_le<std::uint16_t>(in, fh::credits);
  f.h.request_id = get_le<std::uint64_t>(in, fh::request_id);
  f.h.epoch = get_le<std::uint32_t>(in, fh::epoch);
  f.h.bundle_gen_lo = get_le<std::uint32_t>(in, fh::bundle_gen_lo);
  f.body = in.subspan(kFrameHeaderSize);
  return f;
}

WireStatusResult check_opcode(std::uint16_t type) {
  if (!is_known_op(type)) return err(WireStatus::Unsupported, "frame: unknown opcode");
  return {};
}

WireResult<std::size_t> encode_frame(const FrameHeader& h, std::span<const std::byte> body,
                                     std::span<std::byte> out) {
  if (body.size() > kMaxBodyLen) return err(WireStatus::Malformed, "frame: body too large");
  if ((h.flags & ~flag::kKnown) != 0) return err(WireStatus::Malformed, "frame: unknown flag");
  if (out.size() < kFrameHeaderSize + body.size()) return err(WireStatus::Malformed, "frame: out too small");
  put_bytes(out, fh::magic, kFrameMagic);
  put_le<std::uint8_t>(out, fh::ver_major, h.ver_major);
  put_le<std::uint8_t>(out, fh::ver_minor, h.ver_minor);
  put_le<std::uint16_t>(out, fh::type, h.type);
  put_le<std::uint16_t>(out, fh::flags, h.flags);
  put_le<std::uint16_t>(out, fh::credits, h.credits);
  put_le<std::uint32_t>(out, fh::body_len, static_cast<std::uint32_t>(body.size()));
  put_le<std::uint64_t>(out, fh::request_id, h.request_id);
  put_le<std::uint32_t>(out, fh::epoch, h.epoch);
  put_le<std::uint32_t>(out, fh::bundle_gen_lo, h.bundle_gen_lo);
  if (!body.empty()) std::memcpy(out.data() + kFrameHeaderSize, body.data(), body.size());
  return kFrameHeaderSize + body.size();
}

WireResult<Tlv> TlvReader::next() {
  if (rest_.size() < kTlvHeaderSize) return err(WireStatus::Malformed, "tlv: truncated header");
  Tlv t;
  t.tag = get_le<std::uint16_t>(rest_, 0);
  const std::size_t len = get_le<std::uint16_t>(rest_, 2);
  const std::size_t total = pad8(kTlvHeaderSize + len);
  if (total > rest_.size()) return err(WireStatus::Malformed, "tlv: truncated value");
  for (std::size_t i = kTlvHeaderSize + len; i < total; ++i) {
    if (rest_[i] != std::byte{0}) return err(WireStatus::Malformed, "tlv: padding not zero");
  }
  t.value = rest_.subspan(kTlvHeaderSize, len);
  rest_ = rest_.subspan(total);
  return t;
}

WireStatusResult check_tlv_tail(std::uint16_t frame_flags, std::span<const std::byte> tail) {
  TlvReader r(tail);
  bool critical = false;
  while (!r.done()) {
    auto t = r.next();
    if (!t) return t.error();
    critical = critical || t->critical();
  }
  const bool flagged = (frame_flags & flag::CRITICAL_EXT) != 0;
  if (flagged != critical) return err(WireStatus::Malformed, "tlv: CRITICAL_EXT mismatch (D11)");
  if (critical) return err(WireStatus::Unsupported, "tlv: unknown critical tag");
  return {};
}

WireResult<std::size_t> encode_tlv(std::uint16_t tag, std::span<const std::byte> value,
                                   std::span<std::byte> out) {
  const std::size_t total = pad8(kTlvHeaderSize + value.size());
  if (value.size() > 0xffff || out.size() < total) return err(WireStatus::Malformed, "tlv: does not fit");
  put_le<std::uint16_t>(out, 0, tag);
  put_le<std::uint16_t>(out, 2, static_cast<std::uint16_t>(value.size()));
  if (!value.empty()) std::memcpy(out.data() + kTlvHeaderSize, value.data(), value.size());
  std::fill(out.begin() + kTlvHeaderSize + value.size(), out.begin() + total, std::byte{0});
  return total;
}

}  // namespace miracache::proto
