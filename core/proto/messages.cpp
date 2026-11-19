// SPDX-License-Identifier: Apache-2.0
#include "proto/messages.h"

#include <algorithm>
#include <cstring>

#include "proto/le.h"
#include "proto/state_gen.h"

namespace miracache::proto {
namespace {

WireError malformed(const char* c) { return WireError{WireStatus::Malformed, c, false}; }

bool all_zero(std::span<const std::byte> b) {
  return std::all_of(b.begin(), b.end(), [](std::byte v) { return v == std::byte{0}; });
}

bool is_response_op(Op op) {
  switch (op) {
    case Op::RENEW_ACK: case Op::INVALIDATE_ACK: case Op::PUT_DONE:
    case Op::HELLO_ACK: case Op::PONG: case Op::STATS_ACK:
    case Op::LOOKUP_ACK: case Op::PUT_BEGIN_ACK:
      return true;
    default:  // SEG_TABLE and GOAWAY are unsolicited pushes: no RESPONSE
      return false;
  }
}

// Frame type and direction must match; ERROR is only for error replies.
WireStatusResult check_header(const FrameHeader& h, Op op) {
  if (h.type != static_cast<std::uint16_t>(op)) return malformed("msg: wrong frame type");
  if (((h.flags & flag::RESPONSE) != 0) != is_response_op(op)) return malformed("msg: RESPONSE flag");
  if ((h.flags & flag::ERROR) != 0) return malformed("msg: ERROR flag");
  return {};
}

WireStatusResult need_len(std::span<const std::byte> body, std::size_t fixed) {
  if (body.size() < fixed) return malformed("msg: short body");
  return {};
}

// Copies the tail verbatim after `at`; returns total length.
WireResult<std::size_t> finish(std::span<std::byte> out, std::size_t at, std::span<const std::byte> tlvs) {
  if (out.size() < at + tlvs.size()) return malformed("msg: out too small");
  if (!tlvs.empty()) std::memcpy(out.data() + at, tlvs.data(), tlvs.size());
  return at + tlvs.size();
}

WireStatusResult room(std::span<std::byte> out, std::size_t n) {
  if (out.size() < n) return malformed("msg: out too small");
  std::fill(out.begin(), out.begin() + n, std::byte{0});
  return {};
}

std::size_t pad8(std::size_t n) { return (n + 7) & ~std::size_t{7}; }

}  // namespace

FrameHeader header_for(Op op, std::uint64_t request_id) {
  FrameHeader h;
  h.type = static_cast<std::uint16_t>(op);
  h.flags = is_response_op(op) ? flag::RESPONSE : 0;
  h.request_id = request_id;
  return h;
}

// ---- RENEW / RELEASE / PUT_CANCEL: one u64 -------------------------------------------
WireResult<std::size_t> encode_renew(const Renew& m, std::span<std::byte> out) {
  if (m.lease_id == 0) return malformed("renew: lease_id 0");
  if (auto r = room(out, kRenewSize); !r) return r.error();
  put_le<std::uint64_t>(out, 0, m.lease_id);
  return finish(out, kRenewSize, m.tlvs);
}
WireResult<Renew> decode_renew(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::RENEW); !r) return r.error();
  if (auto r = need_len(b, kRenewSize); !r) return r.error();
  Renew m;
  m.lease_id = get_le<std::uint64_t>(b, 0);
  if (m.lease_id == 0) return malformed("renew: lease_id 0");
  m.tlvs = b.subspan(kRenewSize);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

WireResult<std::size_t> encode_release(const Release& m, std::span<std::byte> out) {
  if (auto r = room(out, kReleaseSize); !r) return r.error();
  put_le<std::uint64_t>(out, 0, m.lease_id);
  return finish(out, kReleaseSize, m.tlvs);
}
WireResult<Release> decode_release(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::RELEASE); !r) return r.error();
  if (auto r = need_len(b, kReleaseSize); !r) return r.error();
  Release m;
  m.lease_id = get_le<std::uint64_t>(b, 0);
  m.tlvs = b.subspan(kReleaseSize);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

WireResult<std::size_t> encode_put_cancel(const PutCancel& m, std::span<std::byte> out) {
  if (auto r = room(out, kPutCancelSize); !r) return r.error();
  put_le<std::uint64_t>(out, 0, m.put_id);
  return finish(out, kPutCancelSize, m.tlvs);
}
WireResult<PutCancel> decode_put_cancel(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::PUT_CANCEL); !r) return r.error();
  if (auto r = need_len(b, kPutCancelSize); !r) return r.error();
  PutCancel m;
  m.put_id = get_le<std::uint64_t>(b, 0);
  m.tlvs = b.subspan(kPutCancelSize);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- RENEW_ACK ------------------------------------------------------------------------
WireResult<std::size_t> encode_renew_ack(const RenewAck& m, std::span<std::byte> out) {
  if (m.status > 1) return malformed("renew_ack: status");
  if (auto r = room(out, kRenewAckSize); !r) return r.error();
  put_le<std::uint64_t>(out, rna::lease_id, m.lease_id);
  put_le<std::uint32_t>(out, rna::ttl_ms, m.ttl_ms);
  put_le<std::uint8_t>(out, rna::status, m.status);
  return finish(out, kRenewAckSize, m.tlvs);
}
WireResult<RenewAck> decode_renew_ack(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::RENEW_ACK); !r) return r.error();
  if (auto r = need_len(b, kRenewAckSize); !r) return r.error();
  RenewAck m;
  m.lease_id = get_le<std::uint64_t>(b, rna::lease_id);
  m.ttl_ms = get_le<std::uint32_t>(b, rna::ttl_ms);
  m.status = get_le<std::uint8_t>(b, rna::status);
  if (m.status > 1) return malformed("renew_ack: status");
  if (!all_zero(b.subspan(rna::z, 3))) return malformed("renew_ack: z");
  m.tlvs = b.subspan(kRenewAckSize);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- INVALIDATE / ACK -----------------------------------------------------------------
WireResult<std::size_t> encode_invalidate(const Invalidate& m, std::span<std::byte> out) {
  if (!generation_valid(m.gen)) return malformed("invalidate: gen");
  if (auto r = room(out, kInvalidateSize); !r) return r.error();
  put_bytes(out, inv::scope_id, m.scope_id);
  put_bytes(out, inv::key_hash, m.key_hash);
  put_le<std::uint64_t>(out, inv::gen, m.gen);
  return finish(out, kInvalidateSize, m.tlvs);
}
WireResult<Invalidate> decode_invalidate(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::INVALIDATE); !r) return r.error();
  if (auto r = need_len(b, kInvalidateSize); !r) return r.error();
  Invalidate m;
  get_bytes(b, inv::scope_id, m.scope_id);
  get_bytes(b, inv::key_hash, m.key_hash);
  m.gen = get_le<std::uint64_t>(b, inv::gen);
  if (!generation_valid(m.gen)) return malformed("invalidate: gen");
  m.tlvs = b.subspan(kInvalidateSize);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

WireResult<std::size_t> encode_invalidate_ack(const InvalidateAck& m, std::span<std::byte> out) {
  return finish(out, kInvalidateAckSize, m.tlvs);
}
WireResult<InvalidateAck> decode_invalidate_ack(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::INVALIDATE_ACK); !r) return r.error();
  InvalidateAck m;
  m.tlvs = b;
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- PUT_COMMIT -----------------------------------------------------------------------
WireResult<std::size_t> encode_put_commit(const PutCommit& m, std::span<std::byte> out) {
  if (m.n < 1 || m.n > kMaxPutKeys) return malformed("put_commit: n");
  for (std::size_t i = 1; i < m.n; ++i) {
    if (m.e[i].key_index <= m.e[i - 1].key_index) return malformed("put_commit: key_index order");
  }
  const std::size_t fixed = kPutCommitFixed + m.n * kPutCommitEntry;
  if (auto r = room(out, fixed); !r) return r.error();
  put_le<std::uint64_t>(out, pc::put_id, m.put_id);
  put_le<std::uint16_t>(out, pc::n, m.n);
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kPutCommitFixed + i * kPutCommitEntry;
    put_le<std::uint16_t>(out, o + pce::key_index, m.e[i].key_index);
    put_le<std::uint32_t>(out, o + pce::crc32c, m.e[i].crc32c);
    put_le<std::uint64_t>(out, o + pce::stored_len, m.e[i].stored_len);
  }
  return finish(out, fixed, m.tlvs);
}
WireResult<PutCommit> decode_put_commit(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::PUT_COMMIT); !r) return r.error();
  if (auto r = need_len(b, kPutCommitFixed); !r) return r.error();
  PutCommit m;
  m.put_id = get_le<std::uint64_t>(b, pc::put_id);
  m.n = get_le<std::uint16_t>(b, pc::n);
  if (m.n < 1 || m.n > kMaxPutKeys) return malformed("put_commit: n");
  if (!all_zero(b.subspan(pc::z, 6))) return malformed("put_commit: z");
  const std::size_t fixed = kPutCommitFixed + m.n * kPutCommitEntry;
  if (auto r = need_len(b, fixed); !r) return r.error();
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kPutCommitFixed + i * kPutCommitEntry;
    m.e[i].key_index = get_le<std::uint16_t>(b, o + pce::key_index);
    if (get_le<std::uint16_t>(b, o + pce::z) != 0) return malformed("put_commit: entry z");
    m.e[i].crc32c = get_le<std::uint32_t>(b, o + pce::crc32c);
    m.e[i].stored_len = get_le<std::uint64_t>(b, o + pce::stored_len);
    if (i > 0 && m.e[i].key_index <= m.e[i - 1].key_index) return malformed("put_commit: key_index order");
  }
  m.tlvs = b.subspan(fixed);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- PUT_DONE -------------------------------------------------------------------------
WireResult<std::size_t> encode_put_done(const PutDone& m, std::span<std::byte> out) {
  if (m.n < 1 || m.n > kMaxPutKeys) return malformed("put_done: n");
  for (std::size_t i = 0; i < m.n; ++i) {
    if (m.e[i].status > 1 || m.e[i].reason > 4) return malformed("put_done: status/reason");
  }
  const std::size_t fixed = pad8(kPutCommitFixed + m.n * kPutDoneEntry);
  if (auto r = room(out, fixed); !r) return r.error();
  put_le<std::uint64_t>(out, pc::put_id, m.put_id);
  put_le<std::uint16_t>(out, pc::n, m.n);
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kPutCommitFixed + i * kPutDoneEntry;
    put_le<std::uint16_t>(out, o + pde::key_index, m.e[i].key_index);
    put_le<std::uint8_t>(out, o + pde::status, m.e[i].status);
    put_le<std::uint8_t>(out, o + pde::reason, m.e[i].reason);
  }
  return finish(out, fixed, m.tlvs);
}
WireResult<PutDone> decode_put_done(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::PUT_DONE); !r) return r.error();
  if (auto r = need_len(b, kPutCommitFixed); !r) return r.error();
  PutDone m;
  m.put_id = get_le<std::uint64_t>(b, pc::put_id);
  m.n = get_le<std::uint16_t>(b, pc::n);
  if (m.n < 1 || m.n > kMaxPutKeys) return malformed("put_done: n");
  if (!all_zero(b.subspan(pc::z, 6))) return malformed("put_done: z");
  const std::size_t raw = kPutCommitFixed + m.n * kPutDoneEntry;
  const std::size_t fixed = pad8(raw);
  if (auto r = need_len(b, fixed); !r) return r.error();
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kPutCommitFixed + i * kPutDoneEntry;
    m.e[i].key_index = get_le<std::uint16_t>(b, o + pde::key_index);
    m.e[i].status = get_le<std::uint8_t>(b, o + pde::status);
    m.e[i].reason = get_le<std::uint8_t>(b, o + pde::reason);
    if (m.e[i].status > 1 || m.e[i].reason > 4) return malformed("put_done: status/reason");
  }
  if (!all_zero(b.subspan(raw, fixed - raw))) return malformed("put_done: padding");
  m.tlvs = b.subspan(fixed);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- Error reply ----------------------------------------------------------------------
WireResult<std::size_t> encode_error_reply_frame(const FrameHeader& req, const ErrorReply& m,
                                                 std::span<std::byte> out) {
  if (m.status < 1 || m.status > 5) return malformed("error: status");
  std::array<std::byte, kErrorReplySize> body{};
  put_le<std::uint16_t>(body, er::status, m.status);
  put_le<std::uint32_t>(body, er::retry_after_ms, m.retry_after_ms);
  FrameHeader h = req;
  h.flags = flag::RESPONSE | flag::ERROR;  // type stays the request type
  return encode_frame(h, body, out);
}
WireResult<ErrorReply> decode_error_reply(const FrameHeader& h, std::span<const std::byte> b) {
  if (h.flags != (flag::RESPONSE | flag::ERROR)) {  // no MORE, no CRITICAL_EXT
    return malformed("error: flags");
  }
  if (b.size() != kErrorReplySize) return malformed("error: body length");
  ErrorReply m;
  m.status = get_le<std::uint16_t>(b, er::status);
  if (m.status < 1 || m.status > 5) return malformed("error: status");
  if (get_le<std::uint16_t>(b, er::z) != 0) return malformed("error: z");
  m.retry_after_ms = get_le<std::uint32_t>(b, er::retry_after_ms);
  return m;
}


// ============================ Run B ====================================================
namespace {
bool zero_at(std::span<const std::byte> b, std::size_t off, std::size_t n) {
  return all_zero(b.subspan(off, n));
}
}  // namespace

// ---- HELLO / HELLO_ACK ----------------------------------------------------------------
namespace {
WireStatusResult check_hello(const Hello& m) {
  if (m.major_min > m.major_max) return malformed("hello: major range");
  if (m.cls > 2) return malformed("hello: class");
  if (m.rail >= kMaxRails) return malformed("hello: rail");
  if (m.proto < 1 || m.proto > 2) return malformed("hello: proto");
  if (m.max_frame != kMaxFrameSize) return malformed("hello: max_frame");
  return {};
}
WireResult<std::size_t> encode_hello_as(const Hello& m, std::span<std::byte> out) {
  if (auto r = check_hello(m); !r) return r.error();
  if (auto r = room(out, kHelloSize); !r) return r.error();
  put_le<std::uint8_t>(out, hello::major_min, m.major_min);
  put_le<std::uint8_t>(out, hello::major_max, m.major_max);
  put_le<std::uint8_t>(out, hello::minor, m.minor);
  put_le<std::uint8_t>(out, hello::cls, m.cls);
  put_le<std::uint8_t>(out, hello::ird, m.ird);
  put_le<std::uint8_t>(out, hello::ord, m.ord);
  put_le<std::uint8_t>(out, hello::rail, m.rail);
  put_le<std::uint8_t>(out, hello::proto, m.proto);
  put_le<std::uint64_t>(out, hello::features, m.features);
  put_le<std::uint32_t>(out, hello::node_id, m.node_id);
  put_le<std::uint32_t>(out, hello::mtu, m.mtu);
  put_bytes(out, hello::conn_id, m.conn_id);
  put_le<std::uint32_t>(out, hello::max_frame, m.max_frame);
  return finish(out, kHelloSize, m.tlvs);
}
WireResult<Hello> decode_hello_as(const FrameHeader& h, std::span<const std::byte> b, Op op) {
  if (auto r = check_header(h, op); !r) return r.error();
  if (auto r = need_len(b, kHelloSize); !r) return r.error();
  Hello m;
  m.major_min = get_le<std::uint8_t>(b, hello::major_min);
  m.major_max = get_le<std::uint8_t>(b, hello::major_max);
  m.minor = get_le<std::uint8_t>(b, hello::minor);
  m.cls = get_le<std::uint8_t>(b, hello::cls);
  m.ird = get_le<std::uint8_t>(b, hello::ird);
  m.ord = get_le<std::uint8_t>(b, hello::ord);
  m.rail = get_le<std::uint8_t>(b, hello::rail);
  m.proto = get_le<std::uint8_t>(b, hello::proto);
  m.features = get_le<std::uint64_t>(b, hello::features);
  m.node_id = get_le<std::uint32_t>(b, hello::node_id);
  m.mtu = get_le<std::uint32_t>(b, hello::mtu);
  get_bytes(b, hello::conn_id, m.conn_id);
  m.max_frame = get_le<std::uint32_t>(b, hello::max_frame);
  if (auto r = check_hello(m); !r) return r.error();
  if (get_le<std::uint32_t>(b, hello::z) != 0) return malformed("hello: z");
  m.tlvs = b.subspan(kHelloSize);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}
}  // namespace
WireResult<std::size_t> encode_hello(const Hello& m, std::span<std::byte> out) { return encode_hello_as(m, out); }
WireResult<Hello> decode_hello(const FrameHeader& h, std::span<const std::byte> b) { return decode_hello_as(h, b, Op::HELLO); }
WireResult<std::size_t> encode_hello_ack(const HelloAck& m, std::span<std::byte> out) { return encode_hello_as(m, out); }
WireResult<HelloAck> decode_hello_ack(const FrameHeader& h, std::span<const std::byte> b) { return decode_hello_as(h, b, Op::HELLO_ACK); }
WireResult<std::size_t> encode_boot_nonce_tlv(std::uint64_t nonce, std::span<std::byte> out) {
  std::array<std::byte, 8> v{};
  put_le<std::uint64_t>(v, 0, nonce);
  return encode_tlv(kTlvTagBootNonce, v, out);
}
std::optional<std::uint64_t> find_boot_nonce(std::span<const std::byte> tlvs) {
  TlvReader r(tlvs);
  while (!r.done()) {
    auto t = r.next();
    if (!t) return std::nullopt;
    if (t->tag == kTlvTagBootNonce && t->value.size() == 8) return get_le<std::uint64_t>(t->value, 0);
  }
  return std::nullopt;
}
WireResult<std::size_t> encode_max_stored_block_tlv(std::uint64_t bytes, std::span<std::byte> out) {
  std::array<std::byte, 8> v{};
  put_le<std::uint64_t>(v, 0, bytes);
  return encode_tlv(kTlvTagMaxStoredBlock, v, out);
}
std::optional<std::uint64_t> find_max_stored_block(std::span<const std::byte> tlvs) {
  TlvReader r(tlvs);
  while (!r.done()) {
    auto t = r.next();
    if (!t) return std::nullopt;
    if (t->tag == kTlvTagMaxStoredBlock && t->value.size() == 8) {
      const auto v = get_le<std::uint64_t>(t->value, 0);
      return v == 0 ? std::nullopt : std::optional<std::uint64_t>(v);
    }
  }
  return std::nullopt;
}

namespace {
bool valid_hostname(std::span<const std::byte> v) {
  if (v.empty() || v.size() > kMaxHostnameLen) return false;
  for (const std::byte b : v) {
    const auto c = std::to_integer<unsigned>(b);
    if (c < 0x21 || c > 0x7e) return false;
  }
  return true;
}
}  // namespace
WireResult<std::size_t> encode_hostname_tlv(std::string_view name, std::span<std::byte> out) {
  const auto v = std::as_bytes(std::span<const char>(name.data(), name.size()));
  if (!valid_hostname(v)) return malformed("hostname tlv: empty, too long or not printable");
  return encode_tlv(kTlvTagHostname, v, out);
}
std::optional<std::string> find_hostname(std::span<const std::byte> tlvs) {
  TlvReader r(tlvs);
  while (!r.done()) {
    auto t = r.next();
    if (!t) return std::nullopt;
    if (t->tag == kTlvTagHostname) {
      if (!valid_hostname(t->value)) return std::nullopt;
      return std::string(reinterpret_cast<const char*>(t->value.data()), t->value.size());
    }
  }
  return std::nullopt;
}
// ---- SEG_TABLE ------------------------------------------------------------------------
namespace {
WireStatusResult check_seg_table(const SegTable& m) {
  if (m.n > kMaxSegEntries) return malformed("seg_table: n");
  if (m.n_rails < 1 || m.n_rails > kMaxRails) return malformed("seg_table: n_rails");
  if (m.local_rail >= m.n_rails) return malformed("seg_table: local_rail");
  for (std::size_t i = 0; i < m.n; ++i) {
    if ((m.e[i].flags & ~std::uint32_t{1}) != 0) return malformed("seg_table: entry flags");
  }
  return {};
}
}  // namespace
WireResult<std::size_t> encode_seg_table(const SegTable& m, std::span<std::byte> out) {
  if (auto r = check_seg_table(m); !r) return r.error();
  const std::size_t fixed = kSegTableFixed + m.n * kSegEntrySize;
  if (auto r = room(out, fixed); !r) return r.error();
  put_le<std::uint16_t>(out, segt::n, m.n);
  put_le<std::uint8_t>(out, segt::n_rails, m.n_rails);
  put_le<std::uint8_t>(out, segt::local_rail, m.local_rail);
  put_le<std::uint32_t>(out, segt::table_gen, m.table_gen);
  put_le<std::uint64_t>(out, segt::sg_base, m.sg_base);
  put_le<std::uint64_t>(out, segt::sg_slots, m.sg_slots);
  for (std::size_t r = 0; r < kMaxRails; ++r) put_le<std::uint32_t>(out, segt::sg_rkey + 4 * r, m.sg_rkey[r]);
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kSegTableFixed + i * kSegEntrySize;
    put_le<std::uint32_t>(out, o + sege::seg_id, m.e[i].seg_id);
    put_le<std::uint32_t>(out, o + sege::flags, m.e[i].flags);
    put_le<std::uint64_t>(out, o + sege::base, m.e[i].base);
    put_le<std::uint64_t>(out, o + sege::len, m.e[i].len);
    for (std::size_t r = 0; r < kMaxRails; ++r) put_le<std::uint32_t>(out, o + sege::rkey + 4 * r, m.e[i].rkey[r]);
  }
  return finish(out, fixed, m.tlvs);
}
WireResult<SegTable> decode_seg_table(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::SEG_TABLE); !r) return r.error();
  if (auto r = need_len(b, kSegTableFixed); !r) return r.error();
  SegTable m;
  m.n = get_le<std::uint16_t>(b, segt::n);
  m.n_rails = get_le<std::uint8_t>(b, segt::n_rails);
  m.local_rail = get_le<std::uint8_t>(b, segt::local_rail);
  m.table_gen = get_le<std::uint32_t>(b, segt::table_gen);
  m.sg_base = get_le<std::uint64_t>(b, segt::sg_base);
  m.sg_slots = get_le<std::uint64_t>(b, segt::sg_slots);
  for (std::size_t r = 0; r < kMaxRails; ++r) m.sg_rkey[r] = get_le<std::uint32_t>(b, segt::sg_rkey + 4 * r);
  if (m.n > kMaxSegEntries) return malformed("seg_table: n");
  if (m.n_rails < 1 || m.n_rails > kMaxRails) return malformed("seg_table: n_rails");
  if (m.local_rail >= m.n_rails) return malformed("seg_table: local_rail");
  const std::size_t fixed = kSegTableFixed + m.n * kSegEntrySize;
  if (auto r = need_len(b, fixed); !r) return r.error();
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kSegTableFixed + i * kSegEntrySize;
    m.e[i].seg_id = get_le<std::uint32_t>(b, o + sege::seg_id);
    m.e[i].flags = get_le<std::uint32_t>(b, o + sege::flags);
    if ((m.e[i].flags & ~std::uint32_t{1}) != 0) return malformed("seg_table: entry flags");
    m.e[i].base = get_le<std::uint64_t>(b, o + sege::base);
    m.e[i].len = get_le<std::uint64_t>(b, o + sege::len);
    for (std::size_t r = 0; r < kMaxRails; ++r) m.e[i].rkey[r] = get_le<std::uint32_t>(b, o + sege::rkey + 4 * r);
  }
  m.tlvs = b.subspan(fixed);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- PING / PONG ----------------------------------------------------------------------
namespace {
WireResult<std::size_t> encode_ping_as(const Ping& m, std::span<std::byte> out) {
  if (auto r = room(out, kPingSize); !r) return r.error();
  put_le<std::uint64_t>(out, 0, m.timestamp_ns);
  return finish(out, kPingSize, m.tlvs);
}
WireResult<Ping> decode_ping_as(const FrameHeader& h, std::span<const std::byte> b, Op op) {
  if (auto r = check_header(h, op); !r) return r.error();
  if (auto r = need_len(b, kPingSize); !r) return r.error();
  Ping m;
  m.timestamp_ns = get_le<std::uint64_t>(b, 0);
  m.tlvs = b.subspan(kPingSize);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}
}  // namespace
WireResult<std::size_t> encode_ping(const Ping& m, std::span<std::byte> out) { return encode_ping_as(m, out); }
WireResult<Ping> decode_ping(const FrameHeader& h, std::span<const std::byte> b) { return decode_ping_as(h, b, Op::PING); }
WireResult<std::size_t> encode_pong(const Pong& m, std::span<std::byte> out) { return encode_ping_as(m, out); }
WireResult<Pong> decode_pong(const FrameHeader& h, std::span<const std::byte> b) { return decode_ping_as(h, b, Op::PONG); }

// ---- GOAWAY ---------------------------------------------------------------------------
WireResult<std::size_t> encode_goaway(const Goaway& m, std::span<std::byte> out) {
  if (m.reason < 1 || m.reason > 4) return malformed("goaway: reason");
  if (auto r = room(out, kGoawaySize); !r) return r.error();
  put_le<std::uint32_t>(out, 0, m.reason);
  put_le<std::uint32_t>(out, 4, m.drain_ms);
  return finish(out, kGoawaySize, m.tlvs);
}
WireResult<Goaway> decode_goaway(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::GOAWAY); !r) return r.error();
  if (auto r = need_len(b, kGoawaySize); !r) return r.error();
  Goaway m;
  m.reason = get_le<std::uint32_t>(b, 0);
  m.drain_ms = get_le<std::uint32_t>(b, 4);
  if (m.reason < 1 || m.reason > 4) return malformed("goaway: reason");
  m.tlvs = b.subspan(kGoawaySize);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- STATS / STATS_ACK ----------------------------------------------------------------
namespace {
WireResult<std::size_t> encode_stats_as(std::uint32_t selector, std::span<const std::byte> tlvs,
                                        std::span<std::byte> out) {
  if (auto r = room(out, kStatsSize); !r) return r.error();
  put_le<std::uint32_t>(out, 0, selector);
  return finish(out, kStatsSize, tlvs);
}
WireStatusResult decode_stats_as(const FrameHeader& h, std::span<const std::byte> b, Op op,
                                 std::uint32_t& selector, std::span<const std::byte>& tlvs) {
  if (auto r = check_header(h, op); !r) return r.error();
  if (auto r = need_len(b, kStatsSize); !r) return r.error();
  selector = get_le<std::uint32_t>(b, 0);
  if (get_le<std::uint32_t>(b, 4) != 0) return malformed("stats: z");
  tlvs = b.subspan(kStatsSize);
  return check_tlv_tail(h.flags, tlvs);
}
}  // namespace
WireResult<std::size_t> encode_stats(const Stats& m, std::span<std::byte> out) { return encode_stats_as(m.selector, m.tlvs, out); }
WireResult<Stats> decode_stats(const FrameHeader& h, std::span<const std::byte> b) {
  Stats m;
  if (auto r = decode_stats_as(h, b, Op::STATS, m.selector, m.tlvs); !r) return r.error();
  return m;
}
WireResult<std::size_t> encode_stats_ack(const StatsAck& m, std::span<std::byte> out) { return encode_stats_as(m.selector, m.tlvs, out); }
WireResult<StatsAck> decode_stats_ack(const FrameHeader& h, std::span<const std::byte> b) {
  StatsAck m;
  if (auto r = decode_stats_as(h, b, Op::STATS_ACK, m.selector, m.tlvs); !r) return r.error();
  return m;
}

// ---- LOOKUP ---------------------------------------------------------------------------
WireResult<std::size_t> encode_lookup(const Lookup& m, std::span<std::byte> out) {
  if (m.n < 1 || m.n > kMaxLookupKeys) return malformed("lookup: n");
  if ((m.flags & ~std::uint16_t{1}) != 0) return malformed("lookup: flags");
  const std::size_t fixed = kLookupFixed + m.n * kKeyHashSize;
  if (auto r = room(out, fixed); !r) return r.error();
  put_bytes(out, lk::scope_id, m.scope_id);
  put_le<std::uint16_t>(out, lk::flags, m.flags);
  put_le<std::uint16_t>(out, lk::n, m.n);
  for (std::size_t i = 0; i < m.n; ++i) std::memcpy(out.data() + kLookupFixed + i * kKeyHashSize, m.key_hash[i].data(), kKeyHashSize);
  return finish(out, fixed, m.tlvs);
}
WireResult<Lookup> decode_lookup(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::LOOKUP); !r) return r.error();
  if (auto r = need_len(b, kLookupFixed); !r) return r.error();
  Lookup m;
  get_bytes(b, lk::scope_id, m.scope_id);
  m.flags = get_le<std::uint16_t>(b, lk::flags);
  m.n = get_le<std::uint16_t>(b, lk::n);
  if ((m.flags & ~std::uint16_t{1}) != 0) return malformed("lookup: flags");
  if (m.n < 1 || m.n > kMaxLookupKeys) return malformed("lookup: n");
  if (get_le<std::uint32_t>(b, lk::z) != 0) return malformed("lookup: z");
  const std::size_t fixed = kLookupFixed + m.n * kKeyHashSize;
  if (auto r = need_len(b, fixed); !r) return r.error();
  for (std::size_t i = 0; i < m.n; ++i) std::memcpy(m.key_hash[i].data(), b.data() + kLookupFixed + i * kKeyHashSize, kKeyHashSize);
  m.tlvs = b.subspan(fixed);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- LOOKUP_ACK -----------------------------------------------------------------------
namespace {
// MISS entries are all-zero (D5); HIT carries a valid generation (D14).
WireStatusResult check_lookup_ack_entry(const LookupAckEntry& e) {
  if (e.status > 1) return malformed("lookup_ack: status");
  if (e.status == 0) {
    if (e.seg_id != 0 || e.offset != 0 || e.stored_len != 0 || e.gen != 0 || e.gen_slot != 0) {
      return malformed("lookup_ack: MISS entry not zero");
    }
  } else if (!generation_valid(e.gen)) {
    return malformed("lookup_ack: gen");
  }
  return {};
}
}  // namespace
WireResult<std::size_t> encode_lookup_ack(const LookupAck& m, std::span<std::byte> out) {
  if (m.n < 1 || m.n > kMaxLookupKeys) return malformed("lookup_ack: n");
  for (std::size_t i = 0; i < m.n; ++i) {
    if (auto r = check_lookup_ack_entry(m.e[i]); !r) return r.error();
  }
  const std::size_t fixed = kLookupAckFixed + m.n * kLookupAckEntry;
  if (auto r = room(out, fixed); !r) return r.error();
  put_le<std::uint64_t>(out, lka::lease_id, m.lease_id);
  put_le<std::uint32_t>(out, lka::ttl_ms, m.ttl_ms);
  put_le<std::uint16_t>(out, lka::n, m.n);
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kLookupAckFixed + i * kLookupAckEntry;
    put_le<std::uint8_t>(out, o + lkae::status, m.e[i].status);
    put_le<std::uint32_t>(out, o + lkae::seg_id, m.e[i].seg_id);
    put_le<std::uint64_t>(out, o + lkae::offset, m.e[i].offset);
    put_le<std::uint64_t>(out, o + lkae::stored_len, m.e[i].stored_len);
    put_le<std::uint64_t>(out, o + lkae::gen, m.e[i].gen);
    put_le<std::uint64_t>(out, o + lkae::gen_slot, m.e[i].gen_slot);
  }
  return finish(out, fixed, m.tlvs);
}
WireResult<LookupAck> decode_lookup_ack(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::LOOKUP_ACK); !r) return r.error();
  if (auto r = need_len(b, kLookupAckFixed); !r) return r.error();
  LookupAck m;
  m.lease_id = get_le<std::uint64_t>(b, lka::lease_id);
  m.ttl_ms = get_le<std::uint32_t>(b, lka::ttl_ms);
  m.n = get_le<std::uint16_t>(b, lka::n);
  if (m.n < 1 || m.n > kMaxLookupKeys) return malformed("lookup_ack: n");
  if (get_le<std::uint16_t>(b, lka::z) != 0) return malformed("lookup_ack: z");
  const std::size_t fixed = kLookupAckFixed + m.n * kLookupAckEntry;
  if (auto r = need_len(b, fixed); !r) return r.error();
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kLookupAckFixed + i * kLookupAckEntry;
    m.e[i].status = get_le<std::uint8_t>(b, o + lkae::status);
    if (!zero_at(b, o + lkae::z, 3)) return malformed("lookup_ack: entry z");
    m.e[i].seg_id = get_le<std::uint32_t>(b, o + lkae::seg_id);
    m.e[i].offset = get_le<std::uint64_t>(b, o + lkae::offset);
    m.e[i].stored_len = get_le<std::uint64_t>(b, o + lkae::stored_len);
    m.e[i].gen = get_le<std::uint64_t>(b, o + lkae::gen);
    m.e[i].gen_slot = get_le<std::uint64_t>(b, o + lkae::gen_slot);
    if (auto r = check_lookup_ack_entry(m.e[i]); !r) return r.error();
  }
  m.tlvs = b.subspan(fixed);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- PUT_BEGIN ------------------------------------------------------------------------
WireResult<std::size_t> encode_put_begin(const PutBegin& m, std::span<std::byte> out) {
  if (m.n < 1 || m.n > kMaxPutKeys) return malformed("put_begin: n");
  const std::size_t fixed = kPutBeginFixed + m.n * kPutBeginEntry;
  if (auto r = room(out, fixed); !r) return r.error();
  put_bytes(out, pb::scope_id, m.scope_id);
  put_le<std::uint16_t>(out, pb::n, m.n);
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kPutBeginFixed + i * kPutBeginEntry;
    put_bytes(out, o + pbe::key_hash, m.e[i].key_hash);
    put_bytes(out, o + pbe::parent_hash, m.e[i].parent_hash);
    put_le<std::uint64_t>(out, o + pbe::chain_pos, m.e[i].chain_pos);
    put_le<std::uint64_t>(out, o + pbe::stored_len, m.e[i].stored_len);
  }
  return finish(out, fixed, m.tlvs);
}
WireResult<PutBegin> decode_put_begin(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::PUT_BEGIN); !r) return r.error();
  if (auto r = need_len(b, kPutBeginFixed); !r) return r.error();
  PutBegin m;
  get_bytes(b, pb::scope_id, m.scope_id);
  m.n = get_le<std::uint16_t>(b, pb::n);
  if (m.n < 1 || m.n > kMaxPutKeys) return malformed("put_begin: n");
  if (!zero_at(b, pb::z, 6)) return malformed("put_begin: z");
  const std::size_t fixed = kPutBeginFixed + m.n * kPutBeginEntry;
  if (auto r = need_len(b, fixed); !r) return r.error();
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kPutBeginFixed + i * kPutBeginEntry;
    get_bytes(b, o + pbe::key_hash, m.e[i].key_hash);
    get_bytes(b, o + pbe::parent_hash, m.e[i].parent_hash);
    m.e[i].chain_pos = get_le<std::uint64_t>(b, o + pbe::chain_pos);
    m.e[i].stored_len = get_le<std::uint64_t>(b, o + pbe::stored_len);
  }
  m.tlvs = b.subspan(fixed);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- PUT_BEGIN_ACK --------------------------------------------------------------------
namespace {
WireStatusResult check_put_begin_ack(const PutBeginAck& m) {
  if (m.status > 1) return malformed("put_begin_ack: status");
  if (m.n_mr > kMaxRails) return malformed("put_begin_ack: n_mr");
  if (m.n > kMaxPutKeys) return malformed("put_begin_ack: n");
  for (std::size_t r = m.n_mr; r < kMaxRails; ++r) {
    if (m.mr[r].addr != 0 || m.mr[r].len != 0 || m.mr[r].rkey != 0) return malformed("put_begin_ack: unused mr");
  }
  for (std::size_t i = 0; i < m.n; ++i) {
    const auto& e = m.e[i];
    if (e.status > 1) return malformed("put_begin_ack: entry status");
    if (e.status == 1 ? e.mr_index >= m.n_mr : (e.mr_index != 0 || e.offset != 0)) {
      return malformed("put_begin_ack: entry mr_index/offset");
    }
  }
  return {};
}
}  // namespace
WireResult<std::size_t> encode_put_begin_ack(const PutBeginAck& m, std::span<std::byte> out) {
  if (auto r = check_put_begin_ack(m); !r) return r.error();
  const std::size_t fixed = kPutBeginAckFixed + m.n * kPutBeginAckEntry;
  if (auto r = room(out, fixed); !r) return r.error();
  put_le<std::uint64_t>(out, pba::put_id, m.put_id);
  put_le<std::uint8_t>(out, pba::status, m.status);
  put_le<std::uint8_t>(out, pba::n_mr, m.n_mr);
  put_le<std::uint16_t>(out, pba::n, m.n);
  put_le<std::uint32_t>(out, pba::retry_after_ms, m.retry_after_ms);
  for (std::size_t r = 0; r < kMaxRails; ++r) {
    const std::size_t o = pba::mr + r * kMrEntry;
    put_le<std::uint64_t>(out, o + mre::addr, m.mr[r].addr);
    put_le<std::uint64_t>(out, o + mre::len, m.mr[r].len);
    put_le<std::uint32_t>(out, o + mre::rkey, m.mr[r].rkey);
  }
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kPutBeginAckFixed + i * kPutBeginAckEntry;
    put_le<std::uint8_t>(out, o + pbae::status, m.e[i].status);
    put_le<std::uint8_t>(out, o + pbae::mr_index, m.e[i].mr_index);
    put_le<std::uint64_t>(out, o + pbae::offset, m.e[i].offset);
  }
  return finish(out, fixed, m.tlvs);
}
WireResult<PutBeginAck> decode_put_begin_ack(const FrameHeader& h, std::span<const std::byte> b) {
  if (auto r = check_header(h, Op::PUT_BEGIN_ACK); !r) return r.error();
  if (auto r = need_len(b, kPutBeginAckFixed); !r) return r.error();
  PutBeginAck m;
  m.put_id = get_le<std::uint64_t>(b, pba::put_id);
  m.status = get_le<std::uint8_t>(b, pba::status);
  m.n_mr = get_le<std::uint8_t>(b, pba::n_mr);
  m.n = get_le<std::uint16_t>(b, pba::n);
  m.retry_after_ms = get_le<std::uint32_t>(b, pba::retry_after_ms);
  for (std::size_t r = 0; r < kMaxRails; ++r) {
    const std::size_t o = pba::mr + r * kMrEntry;
    m.mr[r].addr = get_le<std::uint64_t>(b, o + mre::addr);
    m.mr[r].len = get_le<std::uint64_t>(b, o + mre::len);
    m.mr[r].rkey = get_le<std::uint32_t>(b, o + mre::rkey);
    if (get_le<std::uint32_t>(b, o + mre::z) != 0) return malformed("put_begin_ack: mr z");
  }
  if (m.n > kMaxPutKeys) return malformed("put_begin_ack: n");  // before sizing the entry loop
  const std::size_t fixed = kPutBeginAckFixed + m.n * kPutBeginAckEntry;
  if (auto r = need_len(b, fixed); !r) return r.error();
  for (std::size_t i = 0; i < m.n; ++i) {
    const std::size_t o = kPutBeginAckFixed + i * kPutBeginAckEntry;
    m.e[i].status = get_le<std::uint8_t>(b, o + pbae::status);
    m.e[i].mr_index = get_le<std::uint8_t>(b, o + pbae::mr_index);
    if (!zero_at(b, o + pbae::z, 6)) return malformed("put_begin_ack: entry z");
    m.e[i].offset = get_le<std::uint64_t>(b, o + pbae::offset);
  }
  if (auto r = check_put_begin_ack(m); !r) return r.error();
  m.tlvs = b.subspan(fixed);
  if (auto r = check_tlv_tail(h.flags, m.tlvs); !r) return r.error();
  return m;
}

// ---- Ticket ---------------------------------------------------------------------------
WireResult<std::size_t> encode_ticket(const Ticket& t, std::span<std::byte> out) {
  if (t.cls > 2) return malformed("ticket: class");
  if (auto r = room(out, kTicketSize); !r) return r.error();
  put_le<std::uint8_t>(out, tk::cls, t.cls);
  put_bytes(out, tk::id, t.id);
  return kTicketSize;
}
WireResult<Ticket> decode_ticket(std::span<const std::byte> in) {
  if (in.size() != kTicketSize) return malformed("ticket: length");
  if (get_le<std::uint8_t>(in, tk::ver) != 0) return malformed("ticket: version");
  Ticket t;
  t.cls = get_le<std::uint8_t>(in, tk::cls);
  if (t.cls > 2) return malformed("ticket: class");
  if (get_le<std::uint16_t>(in, tk::z) != 0) return malformed("ticket: z");
  get_bytes(in, tk::id, t.id);
  return t;
}

}  // namespace miracache::proto
