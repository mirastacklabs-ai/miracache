// SPDX-License-Identifier: Apache-2.0
// libFuzzer target for the wire v0 frame layer and storage decoders. Anything a decoder
// accepts must re-encode to exactly the same bytes.
// Input: byte 0 selects the decoder (mod 7: 0 frame+message, 1 superblock, 2 segment
// meta, 3 run entry, 4 ticket, 5 scope record, 6 scope region header); the rest is the payload (zero-padded for the fixed-size ones).
// Seed corpus: tests/fuzz/corpus/wire/ (the golden frames, prefixed with selector 0).
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "proto/messages.h"
#include "proto/scope_record.h"
#include "proto/storage_layout.h"

using namespace miracache::proto;

namespace {

void must(bool ok) {
  if (!ok) std::abort();
}

template <std::size_t N>
std::array<std::byte, N> load(const std::uint8_t* data, std::size_t size) {
  std::array<std::byte, N> in{};
  std::memcpy(in.data(), data, size < N ? size : N);
  return in;
}

template <typename M, typename Dec, typename Enc>
void roundtrip_body(const Frame& f, Dec dec, Enc enc) {
  auto m = dec(f.h, f.body);
  if (!m) return;
  std::vector<std::byte> out(kMaxBodyLen);
  auto n = enc(*m, std::span<std::byte>(out));
  must(static_cast<bool>(n));
  must(*n == f.body.size() && std::memcmp(out.data(), f.body.data(), *n) == 0);
}

void fuzz_frame(std::span<const std::byte> in) {
  auto f = decode_frame(in);
  if (!f) return;
  std::vector<std::byte> out(in.size());
  auto n = encode_frame(f->h, f->body, out);
  must(static_cast<bool>(n) && *n == in.size() && std::memcmp(out.data(), in.data(), in.size()) == 0);
  (void)check_opcode(f->h.type);
  if ((f->h.flags & flag::ERROR) != 0) {
    if (auto e = decode_error_reply(f->h, f->body)) {
      std::vector<std::byte> re(in.size());
      auto rn = encode_error_reply_frame(f->h, *e, re);
      must(static_cast<bool>(rn) && *rn == in.size() && std::memcmp(re.data(), in.data(), in.size()) == 0);
    }
    return;
  }
  switch (static_cast<Op>(f->h.type)) {
    case Op::RENEW: roundtrip_body<Renew>(*f, decode_renew, encode_renew); break;
    case Op::RENEW_ACK: roundtrip_body<RenewAck>(*f, decode_renew_ack, encode_renew_ack); break;
    case Op::RELEASE: roundtrip_body<Release>(*f, decode_release, encode_release); break;
    case Op::INVALIDATE: roundtrip_body<Invalidate>(*f, decode_invalidate, encode_invalidate); break;
    case Op::INVALIDATE_ACK: roundtrip_body<InvalidateAck>(*f, decode_invalidate_ack, encode_invalidate_ack); break;
    case Op::PUT_COMMIT: roundtrip_body<PutCommit>(*f, decode_put_commit, encode_put_commit); break;
    case Op::PUT_DONE: roundtrip_body<PutDone>(*f, decode_put_done, encode_put_done); break;
    case Op::PUT_CANCEL: roundtrip_body<PutCancel>(*f, decode_put_cancel, encode_put_cancel); break;
    case Op::HELLO: roundtrip_body<Hello>(*f, decode_hello, encode_hello); break;
    case Op::HELLO_ACK: roundtrip_body<HelloAck>(*f, decode_hello_ack, encode_hello_ack); break;
    case Op::SEG_TABLE: roundtrip_body<SegTable>(*f, decode_seg_table, encode_seg_table); break;
    case Op::PING: roundtrip_body<Ping>(*f, decode_ping, encode_ping); break;
    case Op::PONG: roundtrip_body<Pong>(*f, decode_pong, encode_pong); break;
    case Op::GOAWAY: roundtrip_body<Goaway>(*f, decode_goaway, encode_goaway); break;
    case Op::STATS: roundtrip_body<Stats>(*f, decode_stats, encode_stats); break;
    case Op::STATS_ACK: roundtrip_body<StatsAck>(*f, decode_stats_ack, encode_stats_ack); break;
    case Op::LOOKUP: roundtrip_body<Lookup>(*f, decode_lookup, encode_lookup); break;
    case Op::LOOKUP_ACK: roundtrip_body<LookupAck>(*f, decode_lookup_ack, encode_lookup_ack); break;
    case Op::PUT_BEGIN: roundtrip_body<PutBegin>(*f, decode_put_begin, encode_put_begin); break;
    case Op::PUT_BEGIN_ACK: roundtrip_body<PutBeginAck>(*f, decode_put_begin_ack, encode_put_begin_ack); break;
    default: break;
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const unsigned sel = data[0] % 7;
  ++data;
  --size;
  switch (sel) {
    case 0: {
      std::vector<std::byte> in(size);
      if (size) std::memcpy(in.data(), data, size);
      fuzz_frame(in);
      break;
    }
    case 1: {
      const auto in = load<kSuperblockSize>(data, size);
      if (auto s = decode_superblock(in)) {
        std::array<std::byte, kSuperblockSize> out;
        must(static_cast<bool>(encode(*s, out)) && out == in);
      }
      break;
    }
    case 2: {
      const auto in = load<kSegmentMetaSize>(data, size);
      if (auto m = decode_segment_meta(in)) {
        std::array<std::byte, kSegmentMetaSize> out;
        must(static_cast<bool>(encode(*m, out)) && out == in);
      }
      break;
    }
    case 4: {
      const auto in = load<kTicketSize>(data, size);
      if (auto t = decode_ticket(in)) {
        std::array<std::byte, kTicketSize> out;
        must(static_cast<bool>(encode_ticket(*t, out)) && out == in);
      }
      break;
    }
    case 5: {
      const auto in = load<kScopeRecordSize>(data, size);
      if (auto r = decode_scope_record(in)) {
        std::array<std::byte, kScopeRecordSize> out;
        must(static_cast<bool>(encode(*r, out)) && out == in);
      }
      break;
    }
    case 6: {
      const auto in = load<kScopeRegionHeaderSize>(data, size);
      if (auto h = decode_scope_region_header(in)) {
        std::array<std::byte, kScopeRegionHeaderSize> out;
        must(static_cast<bool>(encode(*h, out)) && out == in);
      }
      break;
    }
    default: {
      const auto in = load<kRunEntrySize>(data, size);
      if (auto r = decode_run_entry(in)) {
        std::array<std::byte, kRunEntrySize> out;
        must(static_cast<bool>(encode(*r, out)) && out == in);
      }
      break;
    }
  }
  return 0;
}
