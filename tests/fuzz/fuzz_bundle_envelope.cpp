// SPDX-License-Identifier: Apache-2.0
// libFuzzer target: the bundle receive path on attacker-controlled bytes must never crash,
// hang or read out of bounds. The input is used as
//   (a) a whole envelope (format parse, role binding and signature verify against a fixed trust set),
//   (b) if its format parses: the sec and body TOML it carries, parsed without the signature gate
//       so the fuzzer reaches the schema code,
//   (c) a split of the raw bytes into a sec part and a body part, and
//   (d) a trust file.
// Seeds: the committed goldens under proto/golden/bundle_v1/ (copied into tests/fuzz/corpus/bundle).
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <string_view>

#include "control/bundle.h"
#include "control/trust_keys.h"

using namespace miracache::control;

namespace {
// Public keys of the test seeds (publish 0x01..0x20, security 0x21..0x40) as in the goldens.
const char kTrust[] =
    "[[key]]\npublic = \"79b5562e8fe654f94078b112e8a98ba7901f853ae695bed7e0e3910bad049664\"\nroles = [\"publish\"]\n"
    "[[key]]\npublic = \"e7f162a10bec559afea195e4dce84b69568d5d2cb0963eb446c0685e2b17f2f0\"\nroles = [\"security\"]\n";
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  static const TrustKeys trust = [] {
    auto t = parse_trust_keys(kTrust);
    if (t.has_value()) return std::move(t.value());
    // The placeholder keys above must stay parseable; if not, fall back to a one-key file.
    std::abort();
  }();
  const std::string_view in(reinterpret_cast<const char*>(data), size);

  if (auto env = parse_envelope(in); env.has_value()) {
    (void)verify_envelope(env.value(), trust);
    (void)parse_bundle(env.value());
  }
  (void)open_bundle(in, trust);

  if (size > 0) {
    const std::size_t cut = data[0] % size;
    (void)parse_sec(in.substr(0, cut));
    (void)parse_body(in.substr(cut));
  }
  (void)parse_trust_keys(in);
  return 0;
}
