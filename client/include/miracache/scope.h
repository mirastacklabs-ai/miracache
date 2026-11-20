// SPDX-License-Identifier: Apache-2.0
// ScopeProvider interface (spec rev 5.1 §2.6). v1 surface only: no caps(),
// controller calls, homes or carrier. Only ScopeId and KeyHash (opaque 32 B values) ever go
// to a memory node; KeySource and everything behind it stays in the adapter.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

#include "crypto/block_codec.h"  // ScopeId, KeyHash
#include "crypto/secret.h"       // Dek
#include "util/expected.h"

namespace miracache {

enum class EngineKind : std::uint8_t { Vllm = 1, Sglang = 2 };

using Hash256 = std::array<std::uint8_t, 32>;

// Per-request input: the namespace digest and one raw chain-root key per KV-cache group.
struct RequestMeta {
  EngineKind engine = EngineKind::Vllm;
  Hash256 ns{};
  std::vector<std::vector<std::byte>> roots;  // roots[group]; none empty
};

// Per-block key material for one (kver, ns). No I/O.
class KeySource {
 public:
  virtual ~KeySource() = default;
  virtual Expected<Dek> dek_for(std::span<const std::byte> raw_key) const = 0;
  virtual Expected<KeyHash> key_hash(std::span<const std::byte> raw_key) const = 0;
};

struct ScopeKeys {
  std::vector<ScopeId> scopes;            // scopes[group]
  std::shared_ptr<const KeySource> keys;  // shared so it outlives the provider call
  std::uint32_t kver = 0;
};

class ScopeProvider {
 public:
  virtual ~ScopeProvider() = default;
  virtual Expected<ScopeKeys> derive(const RequestMeta& meta) const = 0;
};

}  // namespace miracache
