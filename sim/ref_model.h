// SPDX-License-Identifier: Apache-2.0
// Reference model for the store simulator: what a client may and must see.
//
// The model is a SUPERSET of the store's contents. It adds a key only when PUT_DONE says
// Committed and removes it only on an explicit INVALIDATE (matching generation), scope or
// principal drop, or an observed MISS. The store may drop more on its own (LRU eviction,
// idle expiry, reaping); the model cannot see that. So:
//   may_hit():  a HIT for a key outside the model is a violation (NoForeignScopeRead,
//               NoStaleGenerationRead, NoOrphanTail), as is a HIT on the wrong incarnation.
//   must_hit(): only meaningful when nothing but explicit operations can remove keys
//               ("roomy" seeds); the key must be visible while its scope was touched
//               recently enough to be certainly alive.
// Content identity ("AEAD stand-in"): every key incarnation has an instance number; the
// payload is the 8-byte tag mix(principal, scope, key, instance) repeated, so a read of
// the wrong key, scope, principal or incarnation (or a torn read) differs from expected().
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "store/store.h"

namespace miracache::sim {

using store::KeyHash;
using store::PrincipalId;
using store::ScopeId;

inline std::uint64_t mix64(std::uint64_t x) {
  x += 0x9e3779b97f4a7c15ull;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ull;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebull;
  return x ^ (x >> 31);
}

inline std::uint64_t tag_of(PrincipalId p, const ScopeId& s, const KeyHash& k, std::uint64_t inst) {
  std::uint64_t h = mix64(p);
  for (std::uint8_t b : s) h = mix64(h ^ b);
  for (std::uint8_t b : k) h = mix64(h ^ b);
  return mix64(h ^ inst);
}

inline std::vector<std::byte> payload_of(std::uint64_t tag, std::size_t len) {
  std::vector<std::byte> v(len);
  for (std::size_t i = 0; i < len; ++i) v[i] = static_cast<std::byte>(tag >> ((i % 8) * 8));
  return v;
}

class RefModel {
 public:
  struct Key {
    std::uint64_t inst = 0;
    std::uint64_t len = 0;
    std::uint64_t gen = 0;  // 0 = not yet observed
    KeyHash parent{};
    std::int64_t born_ns = 0;  // when the model last knew the key was alive
  };
  struct Scope {
    std::map<KeyHash, Key> keys;
    std::int64_t touch_ns = -1;  // a time at which the store certainly touched the scope
    // Keys born before this may have died with an expired-and-recreated scope.
    std::int64_t floor_ns = 0;
  };

  explicit RefModel(Nanos idle_ttl = Nanos{INT64_MAX / 4}) : ttl_(idle_ttl) {}

  // PUT_DONE(Committed). Returns "" or a violation.
  std::string commit(PrincipalId p, const ScopeId& s, const KeyHash& k, const KeyHash& parent, std::uint64_t inst,
                     std::uint64_t len, Nanos now) {
    static const KeyHash kZero{};
    Scope& sc = scopes_[{p, s}];
    if (parent != kZero && !sc.keys.count(parent)) return "NoOrphanTail: committed block whose parent is not visible";
    sc.keys[k] = Key{inst, len, 0, parent, now.count()};
    touch(sc, now);
    return {};
  }

  const Key* find(PrincipalId p, const ScopeId& s, const KeyHash& k) const {
    auto it = scopes_.find({p, s});
    if (it == scopes_.end()) return nullptr;
    auto kt = it->second.keys.find(k);
    return kt == it->second.keys.end() ? nullptr : &kt->second;
  }

  // LOOKUP HIT of (p,s,k) with generation `gen`. Returns "" or a violation.
  std::string hit(PrincipalId p, const ScopeId& s, const KeyHash& k, std::uint64_t gen, Nanos now) {
    auto it = scopes_.find({p, s});
    if (it == scopes_.end() || !it->second.keys.count(k)) return "HIT outside the visible set (foreign/stale/orphan)";
    Key& key = it->second.keys.at(k);
    if (key.gen != 0 && key.gen != gen) return "NoStaleGenerationRead: generation changed within one incarnation";
    key.gen = gen;
    touch(it->second, now);
    key.born_ns = now.count();
    return {};
  }

  // The store answered MISS for a readable key: it is no longer reachable by a NEW lookup,
  // and neither is its subtree. The cause is not visible to the model (LRU eviction, scope
  // lapse past idle_ttl, scope eviction). Spec 01-design-spec.md section 7 (implicit scopes,
  // line ~649): "An expired or unknown scope means its blocks are unreachable; they are
  // reaped scope.reap_grace_ms after expiry", and a lapse changes no state word. So a fetch
  // admitted BEFORE the MISS may still pass its seq check on the old incarnation until the
  // reap: those incarnations are remembered in `lapsed_` and stay readable (with the right
  // bytes) only to such fetches. Explicit INVALIDATE / drop_scope / drop_principal are NOT
  // recorded here: spec 8.3/8.4 turn the block ZOMBIE or FREE at once, so any seq pass on
  // one of those is a violation.
  void miss(PrincipalId p, const ScopeId& s, const KeyHash& k) {
    auto it = scopes_.find({p, s});
    if (it == scopes_.end()) return;
    std::vector<KeyHash> order{k};
    if (!it->second.keys.count(k)) return;
    for (std::size_t i = 0; i < order.size(); ++i)
      for (const auto& [kk, v] : it->second.keys)
        if (v.parent == order[i]) order.push_back(kk);
    for (const auto& x : order)
      if (auto kt = it->second.keys.find(x); kt != it->second.keys.end()) lapsed_.insert({p, s, x, kt->second.inst});
    remove_subtree(p, s, k);
  }

  // Was this incarnation removed only by a MISS (lapse/eviction), so that an earlier-admitted
  // fetch may legitimately still read it?
  bool lapsed(PrincipalId p, const ScopeId& s, const KeyHash& k, std::uint64_t inst) const {
    return lapsed_.count({p, s, k, inst}) != 0;
  }

  // INVALIDATE accepted by the store (Status OK). Removes the subtree iff the generation is
  // the one observed for the current incarnation.
  void invalidate(PrincipalId p, const ScopeId& s, const KeyHash& k, std::uint64_t gen) {
    const Key* key = find(p, s, k);
    if (key != nullptr && gen != 0 && key->gen == gen) remove_subtree(p, s, k);
  }

  void drop_scope(PrincipalId p, const ScopeId& s) { scopes_.erase({p, s}); }
  void drop_principal(PrincipalId p) {
    for (auto it = scopes_.begin(); it != scopes_.end();) it = it->first.first == p ? scopes_.erase(it) : std::next(it);
  }

  // Roomy seeds only: the key was committed, nothing but explicit ops removes keys, and the
  // scope was touched within idle_ttl, so a readable LOOKUP must hit.
  bool must_hit(PrincipalId p, const ScopeId& s, const KeyHash& k, Nanos now) const {
    auto it = scopes_.find({p, s});
    if (it == scopes_.end() || it->second.touch_ns < 0) return false;
    auto kt = it->second.keys.find(k);
    if (kt == it->second.keys.end() || kt->second.born_ns < it->second.floor_ns) return false;
    return now.count() - it->second.touch_ns < ttl_.count();
  }

  std::size_t n_keys() const {
    std::size_t n = 0;
    for (const auto& [id, sc] : scopes_) n += sc.keys.size();
    return n;
  }

 private:
  void touch(Scope& sc, Nanos now) const {
    if (sc.touch_ns >= 0 && now.count() - sc.touch_ns >= ttl_.count()) sc.floor_ns = now.count();
    sc.touch_ns = now.count();
  }
  void remove_subtree(PrincipalId p, const ScopeId& s, const KeyHash& k) {
    auto it = scopes_.find({p, s});
    if (it == scopes_.end()) return;
    auto& keys = it->second.keys;
    std::vector<KeyHash> order{k};
    for (std::size_t i = 0; i < order.size(); ++i)
      for (const auto& [kk, v] : keys)
        if (v.parent == order[i]) order.push_back(kk);
    for (const auto& x : order) keys.erase(x);
  }

  Nanos ttl_;
  std::set<std::tuple<PrincipalId, ScopeId, KeyHash, std::uint64_t>> lapsed_;
  std::map<std::pair<PrincipalId, ScopeId>, Scope> scopes_;
};

}  // namespace miracache::sim
