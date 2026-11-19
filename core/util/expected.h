// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <utility>
#include <variant>

#include "util/check.h"
#include "util/error.h"

namespace miracache {

// Minimal std::expected stand-in (libstdc++ 13 only ships it for C++23).
// Replace with std::expected once the toolchain floor allows -std=c++23.
// Misuse (value() on an error, error() on a value) traps unconditionally, in every
// build type; core is compiled with -fno-exceptions.
template <typename T, typename E = Error>
class [[nodiscard]] Expected {
 public:
  Expected(T value) : v_(std::in_place_index<0>, std::move(value)) {}
  Expected(E error) : v_(std::in_place_index<1>, std::move(error)) {}

  bool has_value() const noexcept { return v_.index() == 0; }
  explicit operator bool() const noexcept { return has_value(); }

  T& value() & { MIRACACHE_CHECK(has_value()); return *std::get_if<0>(&v_); }
  const T& value() const& { MIRACACHE_CHECK(has_value()); return *std::get_if<0>(&v_); }
  T&& value() && { MIRACACHE_CHECK(has_value()); return std::move(*std::get_if<0>(&v_)); }
  T* operator->() { return &value(); }
  const T* operator->() const { return &value(); }
  T& operator*() & { return value(); }
  const T& operator*() const& { return value(); }

  const E& error() const { MIRACACHE_CHECK(!has_value()); return *std::get_if<1>(&v_); }

 private:
  std::variant<T, E> v_;
};

template <typename E>
class [[nodiscard]] Expected<void, E> {
 public:
  Expected() = default;
  Expected(E error) : err_(std::move(error)), ok_(false) {}

  bool has_value() const noexcept { return ok_; }
  explicit operator bool() const noexcept { return ok_; }
  const E& error() const { MIRACACHE_CHECK(!ok_); return err_; }

 private:
  E err_{};
  bool ok_ = true;
};

using Status = Expected<void, Error>;

}  // namespace miracache
