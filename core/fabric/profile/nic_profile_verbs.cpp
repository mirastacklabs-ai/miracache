// SPDX-License-Identifier: Apache-2.0
// Verbs-backed glue: probe the device, load the registry, select, log. One call for the memory
// node and the client; everything else is the pure code in nic_profile.cpp.
#include "fabric/profile/nic_profile.h"

namespace miracache::fabric::profile {

Expected<Selection> select_for_device(const std::string& device, const std::string& profiles_file, const Overrides& ov,
                                      probe::NicFacts* facts_out) {
  std::string name = device;
  if (name.empty()) {
    auto all = probe::list_devices();
    if (all.empty()) return Error{ErrorCode::NotFound, "nic profile: no RDMA devices"};
    name = all.front();
  }
  auto facts = probe::probe_device(name);
  if (!facts) return facts.error();
  const Registry* reg = nullptr;
  Expected<Registry> file = Error{ErrorCode::NotFound, ""};
  if (!profiles_file.empty()) {
    file = load_registry_file(profiles_file);  // an explicit file that fails to load is an error, never a fallback
    if (!file) return file.error();
    reg = &*file;
  } else {
    auto b = builtin_registry();
    if (!b) return b.error();
    reg = *b;
  }
  auto sel = select(*reg, *facts, ov);
  if (!sel) return sel.error();
  log_selection(*sel, *facts);
  if (facts_out != nullptr) *facts_out = std::move(*facts);
  return sel;
}

}  // namespace miracache::fabric::profile
