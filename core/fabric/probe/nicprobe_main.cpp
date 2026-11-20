// SPDX-License-Identifier: Apache-2.0
// mira-nicprobe [--json] [--profiles FILE] [device...]: report NIC facts, capability trials, the
// "usable for miracache" verdict and the matched NIC profile (profile, verified flag, fixed
// operating point, firmware check). Exit 0 when every probed device is usable, 1 when any is not
// (or when a device has no matching profile), 2 on usage or open errors.
//
// --json: the probe object plus an additive "profiles" array (one entry per device: "device",
// and either "profile":{...} or "error":"..."); schema_version is unchanged.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "fabric/probe/nic_probe.h"
#include "fabric/profile/nic_profile.h"

int main(int argc, char** argv) {
  using namespace miracache::fabric::probe;
  namespace prof = miracache::fabric::profile;
  bool json = false;
  std::string profiles_file;
  std::vector<std::string> names;
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--json") == 0) json = true;
    else if (std::strcmp(argv[i], "--profiles") == 0 && i + 1 < argc) profiles_file = argv[++i];
    else if (argv[i][0] == '-') {
      std::fprintf(stderr, "usage: mira-nicprobe [--json] [--profiles FILE] [device...]\n");
      return 2;
    } else names.emplace_back(argv[i]);
  }
  if (names.empty()) names = list_devices();
  if (names.empty()) {
    std::fprintf(stderr, "mira-nicprobe: no RDMA devices\n");
    return 2;
  }
  std::vector<NicFacts> all;
  for (const auto& n : names) {
    auto f = probe_device(n);
    if (!f) {
      std::fprintf(stderr, "mira-nicprobe: %s: %s\n", n.c_str(), f.error().context);
      return 2;
    }
    all.push_back(std::move(*f));
  }
  // An explicit profiles file that does not load is an error (never a silent fallback to the built-in one).
  miracache::Expected<prof::Registry> file = miracache::Error{miracache::ErrorCode::NotFound, ""};
  const prof::Registry* reg = nullptr;
  if (!profiles_file.empty()) {
    file = prof::load_registry_file(profiles_file);
    if (!file) {
      std::fprintf(stderr, "mira-nicprobe: %s: %s\n", profiles_file.c_str(), file.error().context);
      return 2;
    }
    reg = &*file;
  } else {
    auto b = prof::builtin_registry();
    if (!b) {
      std::fprintf(stderr, "mira-nicprobe: built-in profiles: %s\n", b.error().context);
      return 2;
    }
    reg = *b;
  }

  bool all_matched = true;
  std::string out = json ? to_json(all) : to_table(all);
  if (json) {
    while (!out.empty() && (out.back() == '\n' || out.back() == ' ')) out.pop_back();
    if (!out.empty() && out.back() == '}') out.pop_back();
    out += ",\"profiles\":[";
    for (std::size_t i = 0; i < all.size(); ++i) {
      auto sel = prof::select(*reg, all[i]);
      if (!sel) all_matched = false;
      out += (i ? ",{\"device\":\"" : "{\"device\":\"") + all[i].device + "\",";
      out += sel ? "\"profile\":" + prof::selection_to_json(*sel)
                 : std::string("\"error\":\"") + sel.error().context + "\"";
      out += '}';
    }
    out += "]}\n";
  } else {
    for (const auto& f : all) {
      auto sel = prof::select(*reg, f);
      out += "== " + f.device + ": NIC profile ==\n";
      if (sel) out += prof::selection_to_text(*sel);
      else {
        all_matched = false;
        out += std::string("  none: ") + sel.error().context + "\n";
      }
    }
  }
  std::fputs(out.c_str(), stdout);
  for (const auto& f : all) {
    if (!evaluate(f).usable) return 1;
  }
  return all_matched ? 0 : 1;
}
