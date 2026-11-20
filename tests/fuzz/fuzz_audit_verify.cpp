// SPDX-License-Identifier: Apache-2.0
// libFuzzer target: the audit-log verifier on attacker-controlled bytes must never crash, hang or
// read out of bounds. The input is verified (a) as one file and (b) split on 0x00 bytes into
// several files (cross-file link rules). Seeds: proto/golden/audit_v1 (tests/fuzz/corpus/audit).
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "control/audit.h"

using namespace miracache::control;

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  const std::string in(reinterpret_cast<const char*>(data), size);
  (void)audit_verify({{"fuzz", in}});
  std::vector<AuditFileBytes> files;
  std::size_t pos = 0;
  while (pos <= in.size() && files.size() < 8) {
    const std::size_t z = in.find('\0', pos);
    const std::size_t end = z == std::string::npos ? in.size() : z;
    files.push_back({"audit-" + std::to_string(files.size() + 1) + ".jsonl", in.substr(pos, end - pos)});
    if (z == std::string::npos) break;
    pos = z + 1;
  }
  (void)audit_verify(files);
  return 0;
}
