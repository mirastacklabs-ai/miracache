// SPDX-License-Identifier: Apache-2.0
// Memory-region manager for the memory node (spec 6.3).
//
// Fetch side: one RemoteRead MR per arena segment covering ONLY its data runs (never the superblock, header
// table, scope region or slack; its addr is segment base + data_off), plus one for the state_gen array, all
// registered stepwise (step_registration() registers ONE piece per call, because real
// registration of multi-GiB segments takes seconds). The registered prefix grows from
// segment 0; lookups for blocks outside it must MISS (readable()).
// Ingest side: a RemoteWrite MR per put batch group, registered in the ingest PD on
// PUT_BEGIN and deregistered (the fence) before the digest is computed.
// Nothing else is ever registered (deny by default). Single-threaded (store thread).
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

#include "fabric/fabric.h"
#include "store/arena.h"
#include "util/expected.h"

namespace miracache::store {

class MrManager {
 public:
  // One device = one fabric with its fetch and ingest PDs (MRs are per device, so rkeys are per rail; rails on
  // one device share them).
  struct DeviceSpec {
    fabric::Fabric* fabric = nullptr;
    fabric::PdId fetch_pd, ingest_pd;
  };
  MrManager(fabric::Fabric& fabric, Arena& arena, fabric::PdId fetch_pd, fabric::PdId ingest_pd);  // one device
  MrManager(std::vector<DeviceSpec> devices, Arena& arena);                                      // 1..n devices
  ~MrManager();  // deregisters whatever is still registered
  MrManager(const MrManager&) = delete;
  MrManager& operator=(const MrManager&) = delete;

  // Registers the next piece (a segment on the device with the shortest prefix, then the state_gen array on each
  // device). Returns true if it registered something, false when everything is already registered. A registration
  // error is returned and the same step is retried by the next call.
  Expected<bool> step_registration();
  bool registration_complete() const;

  std::size_t n_devices() const { return devs_.size(); }
  // Segments registered on EVERY device (the common prefix).
  std::uint32_t registered_segments() const;
  bool array_registered() const { return registration_complete(); }
  // True if a block in `seg` may be handed to a reader: its segment MR is registered on every device and so is the
  // array MR.
  bool readable(std::uint32_t seg) const;
  const fabric::MemRegion* segment_mr(std::uint32_t seg, std::uint32_t device = 0) const;
  // What a client is told about segment `seg`: addr = the segment BASE (block offsets are relative to it), len = up to
  // the end of the data MR, the same rkey. Only [segment_mr addr, +len) is actually registered, so the NIC refuses the
  // rest. Requires segment_mr(seg, device) != nullptr.
  fabric::MemRegion segment_view(std::uint32_t seg, std::uint32_t device = 0) const;
  const fabric::MemRegion* array_mr(std::uint32_t device = 0) const;

  // RemoteWrite-only region over `buf` in the ingest PD of `device`; the region records its device.
  Expected<fabric::MemRegion> register_write(std::span<std::byte> buf, std::uint32_t device = 0);
  // Deregisters a write MR. On error (Busy) the MR stays registered and live.
  Status fence(const fabric::MemRegion& mr);
  std::size_t live_write_mrs() const { return writes_.size(); }
  bool is_live_write(const fabric::MemRegion& mr) const { return writes_.count(write_key(mr)) != 0; }
  // Live write MRs by write_key().
  const std::map<std::uint64_t, fabric::MemRegion>& write_mrs() const { return writes_; }
  static std::uint64_t write_key(const fabric::MemRegion& mr) {
    return (static_cast<std::uint64_t>(mr.device) << 32) | mr.rkey;
  }

  // Fetch MRs are RemoteRead only, write MRs RemoteWrite only, prefix contiguous.
  Status check_invariants() const;

 private:
  struct Dev {
    fabric::Fabric* fabric = nullptr;
    fabric::PdId fetch_pd, ingest_pd;
    std::vector<fabric::MemRegion> segs;
    std::optional<fabric::MemRegion> array;
  };
  std::span<std::byte> data_span(std::uint32_t seg) const;  // the data runs of `seg`
  Arena& arena_;
  std::vector<Dev> devs_;
  std::map<std::uint64_t, fabric::MemRegion> writes_;  // by write_key
};

}  // namespace miracache::store
