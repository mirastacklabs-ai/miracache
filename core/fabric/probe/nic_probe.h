// SPDX-License-Identifier: Apache-2.0
// NIC detection and capability probes (spec 4.1/4.2). `NicFacts` is plain data; the
// verbs-backed collector (nic_probe_verbs.cpp) fills it, tests fill it from fixtures. The
// verdict and the renderers are pure functions of the facts, so they run without hardware.
// Capability first, identity second: the verdict never looks at vendor identity.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "fabric/types.h"
#include "fabric/verbs_cm/protocol_rules.h"

namespace miracache::fabric::probe {

// Bump when the --json shape changes incompatibly.
inline constexpr int kJsonSchemaVersion = 1;
// Spec 4.2: the unknown-NIC read depth is 4; a device that cannot keep 4 READs in flight per
// QP is not usable (the transport window would be 1-3 and the slice math in 3.2 breaks).
inline constexpr std::uint32_t kReadDepthFloor = 4;

enum class Trial : std::uint8_t { NotTried, Supported, Unsupported };
const char* to_string(Trial t);

struct TrialResult {
  Trial result = Trial::NotTried;
  std::string detail;  // errno text or the reason it was not tried
};

struct GidEntry {
  std::uint32_t index = 0;
  std::string gid;   // text form, e.g. "::ffff:10.0.0.1"
  std::string type;  // "roce-v2", "roce-v1", "ib" or "unknown"
  bool ipv4_mapped = false;
};

struct PortFacts {
  std::uint8_t port = 1;
  std::string state;             // "active", "down", "init", ...
  std::string link_layer;        // "ethernet" | "infiniband" | "unspecified"
  std::uint32_t speed_mbps = 0;  // active_speed x active_width, 0 when unknown
  std::uint32_t active_mtu = 0;  // bytes
  std::uint32_t max_mtu = 0;
  std::vector<GidEntry> gids;  // populated (non-zero) entries only
};

struct DeviceLimits {
  std::uint32_t max_qp = 0, max_cq = 0, max_mr = 0, max_sge = 0, max_sge_rd = 0, max_qp_wr = 0,
                max_cqe = 0, max_pd = 0;
  std::uint64_t max_mr_size = 0;
  std::uint64_t page_size_cap = 0;        // bitmask of supported MR page sizes
  std::uint32_t max_qp_rd_atom = 0;       // responder: incoming READs per QP (IRD)
  std::uint32_t max_qp_init_rd_atom = 0;  // initiator: outstanding READs per QP (ORD)
};

struct NicFacts {
  std::string device;  // "rxe0"
  std::string driver;  // sysfs driver name, "" when unavailable
  std::uint32_t vendor_id = 0, vendor_part_id = 0, hw_ver = 0;
  std::uint64_t node_guid = 0;
  std::string fw_version;
  std::string transport;  // "ib" | "iwarp" | "unknown" (verbs transport_type)
  protocol::Protocol protocol = protocol::Protocol::Unknown;
  std::vector<PortFacts> ports;
  DeviceLimits limits;
  bool odp = false;                // on-demand paging advertised
  TrialResult mw_type1, mw_type2;  // real ibv_alloc_mw trials (flags lie, R/13 1)
  TrialResult dmabuf;              // ibv_reg_dmabuf_mr: needs a dma-buf source, recorded only (v2)
};

struct Verdict {
  bool usable = false;
  std::vector<std::string> reasons;   // why not usable (empty when usable)
  std::vector<std::string> warnings;  // usable, but worth knowing
};

// Pure. Rules: protocol must be RoCE or iWARP (InfiniBand/unknown refused, same as
// protocol::resolve(Auto)); some port ACTIVE; RoCE needs a RoCE v2 GID; read depth floor on
// both max_qp_rd_atom and max_qp_init_rd_atom. MW / dma-buf / ODP are informational (v2).
Verdict evaluate(const NicFacts& f);

// Stable output. The JSON object has "schema":"miracache.nicprobe" and "schema_version".
std::string to_json(const std::vector<NicFacts>& devices);
std::string to_table(const std::vector<NicFacts>& devices);

// Verbs-backed collection (only when built with MIRACACHE_WITH_VERBS). Never aborts: a
// failed trial is a result, an unopenable device is an Error.
#ifdef MIRACACHE_WITH_VERBS
Expected<NicFacts> probe_device(const std::string& name);
std::vector<std::string> list_devices();
#endif

}  // namespace miracache::fabric::probe
