// SPDX-License-Identifier: Apache-2.0
// Verbs-backed collector for NicFacts. Unprivileged, read-only apart from throw-away
// allocations (one PD, two MWs) that are freed before return.
#include <arpa/inet.h>
#include <infiniband/verbs.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>

#include "fabric/probe/nic_probe.h"

namespace miracache::fabric::probe {

namespace {

using protocol::Protocol;

std::string driver_name(const std::string& dev) {
  const std::string path = "/sys/class/infiniband/" + dev + "/device/driver";
  char buf[256];
  const ssize_t n = ::readlink(path.c_str(), buf, sizeof buf - 1);
  if (n <= 0) return {};
  buf[n] = '\0';
  const char* slash = std::strrchr(buf, '/');
  return slash != nullptr ? slash + 1 : buf;
}

std::string state_name(ibv_port_state s) {
  switch (s) {
    case IBV_PORT_NOP: return "nop";
    case IBV_PORT_DOWN: return "down";
    case IBV_PORT_INIT: return "init";
    case IBV_PORT_ARMED: return "armed";
    case IBV_PORT_ACTIVE: return "active";
    case IBV_PORT_ACTIVE_DEFER: return "active-defer";
  }
  return "unknown";
}

std::uint32_t mtu_bytes(ibv_mtu m) {
  switch (m) {
    case IBV_MTU_256: return 256;
    case IBV_MTU_512: return 512;
    case IBV_MTU_1024: return 1024;
    case IBV_MTU_2048: return 2048;
    case IBV_MTU_4096: return 4096;
  }
  return 0;
}

// active_speed code x active_width -> Mb/s (approximate IB signalling rates).
std::uint32_t speed_mbps(std::uint8_t speed, std::uint8_t width) {
  std::uint32_t per_lane = 0;
  switch (speed) {
    case 1: per_lane = 2500; break;
    case 2: per_lane = 5000; break;
    case 4: case 8: per_lane = 10000; break;
    case 16: per_lane = 14000; break;
    case 32: per_lane = 25000; break;
    case 64: per_lane = 50000; break;
    case 128: per_lane = 100000; break;
    default: return 0;
  }
  std::uint32_t lanes = 0;
  switch (width) {
    case 1: lanes = 1; break;
    case 2: lanes = 4; break;
    case 4: lanes = 8; break;
    case 8: lanes = 12; break;
    case 16: lanes = 2; break;
    default: return 0;
  }
  return per_lane * lanes;
}

std::string gid_text(const ibv_gid& g, bool* v4) {
  static constexpr unsigned char kMapped[12] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff};
  *v4 = std::memcmp(g.raw, kMapped, sizeof kMapped) == 0;
  char b[INET6_ADDRSTRLEN] = {};
  if (*v4) {
    std::snprintf(b, sizeof b, "::ffff:%u.%u.%u.%u", g.raw[12], g.raw[13], g.raw[14], g.raw[15]);
  } else {
    ::inet_ntop(AF_INET6, g.raw, b, sizeof b);
  }
  return b;
}

const char* gid_type_name(std::uint32_t t) {
  switch (t) {
    case IBV_GID_TYPE_IB: return "ib";
    case IBV_GID_TYPE_ROCE_V1: return "roce-v1";
    case IBV_GID_TYPE_ROCE_V2: return "roce-v2";
  }
  return "unknown";
}

PortFacts probe_port(ibv_context* ctx, std::uint8_t port) {
  PortFacts p;
  p.port = port;
  ibv_port_attr pa{};
  if (ibv_query_port(ctx, port, &pa) != 0) {
    p.state = "unknown";
    p.link_layer = "unspecified";
    return p;
  }
  p.state = state_name(pa.state);
  p.link_layer = pa.link_layer == IBV_LINK_LAYER_ETHERNET     ? "ethernet"
                 : pa.link_layer == IBV_LINK_LAYER_INFINIBAND ? "infiniband"
                                                              : "unspecified";
  p.speed_mbps = speed_mbps(pa.active_speed, pa.active_width);
  p.active_mtu = mtu_bytes(pa.active_mtu);
  p.max_mtu = mtu_bytes(pa.max_mtu);
  const int n = std::min(pa.gid_tbl_len, 256);
  for (int i = 0; i < n; ++i) {
    ibv_gid_entry e{};
    if (ibv_query_gid_ex(ctx, port, static_cast<std::uint32_t>(i), &e, 0) != 0) continue;
    static constexpr unsigned char kZero[16] = {};
    if (std::memcmp(e.gid.raw, kZero, 16) == 0) continue;
    GidEntry g;
    g.index = static_cast<std::uint32_t>(i);
    g.gid = gid_text(e.gid, &g.ipv4_mapped);
    g.type = gid_type_name(e.gid_type);
    p.gids.push_back(std::move(g));
  }
  return p;
}

TrialResult try_mw(ibv_pd* pd, ibv_mw_type type) {
  errno = 0;
  ibv_mw* mw = ibv_alloc_mw(pd, type);
  if (mw == nullptr) {
    const int e = errno != 0 ? errno : ENOSYS;
    return {Trial::Unsupported, std::strerror(e)};
  }
  (void)ibv_dealloc_mw(mw);
  return {Trial::Supported, {}};
}

}  // namespace

std::vector<std::string> list_devices() {
  std::vector<std::string> out;
  int n = 0;
  ibv_device** l = ibv_get_device_list(&n);
  if (l == nullptr) return out;
  for (int i = 0; i < n; ++i) out.emplace_back(ibv_get_device_name(l[i]));
  ibv_free_device_list(l);
  std::sort(out.begin(), out.end());
  return out;
}

Expected<NicFacts> probe_device(const std::string& name) {
  int n = 0;
  ibv_device** l = ibv_get_device_list(&n);
  if (l == nullptr || n == 0) {
    if (l != nullptr) ibv_free_device_list(l);  // empty list is still allocated
    return Error{ErrorCode::NotFound, "no RDMA devices"};
  }
  ibv_context* ctx = nullptr;
  for (int i = 0; i < n; ++i) {
    if (name == ibv_get_device_name(l[i])) {
      ctx = ibv_open_device(l[i]);
      break;
    }
  }
  ibv_free_device_list(l);
  if (ctx == nullptr) return Error{ErrorCode::NotFound, "RDMA device not found or not openable"};

  NicFacts f;
  f.device = name;
  f.driver = driver_name(name);
  f.protocol = protocol::detect(ctx);
  switch (ctx->device->transport_type) {
    case IBV_TRANSPORT_IB: f.transport = "ib"; break;
    case IBV_TRANSPORT_IWARP: f.transport = "iwarp"; break;
    default: f.transport = "unknown"; break;
  }

  ibv_device_attr_ex ex{};
  ibv_device_attr base{};
  const ibv_device_attr* a = nullptr;
  if (ibv_query_device_ex(ctx, nullptr, &ex) == 0) {
    a = &ex.orig_attr;
    f.odp = (ex.odp_caps.general_caps & IBV_ODP_SUPPORT) != 0;
  } else if (ibv_query_device(ctx, &base) == 0) {
    a = &base;
  }
  std::uint8_t phys_ports = 0;
  if (a != nullptr) {
    f.vendor_id = a->vendor_id;
    f.vendor_part_id = a->vendor_part_id;
    f.hw_ver = a->hw_ver;
    f.node_guid = be64toh(a->node_guid);
    f.fw_version = a->fw_ver;
    phys_ports = a->phys_port_cnt;
    DeviceLimits& d = f.limits;
    d.max_qp = static_cast<std::uint32_t>(a->max_qp);
    d.max_cq = static_cast<std::uint32_t>(a->max_cq);
    d.max_cqe = static_cast<std::uint32_t>(a->max_cqe);
    d.max_mr = static_cast<std::uint32_t>(a->max_mr);
    d.max_mr_size = a->max_mr_size;
    d.max_pd = static_cast<std::uint32_t>(a->max_pd);
    d.max_sge = static_cast<std::uint32_t>(a->max_sge);
    d.max_sge_rd = static_cast<std::uint32_t>(a->max_sge_rd);
    d.max_qp_wr = static_cast<std::uint32_t>(a->max_qp_wr);
    d.page_size_cap = a->page_size_cap;
    d.max_qp_rd_atom = static_cast<std::uint32_t>(a->max_qp_rd_atom);
    d.max_qp_init_rd_atom = static_cast<std::uint32_t>(a->max_qp_init_rd_atom);
  }
  for (std::uint8_t p = 1; p <= phys_ports; ++p) f.ports.push_back(probe_port(ctx, p));

  ibv_pd* pd = ibv_alloc_pd(ctx);
  if (pd != nullptr) {
    f.mw_type1 = try_mw(pd, IBV_MW_TYPE_1);
    f.mw_type2 = try_mw(pd, IBV_MW_TYPE_2);
    ibv_dealloc_pd(pd);
  } else {
    f.mw_type1 = f.mw_type2 = {Trial::NotTried, "ibv_alloc_pd failed"};
  }
  // ibv_reg_dmabuf_mr needs a dma-buf fd from a GPU/accelerator driver. We carry no GPU
  // dependency, so there is nothing to register; the result stays "not tried" (v2, recorded).
  f.dmabuf = {Trial::NotTried, "no dma-buf source available"};

  ibv_close_device(ctx);
  return f;
}

}  // namespace miracache::fabric::probe
