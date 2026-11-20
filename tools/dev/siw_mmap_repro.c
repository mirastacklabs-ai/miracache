// Reproducer for the siw0 per-process queue-mapping limit (see the workstation setup guide).
// In the dev container: clang-18 -O1 -o /tmp/ep tools/dev/siw_mmap_repro.c -lrdmacm -libverbs
//   for d in 16 256 1024 4096; do /tmp/ep $d 0; /tmp/ep $d 1; done   (tools/dev/run.sh --rdma)
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>
int main(int argc, char** argv) {
  int depth = atoi(argv[1]), probe = atoi(argv[2]), n = 0;
  struct ibv_context** l = rdma_get_devices(&n);
  struct ibv_context* c = NULL;
  for (int i = 0; i < n; ++i) if (!strcmp(ibv_get_device_name(l[i]->device), "siw0")) c = l[i];
  // probe=2: create QPs (never destroyed) on one shared 4096-entry CQ: max_send_wr = depth, max_recv_wr = argv[3] (default 16).
  int rq = argc > 3 ? atoi(argv[3]) : 16;
  struct ibv_pd* qpd = ibv_alloc_pd(c);
  struct ibv_cq* shared = probe == 2 ? ibv_create_cq(c, 4096, NULL, NULL, 0) : NULL;
  for (int i = 0; i < 400; ++i) {
    if (probe == 3) {  // a fabric: PD + comp channel + CQ(depth) + argv[3] QPs (sq 128, rq 16); argv[4]=1 destroys it again
      int k = argc > 3 ? atoi(argv[3]) : 3, destroy = argc > 4 ? atoi(argv[4]) : 0;
      struct ibv_pd* pd = ibv_alloc_pd(c);
      struct ibv_comp_channel* ch = ibv_create_comp_channel(c);
      errno = 0;
      struct ibv_cq* cq = ibv_create_cq(c, depth, NULL, ch, 0);
      if (!cq) { printf("fabric cq %d: failed at fabric %d errno %d\n", depth, i, errno); return 2; }
      struct ibv_qp* qps[64];
      for (int j = 0; j < k && j < 64; ++j) {
        struct ibv_qp_init_attr qa = {0}; qa.send_cq = qa.recv_cq = cq; qa.qp_type = IBV_QPT_RC;
        qa.cap.max_send_wr = argc > 5 ? atoi(argv[5]) : 128; qa.cap.max_recv_wr = argc > 6 ? atoi(argv[6]) : 16; qa.cap.max_send_sge = qa.cap.max_recv_sge = 1;
        qps[j] = ibv_create_qp(pd, &qa);
        if (!qps[j]) { printf("fabric cq %d: qp %d failed at fabric %d\n", depth, j, i); return 2; }
      }
      if (destroy) { for (int j = 0; j < k && j < 64; ++j) ibv_destroy_qp(qps[j]); ibv_destroy_cq(cq); ibv_destroy_comp_channel(ch); ibv_dealloc_pd(pd); }
      continue;
    }
    if (probe == 2) {
      struct ibv_qp_init_attr qa = {0}; qa.send_cq = qa.recv_cq = shared; qa.qp_type = IBV_QPT_RC;
      qa.cap.max_send_wr = depth; qa.cap.max_recv_wr = rq; qa.cap.max_send_sge = qa.cap.max_recv_sge = 1;
      errno = 0;
      if (!ibv_create_qp(qpd, &qa)) { printf("qp sq %d rq %d: failed at iteration %d errno %d\n", depth, rq, i, errno); return 2; }
      continue;
    }
    if (probe) {
      struct ibv_pd* pd = ibv_alloc_pd(c);
      struct ibv_cq* pc = ibv_create_cq(c, 16, NULL, NULL, 0);
      if (!pc) { printf("depth %d probe=%d: probe cq failed at iteration %d errno %d\n", depth, probe, i, errno); return 2; }
      struct ibv_qp_init_attr qa = {0}; qa.send_cq = qa.recv_cq = pc; qa.qp_type = IBV_QPT_RC;
      qa.cap.max_send_wr = qa.cap.max_recv_wr = 16; qa.cap.max_send_sge = qa.cap.max_recv_sge = 1; qa.cap.max_inline_data = 256;
      struct ibv_qp* qp = ibv_create_qp(pd, &qa); if (qp) ibv_destroy_qp(qp);
      ibv_destroy_cq(pc); ibv_dealloc_pd(pd);
    }
    struct ibv_comp_channel* ch = ibv_create_comp_channel(c);
    errno = 0;
    if (!ibv_create_cq(c, depth, NULL, ch, 0)) { printf("depth %d probe=%d: cq failed at iteration %d errno %d\n", depth, probe, i, errno); return 2; }
  }
  printf("depth %d probe=%d: 400 ok\n", depth, probe);
  return 0;
}
