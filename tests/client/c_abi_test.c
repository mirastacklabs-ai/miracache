/* SPDX-License-Identifier: Apache-2.0 */
/* C ABI test: plain C, links libmiracache.so only through miracache.h. */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miracache/miracache.h"

static int failures;
#define CHECK(c)                                                            \
  do {                                                                      \
    if (!(c)) {                                                             \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
      failures++;                                                           \
    }                                                                       \
  } while (0)

#define BLK 100000u
#define NB 3

/* Waits for the completion of `ticket`; returns its kind or -1; statuses into st. */
static int wait_ticket(mira_client* c, uint64_t ticket, uint8_t* st, uint32_t* n) {
  struct pollfd p = {mira_event_fd(c), POLLIN, 0};
  for (int tries = 0; tries < 200; ++tries) {
    mira_completion comp[4];
    uint8_t sb[64];
    size_t got = mira_poll(c, comp, 4, sb, sizeof sb);
    for (size_t i = 0; i < got; ++i) {
      if (comp[i].ticket == ticket) {
        *n = comp[i].n_keys;
        memcpy(st, sb + comp[i].status_off, comp[i].n_keys);
        return (int)comp[i].kind;
      }
    }
    if (got == 0) poll(&p, 1, 100);
  }
  return -1;
}

static void fill_keys(mira_key* k, uint8_t names[NB][8], uint64_t region, const char* tag) {
  for (int i = 0; i < NB; ++i) {
    memset(names[i], 0, 8);
    snprintf((char*)names[i], 8, "%s%d", tag, i);
    memset(&k[i], 0, sizeof k[i]);
    k[i].raw = names[i];
    k[i].raw_len = strlen((char*)names[i]);
    if (i > 0) {
      k[i].parent = names[i - 1];
      k[i].parent_len = strlen((char*)names[i - 1]);
    }
    k[i].chain_pos = (uint64_t)i;
    k[i].region = region;
    k[i].offset = (uint64_t)i * BLK;
    k[i].len = BLK;
  }
}

static void test_basics(void) {
  CHECK(mira_abi_version() == MIRA_ABI_VERSION);
  CHECK(strcmp(mira_strerror(MIRA_OK), "ok") == 0);
  CHECK(strlen(mira_strerror(9999)) > 0);

  mira_client* c = (mira_client*)0x1;
  int rc = mira_client_open("[nodes", NULL, &c);
  CHECK(rc == MIRA_E_CONFIG);
  CHECK(c == NULL);
  CHECK(strlen(mira_last_error()) > 0);
  rc = mira_client_open("/nonexistent/client.toml", NULL, &c);
  CHECK(rc != MIRA_OK);
  CHECK(mira_client_open(NULL, NULL, &c) == MIRA_E_INVALID);
  mira_client_close(NULL);
}

/* Size negotiation and content of mira_client_metrics (after 3 puts, 3 hits, 3 misses). */
static void test_metrics(mira_client* c) {
  CHECK((mira_abi_version() & 0xffffu) >= 1u);
  size_t need = 0;
  CHECK(mira_client_metrics(c, NULL, 0, &need) == MIRA_E_BUFFER);
  CHECK(need > 100);
  char tiny[8];
  size_t need2 = 0;
  CHECK(mira_client_metrics(c, tiny, sizeof tiny, &need2) == MIRA_E_BUFFER && need2 > 0);
  char* buf = malloc(need + 4096);
  size_t got = 0;
  CHECK(mira_client_metrics(c, buf, need + 4096, &got) == MIRA_OK);
  CHECK(got >= need && strlen(buf) + 1 == got);
  char* exact = malloc(got);
  size_t again = 0;
  int rc = mira_client_metrics(c, exact, got, &again);
  CHECK(rc == MIRA_OK || rc == MIRA_E_BUFFER);
  free(exact);
  CHECK(strstr(buf, "# TYPE miracache_client_fetch_seconds histogram") != NULL);
  CHECK(strstr(buf, "miracache_client_put_ops_total{result=\"committed\"} 3\n") != NULL);
  CHECK(strstr(buf, "miracache_client_fetch_ops_total{result=\"hit\"} 3\n") != NULL);
  CHECK(strstr(buf, "miracache_client_fetch_ops_total{result=\"miss\"} 3\n") != NULL);
  CHECK(strstr(buf, "miracache_client_lookup_keys_total{result=\"hit\"} 3\n") != NULL);
  CHECK(strstr(buf, "miracache_client_inflight{op=\"fetch\"} 0\n") != NULL);
  CHECK(mira_client_metrics(NULL, buf, 10, &got) == MIRA_E_INVALID);
  /* ABI 1.2: the loopback node is not a wire node, so it reports no block limit. */
  size_t checked = 99;
  CHECK(mira_check_block_size(c, 1u << 20, &checked) == MIRA_OK && checked == 0);
  CHECK(mira_check_block_size(NULL, 1, &checked) == MIRA_E_INVALID);
  free(buf);
}

static void test_roundtrip_and_miss(void) {
  mira_client* c = NULL;
  CHECK(mira_client_open_loopback(NULL, &c) == MIRA_OK);
  CHECK(c != NULL);
  CHECK(mira_event_fd(c) >= 0);

  uint8_t ns[32], root[] = "root-key";
  memset(ns, 7, sizeof ns);
  mira_scope* sc = NULL;
  CHECK(mira_derive(c, MIRA_ENGINE_VLLM, ns, root, sizeof root - 1, 0, &sc) == MIRA_OK);

  uint8_t* src = malloc(NB * BLK);
  uint8_t* dst = malloc(NB * BLK);
  for (size_t i = 0; i < NB * BLK; ++i) src[i] = (uint8_t)(i * 31 + 5);
  memset(dst, 0xAA, NB * BLK);
  uint64_t rs = 0, rd = 0;
  CHECK(mira_attach_region(c, src, NB * BLK, &rs) == MIRA_OK);
  CHECK(mira_attach_region(c, dst, NB * BLK, &rd) == MIRA_OK);

  uint8_t names[NB][8];
  mira_key k[NB];
  uint64_t t = 0;
  uint8_t st[8];
  uint32_t n = 0;

  fill_keys(k, names, rs, "k");
  CHECK(mira_put(c, sc, k, NB, 5000, &t) == MIRA_OK && t != 0);
  CHECK(wait_ticket(c, t, st, &n) == MIRA_OP_PUT);
  CHECK(n == NB);
  for (uint32_t i = 0; i < n; ++i) CHECK(st[i] == MIRA_KEY_COMMITTED);

  CHECK(mira_lookup_nb(c, sc, k, NB, 5000, &t) == MIRA_OK);
  CHECK(wait_ticket(c, t, st, &n) == MIRA_OP_LOOKUP);
  for (uint32_t i = 0; i < n; ++i) CHECK(st[i] == MIRA_KEY_HIT);

  fill_keys(k, names, rd, "k");
  CHECK(mira_fetch(c, sc, k, NB, 5000, &t) == MIRA_OK);
  CHECK(wait_ticket(c, t, st, &n) == MIRA_OP_FETCH);
  CHECK(n == NB);
  for (uint32_t i = 0; i < n; ++i) CHECK(st[i] == MIRA_KEY_HIT);
  CHECK(memcmp(src, dst, NB * BLK) == 0);

  /* Miss: unknown keys report MISS and the destination is zeroed. */
  memset(dst, 0xAA, NB * BLK);
  fill_keys(k, names, rd, "nokey");
  CHECK(mira_fetch(c, sc, k, NB, 5000, &t) == MIRA_OK);
  CHECK(wait_ticket(c, t, st, &n) == MIRA_OP_FETCH);
  for (uint32_t i = 0; i < n; ++i) CHECK(st[i] == MIRA_KEY_MISS);
  int zero = 1;
  for (size_t i = 0; i < NB * BLK; ++i) zero &= dst[i] == 0;
  CHECK(zero);

  test_metrics(c);

  /* Argument checks. */
  k[0].offset = NB * BLK;
  CHECK(mira_fetch(c, sc, k, 1, 5000, &t) == MIRA_E_INVALID);
  k[0].offset = 0;
  k[0].region = 999;
  CHECK(mira_fetch(c, sc, k, 1, 5000, &t) == MIRA_E_INVALID);
  CHECK(mira_detach_region(c, rd) == MIRA_OK);
  CHECK(mira_detach_region(c, rd) == MIRA_E_INVALID);

  mira_scope_free(sc);
  mira_client_close(c);
  free(src);
  free(dst);
}

static void test_close_with_inflight(void) {
  mira_client* c = NULL;
  CHECK(mira_client_open_loopback(NULL, &c) == MIRA_OK);
  uint8_t ns[32], root[] = "root-key";
  memset(ns, 9, sizeof ns);
  mira_scope* sc = NULL;
  CHECK(mira_derive(c, MIRA_ENGINE_VLLM, ns, root, sizeof root - 1, 0, &sc) == MIRA_OK);
  uint8_t* buf = calloc(NB, BLK);
  uint64_t r = 0;
  CHECK(mira_attach_region(c, buf, NB * BLK, &r) == MIRA_OK);
  uint8_t names[NB][8];
  mira_key k[NB];
  fill_keys(k, names, r, "f");
  uint64_t t;
  for (int i = 0; i < 20; ++i) CHECK(mira_fetch(c, sc, k, NB, 60000, &t) == MIRA_OK);
  CHECK(mira_put(c, sc, k, NB, 60000, &t) == MIRA_OK);
  mira_client_close(c); /* must return: aborts and drains everything, joins workers */
  mira_scope_free(sc);  /* scopes outlive the client safely */
  free(buf);            /* only after close: no op touches it any more */
}

/* A status_buf too small for the first completion is a distinct error, not 0. */
static void test_poll_small_status_buf(void) {
  mira_client* c = NULL;
  CHECK(mira_client_open_loopback(NULL, &c) == MIRA_OK);
  uint8_t ns[32], root[] = "root-key";
  memset(ns, 5, sizeof ns);
  mira_scope* sc = NULL;
  CHECK(mira_derive(c, MIRA_ENGINE_VLLM, ns, root, sizeof root - 1, 0, &sc) == MIRA_OK);
  uint8_t* buf = calloc(NB, BLK);
  uint64_t r = 0;
  CHECK(mira_attach_region(c, buf, NB * BLK, &r) == MIRA_OK);
  uint8_t names[NB][8];
  mira_key k[NB];
  fill_keys(k, names, r, "s");
  uint64_t t = 0;
  CHECK(mira_lookup_nb(c, sc, k, NB, 5000, &t) == MIRA_OK);
  struct pollfd p = {mira_event_fd(c), POLLIN, 0};
  mira_completion comp[2];
  uint8_t tiny[1], big[16];
  size_t got = 0;
  for (int i = 0; i < 40 && got == 0; ++i) {
    got = mira_poll(c, comp, 2, tiny, sizeof tiny);
    if (got == 0) poll(&p, 1, 100);
  }
  CHECK(got == MIRA_POLL_ERROR);
  CHECK(strlen(mira_last_error()) > 0);
  got = 0;
  for (int i = 0; i < 40 && got == 0; ++i) {
    got = mira_poll(c, comp, 2, big, sizeof big);
    if (got == 0) poll(&p, 1, 100);
  }
  CHECK(got == 1 && comp[0].n_keys == NB && comp[0].ticket == t);
  mira_scope_free(sc);
  mira_client_close(c);
  free(buf);
}

int main(void) {
  test_poll_small_status_buf();
  test_basics();
  test_roundtrip_and_miss();
  test_close_with_inflight();
  if (failures) {
    fprintf(stderr, "c_abi_test: %d failure(s)\n", failures);
    return 1;
  }
  puts("c_abi_test: OK");
  return 0;
}
