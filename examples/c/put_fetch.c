/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Store one block in the memory nodes, look it up, fetch it back and compare, through the C ABI.
 *
 *   example_c_put_fetch /path/to/client.toml
 *
 * Every call returns MIRA_OK (0) or an error code; a data-path failure is a per-key status in a completion,
 * not an error code. Buffers named in a put or fetch stay yours and must stay valid until the completion for
 * that ticket is returned by mira_poll().
 */
#include <miracache/miracache.h>

#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define BLOCK (64 * 1024)

static uint8_t src[BLOCK];
static uint8_t dst[BLOCK];

/* Waits until the completion of `ticket` arrives; returns its status for the one key in `*status`. */
static int wait_for(mira_client* c, uint64_t ticket, uint8_t* status) {
  for (int i = 0; i < 150; i++) { /* 150 x 200 ms = 30 s */
    struct pollfd pfd = {mira_event_fd(c), POLLIN, 0}; /* readable whenever completions are pending */
    poll(&pfd, 1, 200);
    mira_completion done[8];
    uint8_t statuses[64];
    size_t n = mira_poll(c, done, 8, statuses, sizeof statuses);
    if (n == MIRA_POLL_ERROR) return -1;
    for (size_t k = 0; k < n; k++)
      if (done[k].ticket == ticket && done[k].n_keys == 1) {
        *status = statuses[done[k].status_off];
        return 0;
      }
  }
  return -1;
}

int main(int argc, char** argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: %s client.toml\n", argv[0]);
    return 2;
  }
  int rc;

  /* 1. Connect to the memory nodes named in the config (it also names the deployment secret file). */
  mira_client* c = NULL;
  rc = mira_client_open(argv[1], NULL, &c);
  if (rc != MIRA_OK) {
    fprintf(stderr, "open: %s (%s)\n", mira_strerror(rc), mira_last_error());
    return 1;
  }

  /* 2. Register the buffers once; the client copies through its own pool, so any memory works. */
  uint64_t r_src = 0, r_dst = 0;
  if (mira_attach_region(c, src, sizeof src, &r_src) != MIRA_OK || mira_attach_region(c, dst, sizeof dst, &r_dst) != MIRA_OK) {
    fprintf(stderr, "attach_region: %s\n", mira_last_error());
    mira_client_close(c);
    return 1;
  }
  for (size_t i = 0; i < sizeof src; i++) src[i] = (uint8_t)((i * 31 + 5) & 0xFF);

  /* 3. Derive the scope: who may read this block. An engine passes its namespace digest (32 bytes) and
   * the raw key of each KV-cache group's chain root; here one group (0) with a fixed example namespace. */
  uint8_t ns[32];
  for (int i = 0; i < 32; i++) ns[i] = (uint8_t)i;
  static const uint8_t root[] = "example-root";
  mira_scope* scope = NULL;
  rc = mira_derive(c, MIRA_ENGINE_VLLM, ns, root, sizeof root - 1, 0, &scope);
  if (rc != MIRA_OK) {
    fprintf(stderr, "derive: %s (%s)\n", mira_strerror(rc), mira_last_error());
    mira_client_close(c);
    return 1;
  }

  /* 4. One key: the raw block key (the engine's block hash) and where its bytes live in a region. */
  static const uint8_t raw[] = "example-block-0";
  mira_key key;
  memset(&key, 0, sizeof key); /* parent NULL/0: a chain root */
  key.raw = raw;
  key.raw_len = sizeof raw - 1;
  key.len = BLOCK;

  uint64_t ticket = 0;
  uint8_t status = 0;
  int ok = 0;

  /* Store (put), then look up, then fetch. The timeout argument is in ms (0 = the default, 10 s). */
  key.region = r_src;
  if (mira_put(c, scope, &key, 1, 10000, &ticket) != MIRA_OK || wait_for(c, ticket, &status) != 0 || status != MIRA_KEY_COMMITTED) {
    fprintf(stderr, "store failed (%s)\n", mira_last_error());
    goto done;
  }
  printf("store:  committed\n");

  if (mira_lookup_nb(c, scope, &key, 1, 10000, &ticket) != MIRA_OK || wait_for(c, ticket, &status) != 0 || status != MIRA_KEY_HIT) {
    fprintf(stderr, "lookup did not hit\n");
    goto done;
  }
  printf("lookup: hit\n");

  key.region = r_dst;
  if (mira_fetch(c, scope, &key, 1, 10000, &ticket) != MIRA_OK || wait_for(c, ticket, &status) != 0 || status != MIRA_KEY_HIT) {
    fprintf(stderr, "fetch failed (%s)\n", mira_last_error());
    goto done;
  }
  if (memcmp(src, dst, BLOCK) != 0) {
    fprintf(stderr, "fetched bytes differ\n");
    goto done;
  }
  printf("fetch:  hit, %d bytes identical\n", BLOCK);
  ok = 1;

done:
  mira_scope_free(scope);
  mira_client_close(c); /* drains in-flight work and frees the client */
  if (ok) printf("PASS\n");
  return ok ? 0 : 1;
}
