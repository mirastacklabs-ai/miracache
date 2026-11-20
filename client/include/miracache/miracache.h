/* SPDX-License-Identifier: Apache-2.0 */
/*
 * miracache C ABI. Stable surface for non-C++ callers (the Python binding loads
 * this through ctypes). Rules:
 *   - Every symbol is `mira_*`; opaque handles, POD structs, no C++ types, no callbacks.
 *   - No C++ exception crosses the ABI; every call returns an int status (MIRA_OK == 0) or a
 *     plain value. Data-path failure is a per-key status in a completion, not an error code.
 *   - Thread-safe: any thread may call any function on one client, except that
 *     mira_client_close must not race with other calls on the same client.
 *   - Buffers named in mira_fetch/mira_put stay caller-owned and must stay valid and unmoved
 *     until the completion for that ticket is returned by mira_poll (a completion means the
 *     client no longer touches them).
 *   - mira_abi_version() returns MIRA_ABI_VERSION of the library; callers compare the major
 *     (high 16 bits) with the header they were built against.
 */
#ifndef MIRACACHE_MIRACACHE_H
#define MIRACACHE_MIRACACHE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MIRA_ABI_VERSION 0x00010002u /* major << 16 | minor; 1.1 adds mira_client_metrics, 1.2 mira_check_block_size */

#if defined(__GNUC__)
#define MIRA_API __attribute__((visibility("default")))
#else
#define MIRA_API
#endif

typedef struct mira_client mira_client;
typedef struct mira_scope mira_scope;

/* Return codes. */
enum {
  MIRA_OK = 0,
  MIRA_E_INVALID = 1,      /* bad argument (null, bounds, unknown region/ticket) */
  MIRA_E_CONFIG = 2,       /* configuration rejected; see mira_last_error() */
  MIRA_E_UNSUPPORTED = 3,  /* not available here: e.g. mira_client_open in a build without verbs, or
                              mira_derive on a client that has no scope provider */
  MIRA_E_NOT_FOUND = 4,
  MIRA_E_ACCESS = 5, /* e.g. secret file mode is not 0600 */
  MIRA_E_CLOSED = 6,
  MIRA_E_NOMEM = 7,
  MIRA_E_INTERNAL = 8,
  MIRA_E_BUFFER = 9 /* output buffer too small; *needed says how big (ABI 1.1) */
};

/* Per-key statuses in a completion (same order as the C++ KeyStatus). */
enum {
  MIRA_KEY_HIT = 0,
  MIRA_KEY_MISS = 1,
  MIRA_KEY_COMMITTED = 2,
  MIRA_KEY_SKIPPED = 3,
  MIRA_KEY_REFUSED = 4,
  MIRA_KEY_ABORTED = 5,
  MIRA_KEY_TIMEOUT = 6
};

/* Completion kinds. */
enum { MIRA_OP_LOOKUP = 0, MIRA_OP_FETCH = 1, MIRA_OP_PUT = 2 };

/* Engines for mira_derive. */
enum { MIRA_ENGINE_VLLM = 1, MIRA_ENGINE_SGLANG = 2 };

/* One key of a request. `parent` is empty (NULL/0) for a chain root. For fetch/put the data
 * lives in an attached region at [offset, offset+len): fetch fills it (len == plaintext
 * length), put reads it. Ignored by lookup. */
typedef struct mira_key {
  const uint8_t* raw;
  size_t raw_len;
  const uint8_t* parent;
  size_t parent_len;
  uint64_t chain_pos;
  uint64_t region; /* id from mira_attach_region */
  uint64_t offset;
  uint64_t len;
} mira_key;

/* Provider configuration for mira_client_open. Engine-native scope provider only. */
typedef struct mira_provider_cfg {
  uint32_t struct_size;    /* sizeof(mira_provider_cfg) */
  const char* secret_file; /* overrides scope.secret_file of the config; NULL = use the config's */
} mira_provider_cfg;

/* Options for mira_client_open_loopback (test/lab). */
typedef struct mira_loopback_opts {
  uint32_t struct_size;    /* sizeof(mira_loopback_opts) */
  uint32_t workers;        /* runtime worker threads; 0 = default */
  const uint8_t* secret32; /* 32-byte deployment secret; NULL = a fixed built-in test secret */
} mira_loopback_opts;

typedef struct mira_completion {
  uint64_t ticket;
  uint32_t kind;   /* MIRA_OP_* */
  uint32_t n_keys; /* statuses for this completion: status_buf[status_off .. +n_keys) */
  uint32_t status_off;
  uint32_t reserved;
} mira_completion;

MIRA_API uint32_t mira_abi_version(void);
MIRA_API const char* mira_strerror(int code);
/* Detail text of the last failure on this thread (valid until the next mira_* call on it). */
MIRA_API const char* mira_last_error(void);

/* Production open from a config path or TOML text (client.toml). Validates the config and the
 * provider (an invalid one is MIRA_E_CONFIG / MIRA_E_ACCESS / MIRA_E_NOT_FOUND), then connects
 * to the memory nodes over RDMA: lab mode from [[nodes]], bundle mode from the signed bundle
 * ([control]). Both need a build with verbs (else MIRA_E_UNSUPPORTED). A node whose first connect
 * fails is retried inside the open for up to 2 s (open_settle); the open then succeeds if at
 * least one node is up, logs "N of M memory nodes connected", and connects the rest later in
 * the background. It fails only when no node is up.
 * Connect-time refusals that are worth retrying later (the same open, with backoff) have no code of
 * their own; mira_last_error() names them: the node out of resources or at a connection cap
 * ("out of resources") is MIRA_E_NOMEM; a draining node ("busy") and no memory node listening
 * ("rejected by peer", "link down") are MIRA_E_INTERNAL. A refused ticket is MIRA_E_ACCESS. */
MIRA_API int mira_client_open(const char* config_path_or_toml, const mira_provider_cfg* prov, mira_client** out);
/* Test/lab: a client against an in-process memory node over a simulated fabric. */
MIRA_API int mira_client_open_loopback(const mira_loopback_opts* opts, mira_client** out);
/* Stops accepting work, aborts and drains every in-flight op, frees the client. NULL is ok. */
MIRA_API void mira_client_close(mira_client* c);

/* Registers a caller buffer as a source/destination region. v1 keeps the registration in the
 * client (bounds-checked); the memory is not pinned or RDMA-registered separately (the client
 * copies through its landing pool), so it may be any readable/writable memory. */
MIRA_API int mira_attach_region(mira_client* c, void* base, size_t len, uint64_t* region_out);
MIRA_API int mira_detach_region(mira_client* c, uint64_t region);

/* Engine-native scope derivation for one KV-cache group: `ns` is the 32-byte namespace digest,
 * `root` the raw chain-root key of that group. Free the result with mira_scope_free. */
MIRA_API int mira_derive(mira_client* c, uint32_t engine, const uint8_t ns[32], const uint8_t* root,
                         size_t root_len, uint32_t group, mira_scope** out);
MIRA_API void mira_scope_free(mira_scope* s);

/* Non-blocking submits; each returns a ticket (>0) delivered later by mira_poll. */
MIRA_API int mira_lookup_nb(mira_client* c, const mira_scope* s, const mira_key* keys, size_t n,
                            uint32_t timeout_ms, uint64_t* ticket_out);
MIRA_API int mira_fetch(mira_client* c, const mira_scope* s, const mira_key* keys, size_t n,
                        uint32_t timeout_ms, uint64_t* ticket_out);
MIRA_API int mira_put(mira_client* c, const mira_scope* s, const mira_key* keys, size_t n,
                      uint32_t timeout_ms, uint64_t* ticket_out);

/* Moves up to max_out completions into `out`, per-key statuses into status_buf (capacity
 * status_cap bytes). A completion that does not fit stays queued. Returns the count (0 = none).
 * If the FIRST queued completion's statuses do not fit status_cap, nothing is consumed and
 * MIRA_POLL_ERROR is returned (mira_last_error() says why; the eventfd is NOT re-armed, so the
 * caller must retry with a larger status_buf instead of spinning on a 0). */
#define MIRA_POLL_ERROR ((size_t)-1)
MIRA_API size_t mira_poll(mira_client* c, mira_completion* out, size_t max_out, uint8_t* status_buf,
                          size_t status_cap);
/* Readable (poll(2) POLLIN) whenever completions are pending; owned by the client. -1 on error. */
MIRA_API int mira_event_fd(mira_client* c);

/* ABI 1.1. Writes this client's metrics as Prometheus text exposition 0.0.4 (NUL-terminated) into
 * buf. *needed (if not NULL) always receives the size in bytes including the NUL. Returns MIRA_OK
 * when it fit, MIRA_E_BUFFER when cap was too small (nothing written beyond cap; buf may be NULL
 * with cap 0 to just ask for the size; retry with a bigger buffer, the text may grow between calls). */
MIRA_API int mira_client_metrics(mira_client* c, char* buf, size_t cap, size_t* needed);

/* ABI 1.2. Start-up check for engine adapters: can every connected memory node store one block of
 * block_bytes plaintext bytes (one vLLM chunk slot / one SGLang page)? MIRA_OK: yes, or no connected
 * node reports a limit (*checked = 0; older nodes still refuse oversized puts themselves). MIRA_E_CONFIG:
 * some node cannot; mira_last_error() names the node (ID, hostname, address), the stored size, the
 * node's limit and the store.run_bytes to set. *checked (if not NULL) = nodes that reported a limit. */
MIRA_API int mira_check_block_size(mira_client* c, uint64_t block_bytes, size_t* checked);

#ifdef __cplusplus
}
#endif
#endif /* MIRACACHE_MIRACACHE_H */
