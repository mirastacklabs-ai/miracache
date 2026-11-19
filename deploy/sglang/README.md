# SGLang with miracache (L3 via HiCache `dynamic` backend)

No SGLang patch. Config flags only. Check them before launch:

```
python -m miracache.check_sglang_config --extra-config deploy/sglang/extra-config.example.json --page-size 64
```

(`python -m miracache.preflight --engine sglang ...` runs the same rules.)

```
python -m sglang.launch_server --model-path <model> --tp <N> \
  --page-size 64 \
  --enable-hierarchical-cache \
  --hicache-storage-backend dynamic \
  --hicache-storage-backend-extra-config "$(cat deploy/sglang/extra-config.example.json)"
```

Required:

| Setting | Why |
|---|---|
| `--hicache-storage-backend dynamic` | loads our class from the extra config |
| `backend_name`, `module_path: miracache.sglang`, `class_name: MiraHiCacheStorage` | the dynamic hook |
| `interface_v1: 1` | otherwise SGLang does not use the zero-copy page functions |
| `"miracache": {"config": "/etc/miracache/client.toml"}` | path to the client config passed to `Client.open(config, secret_file=None)`. Add `"secret_file": "/path"` only when `client.toml` does not name one. The adapter refuses to start without `miracache.config` |
| `hicache_storage_pass_prefix_keys: true` | SGLang's own flag. Gives the adapter `prefix_keys`, so the chain root `(prefix_keys + keys)[0]` is known. Default is false. SGLang removes it before our class is built, so the adapter cannot see it: `check_sglang_config` is where a missing flag is caught. At runtime the adapter counts `root_batches` / `batches` (`get_stats()`) and logs a warning if the first 64 batches were all root batches |
| `miracache_expect_prefix_keys: true` | our own flag, the operator's promise that the line above is set. The adapter refuses to start without it. **Set BOTH.** With both set, `prefix_keys` None or empty means "batch starts at the chain root" |
| `--page-size >= 16` (64 recommended) | smaller pages make objects too small for RDMA; the adapter refuses at host-pool registration (startup) |
| default `--hicache-storage-key-scheme` (`rank-suffix`) | keys are treated as opaque; do not set `unified` |
| PP = 1 | pipeline parallelism is unsupported in v1; the adapter refuses when the SGLang config has `pp_size > 1` |

Optional keys (all in the same `--hicache-storage-backend-extra-config` JSON):

| Key | Default | Meaning |
|---|---|---|
| `miracache_stage_pages` | 16 | staging region size in pages; larger batches are split |
| `miracache_lookup_deadline_ms` | 50 | client deadline of one batched `batch_exists` lookup (the adapter waits this plus a small grace); expiry is a miss |
| `miracache_metrics_port` (alias `metrics_port`) | 0 (off) | serve `GET /metrics` (Prometheus text: `miracache_client_*` plus `miracache_adapter_*` / `miracache_recompute_*`) on `port + tp_rank`; any other path is 404 |
| `miracache_metrics_host` (alias `metrics_host`) | `127.0.0.1` | bind address of that endpoint |
| `ns_fields` | `{}` | extra values folded into `ns` (a JSON object; string keys, JSON values). SGLang does not pass these to a storage backend, so copy them in (same string) when you set the flag to anything but `auto` / `main`: `model_revision` (= `--revision`; pin a commit, `main` can differ between hosts), `quantization` (= `--quantization`), `quantization_param_path` (= `--quantization-param-path`), `dtype` (= `--dtype`), `kv_cache_dtype` (= `--kv-cache-dtype`: SGLang stores `fp8_e4m3` and `fp8_e5m2` alike as `uint8`), `model_override_args` (= `--json-model-override-args`) and `model_path` (= `--model-path`, only when `--served-model-name` differs from it: SGLang gives the backend the served name, which does not name the weights). Without them, hosts that differ in one of these would share KV computed differently, so **preflight fails** until they are mirrored. Example: an answers file such as `sglang-on.json` |

For vLLM the same endpoint is configured on the `MiraTier` entry: `metrics_port` (0 = off), `metrics_host`, `metrics_rank` (default from `MIRACACHE_RANK` / `LOCAL_RANK` / `RANK`).

Host-pool layouts: every layout `get_page_buffer_meta` returns at the pin is supported (MHA page-first / page-first-direct / page-head / layer-first, MLA page-first / page-first-direct / layer-first / page-first-kv-split). One miracache block per page = all of the page's buffers concatenated in the order SGLang returns them (page-major for every layout; checked at registration). I/O goes through a staging buffer (copy in on store, copy out on load). An op that outlives its wait never gets its staging buffer back: the adapter attaches a fresh one and fails the rest of that batch (counters `io_timeout`, `quarantined`).

**What a refusal does (SGLang 18d862f).** The adapter refuses (raises `MiraRefusal`, a clear message naming the setting) when PP>1, `miracache_expect_prefix_keys` or `miracache.config` is missing, the client cannot be opened, page size < 16, SGLang passes no model name, or `ns_fields` is not a JSON object of JSON values. SGLang does not catch it: `attach_storage_backend` cleans up and re-raises (`python/sglang/srt/managers/cache_controller.py:723-747`; construction at `:664`, registration at `:667`; `backend_factory.py:166-170` logs and re-raises), and at startup the `HiCacheController` constructor calls it with no handler for this error (`:432-442` only rewraps `ValueError`). So **SGLang fails to start**; it does not fall back to running without L3. Fix the config (run `check_sglang_config`) or drop `--hicache-storage-backend` to run without L3. After a successful start, data-path errors never raise: they are misses.

Hosts with a different SGLang version, TP / attention-CP / DCP rank or size, head split, served model name, KV dtype, page size, buffer layout or `ns_fields` have a different `ns` and miss silently (the start-up line `miracache sglang ns fingerprint <8 hex>` lets you compare hosts). So an SGLang upgrade starts with an empty L3, as it does for the engine's own caches; a miracache upgrade does not (golden-vector tests pin the `ns` bytes).
Hybrid / sidecar-pool models (`*_v2` calls) are not supported in v1: they always miss.
