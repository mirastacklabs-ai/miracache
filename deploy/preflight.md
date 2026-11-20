# mira-preflight and node-prep

Both are pure Python, need no engine import, and run from `python/` (`PYTHONPATH=python`).

## mira-preflight

```
python -m miracache.preflight --engine vllm   --engine-args "<cli string>" --secret-file /etc/miracache/keys/secret [--json]
python -m miracache.preflight --engine sglang --answers answers.json --secret-file ...
python -m miracache.preflight fingerprint --engine ... --engine-args ...      # this host's parity fingerprint
python -m miracache.preflight compare host-a.json host-b.json ...             # exit 1 on any mismatch, names the field
```

Exit: 0 ok, 1 hard fail, 2 warnings only with `--strict-warnings` (or a usage error).
Other flags: `--provider engine-native|et-gateway`, `--engine-version`, `--env K=V` (default: this process), `--root` (fake fs for node facts), `--no-node-facts`, `--min-memlock-mib`, `--nic-report` (output of `mira-nicprobe --json`, attached verbatim; its findings are not yet graded pass/warn/fail).

| Result | Check |
|---|---|
| fail | vLLM `kv_load_failure_policy` != `recompute`, at the top level of `--kv-transfer-config` or in the MiraTier entry (the tier cannot see the top-level value, so the entry repeats it; the tier refuses to start without it); hash algo != `sha256_cbor` (`sha256` too); `canonical_layout` not true; PP/CP > 1; bad block size; unsupported engine version |
| fail | SGLang `--page-size` < 16 (or unknown); `hicache_storage_pass_prefix_keys` or `miracache_expect_prefix_keys` not true (or absent); PP > 1; `interface_v1` missing; key scheme not `rank-suffix` |
| fail | engine-native secret file missing, group/world accessible (anything beyond owner), malformed, or `current` kver missing |
| fail | request logging with `--provider et-gateway` |
| warn | request logging with engine-native; SGLang page size 16-63; no hugepages reserved; memlock soft limit below `--min-memlock-mib` (default 1024); no MiraTier in the vLLM kv-transfer config |

vLLM rules live in `check_vllm_config` + `vllm/compat.py`; SGLang rules in `sglang/storage.py:settings_problems` (shared with the adapter's constructor).

Secret file format (text, mode exactly 0600; same rules as the client's `load_secret_file` in `client/scope/engine_native.cpp`): lines `current = <kver>` and `<kver> = <64 hex chars>` (32 bytes), `#` comment lines, blanks ignored. Key bytes are never printed.

Fingerprint fields: `pythonhashseed`, `block_size`, `lookahead_slots` (`--num-lookahead-slots`), `lora_paths` (sorted set), `model_id`, `engine_version`, `tp_size`, `engine`, `provider`, `hash_algo`, `canonical_layout`, `kv_cache_dtype` (vLLM); `page_size`, `key_scheme`, `ns_fields`, `interface_v1` (SGLang). Hosts that differ never share keys; they miss silently, so compare before launch.

## node-prep

```
python -m miracache.node_prep [--hugepage-size 1G|2M] [--hugepage-gib N] [--memlock-user U] [--json]
python -m miracache.node_prep --apply --yes        # root only
```

Dry run by default: prints the plan (hugepage reservation, hugetlbfs mount, memlock limits file, `rdma_rxe`/`siw` status, IOMMU `iommu=pt` hint). Software RDMA modules are only listed, never loaded. `--apply` is refused without `--yes` and without root; it never touches 1 GiB reservations (boot-time kernel cmdline, reboot required) or modules. Satisfied items are omitted (idempotent).
