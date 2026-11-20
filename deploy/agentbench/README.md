# agentbench configs

`on.json` / `off.json` (vLLM) and `sglang-on.json` / `sglang-off.json` (SGLang) are agentbench deploy answers. Each pair is identical except for the miracache tier (the local CPU/host-memory tier is the same in both, so the comparison is fair). `tests/python/test_check_vllm_config.py` and `tests/python/test_sglang_check_config.py` check that the "on" files pass our config checks, the "off" files have no miracache tier, and the pairs differ only there.

## Plan: vLLM then SGLang, for every model, full test cases

Run the full test cases for every model, vLLM first and then SGLang. Fill these fields when the GPU models are known (all are placeholders until the GPU models are chosen; the JSON files carry only keys agentbench knows, so this note lives here). Keep `sglang-on.json` and `sglang-off.json` identical except the miracache storage backend. In SGLang `--hicache-size` is GB per rank (32 matches vLLM `cpu_bytes_to_use`):

- model, revision, served_name, tp, max_len, gpu_memory
- corpus / `target_sessions`
- host-cache size: vLLM `cpu_bytes_to_use`, SGLang `--hicache-size` (GB per rank). Set it the same for on and off.

SGLang "on" requires (checked by `python -m miracache.check_sglang_config` and `miracache.preflight --engine sglang`): `--page-size` >= 16 (64 used), pp = 1, `--hicache-storage-backend dynamic`, and in `--hicache-storage-backend-extra-config`: `module_path` `miracache.sglang`, `class_name` `MiraHiCacheStorage`, `backend_name`, `interface_v1` 1, `hicache_storage_pass_prefix_keys` and `miracache_expect_prefix_keys` true, `miracache.config` `/etc/miracache/client.toml`. See `deploy/sglang/README.md`.

The engine contract check (`tools/ci/engine_contract.sh`) feeds each file's engine flags, built the way agentbench's `deploy_inference.py` builds them, to the real vLLM 0.33.0 and SGLang 0.5.23 argument parsers (no engine start), and checks the `TieringOffloadingSpec` / `miracache.vllm_tier` resolution. agentbench ignores unknown answers keys (it reads only the keys it asks for), but the files keep to known keys anyway.

Memory nodes: these files configure the engine side only; each memory node of an agentbench run uses `deploy/two-host/memnode.toml`. Its `[node] state_dir` (default `/var/lib/miracache`) holds the node's identity and must be a directory the memory node's user owns, not group- or world-writable, one per memory node. A memory node run as non-root needs `sudo install -d -m 0700 -o <user> /var/lib/miracache` or its own `state_dir` (see `deploy/two-host/README.md`, "One `state_dir` per memory node").

## Versions and the wheel

- **One version source:** `pyproject.toml` (`0.3.0`). `CMakeLists.txt` and the `miracache==...` pin in the "on" files must match it; `tools/pkg/build_wheel.sh` refuses to build when they differ.
- **Engine pins:** every file carries `"version"` (the key agentbench reads, `deploy_inference.py` `RESOLUTION_ANSWER_KEYS`): vLLM `0.33.0`, SGLang `0.5.23`. Without it agentbench picks a recipe or the latest build.
- **The wheel is on no index.** Build it on the machine that matches the GPU host (x86_64 Linux), inside the dev container, then point the installer at the directory:

```
tools/dev/run.sh -- tools/pkg/build_wheel.sh release     # -> build/wheel/miracache-0.3.0-py3-none-linux_x86_64.whl
# copy build/wheel/ to the GPU host (e.g. /opt/miracache-wheels), then, before running agentbench's deploy step:
export UV_FIND_LINKS=/opt/miracache-wheels               # agentbench installs pip_extras with `uv pip install`; it inherits this
export PIP_FIND_LINKS=/opt/miracache-wheels              # same for plain pip
# by hand, into an engine venv:
pip install --no-index --find-links /opt/miracache-wheels miracache==0.3.0
```

With `--no-index` pip cannot fetch anything else; the wheel has no dependencies (`dependencies = []`).
