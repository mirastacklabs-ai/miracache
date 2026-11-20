"""KV-tier backend for the agentbench ``kvtier`` stage, over ``miracache.Client``.

agentbench is optional: if importable we subclass its ``KVTierBackend``; otherwise a
structurally identical fallback is defined so this module always imports.

Options (the stage merges backend options + variant options + ``block_size``):
  mode          "loopback" (in-process, no RDMA) | "wire" (default "loopback")
  config        wire only: client.toml path or TOML text (passed to ``Client.open``)
  secret_file   wire only: optional secret file (passed to ``Client.open``)
  workers       loopback only: worker threads for ``open_loopback`` (default 0 = library default)
  ns            optional 64-hex-char namespace (32 bytes); default is a fixed benchmark namespace
  timeout_s     per-op completion timeout (default 30)
  block_size    bytes per block (required, set by the stage)
  max_op_blocks   largest batch (blocks per put/fetch) the backend accepts (default 64 = the stage's prefill batch); a larger
                  op raises ValueError. Set it to the workload's ``batch_size`` or more.
  max_inflight    concurrent ops the staging region serves (default 16; set it to the workload's
                  ``concurrency`` or more). Ops beyond that wait for a slot up to ``timeout_s``.
  staging_bytes   total pre-registered staging region (default max_inflight * max_op_blocks *
                  block_size). Split into fixed slots of max_op_blocks * block_size bytes; an
                  explicit value must hold at least one slot.
  The staging region is attached once at open and detached at close (not per op).
  cipher        ``false``/"none" is rejected: the client exposes no null-cipher option, so
                ``supports_null_cipher`` is False and variants requiring it are skipped.
"""
from __future__ import annotations

import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import Any

from miracache import _core
from miracache._core import Client, MiraError

try:
    from agentbench.kvtier.backend import ERROR, MISS, OK, KVTierBackend
    HAVE_AGENTBENCH = True
except ImportError:
    HAVE_AGENTBENCH = False
    OK, MISS, ERROR = "ok", "miss", "error"

    class KVTierBackend(ABC):  # type: ignore[no-redef]
        """Fallback mirroring agentbench.kvtier.backend.KVTierBackend."""

        capabilities: dict[str, bool] = {}

        @abstractmethod
        def open(self, config: dict[str, Any]) -> None: ...

        @abstractmethod
        def put(self, keys: Sequence[bytes], buffers: Sequence[Any]) -> None: ...

        @abstractmethod
        def fetch(self, keys: Sequence[bytes], buffers: Sequence[Any]) -> list[str]: ...

        @abstractmethod
        def lookup(self, keys: Sequence[bytes]) -> list[bool]: ...

        @abstractmethod
        def close(self) -> None: ...


_DEFAULT_NS = bytes(range(32))
_ROOT = b"agentbench-root"


class MiracacheBackend(KVTierBackend):
    # The C ABI / Python client has no null-cipher switch; do not claim the capability.
    capabilities = {"supports_null_cipher": False}

    def __init__(self) -> None:
        self._client: Client | None = None
        self._scope = None
        self._block = 0
        self._timeout = 30.0
        self._attach_mu = threading.Lock()
        # Pooled staging: one region, fixed-size slots handed out under _slot_cv.
        self._slot_cv = threading.Condition()
        self._staging: bytearray | None = None
        self._staging_view: memoryview | None = None
        self._region: int | None = None
        self._slot_bytes = 0
        self._slot_max_blocks = 0
        self._free: list[int] = []
        self._inflight = 0
        self._retired: set[int] = set()
        self._closing = False
        self._poll_mu = threading.Lock()
        self._lookup_mu = threading.Lock()
        self._stash: dict[int, Any] = {}
        self._stat_mu = threading.Lock()
        # Bytes and wall time per op kind (the stage also times ops itself).
        self._stats = {"put_ops": 0, "put_bytes": 0, "fetch_ops": 0, "fetch_bytes": 0,
                      "lookup_ops": 0, "last_op_s": 0.0, "total_op_s": 0.0}

    @property
    def stats(self) -> dict:
        """``Client.metrics_dict()`` (``name{k="v"}`` -> value; histogram buckets, _sum and _count
        included) plus this backend's own op/byte/time totals (``put_ops`` ... ``total_op_s``).
        The client part is empty before open/after close or for a client without metrics."""
        with self._stat_mu:
            out: dict = dict(self._stats)
        c = self._client
        fn = getattr(c, "metrics_dict", None)
        if fn is not None:
            try:
                out.update(fn())
            except Exception:  # noqa: BLE001 - stats must never fail a run (closed client, old lib)
                pass
        return out

    # -- lifecycle ----------------------------------------------------------
    def open(self, config: dict[str, Any]) -> None:
        mode = config.get("mode", "loopback")
        if config.get("cipher") in (False, "none"):
            raise ValueError("miracache cannot disable encryption (no null-cipher option); "
                             "drop the cipher-off variant")
        self._block = int(config.get("block_size", 0))
        if self._block <= 0:
            raise ValueError("block_size must be a positive int")
        self._timeout = float(config.get("timeout_s", 30))
        max_op = int(config.get("max_op_blocks", 64))
        max_inflight = int(config.get("max_inflight", 16))
        if max_op <= 0 or max_inflight <= 0:
            raise ValueError("max_op_blocks and max_inflight must be positive")
        if config.get("staging_bytes") and int(config["staging_bytes"]) < max_op * self._block:
            raise ValueError("staging_bytes=%s is smaller than one op (max_op_blocks=%d x "
                             "block_size=%d = %d bytes)" % (config["staging_bytes"], max_op,
                                                            self._block, max_op * self._block))
        if mode == "loopback":
            client = Client.open_loopback(int(config.get("workers", 0)))
        elif mode == "wire":
            if not config.get("config"):
                raise ValueError("mode=wire needs `config` (client.toml path or text)")
            client = Client.open(str(config["config"]), config.get("secret_file"))
        else:
            raise ValueError("mode must be 'loopback' or 'wire', got %r" % (mode,))
        ns = bytes.fromhex(config["ns"]) if config.get("ns") else _DEFAULT_NS
        self._client = client
        try:
            self._scope = client.derive({"engine": "vllm", "ns": ns, "roots": {0: _ROOT}}, 0)
            self._setup_staging(int(config.get("staging_bytes", 0)) or
                                max_inflight * max_op * self._block, max_op)
        except BaseException:
            self._client = None
            self._scope = None
            client.close()
            raise

    def _setup_staging(self, total_bytes: int, max_op_blocks: int) -> None:
        """Allocate and attach the one staging region: ``total_bytes`` split into slots of
        ``max_op_blocks`` blocks. Called once, from open()."""
        c = self._need()
        slot = max_op_blocks * self._block
        if max_op_blocks <= 0 or total_bytes < slot:
            raise ValueError("staging_bytes=%d cannot hold one op of max_op_blocks=%d x block_size=%d "
                             "(%d bytes); raise staging_bytes or lower max_op_blocks"
                             % (total_bytes, max_op_blocks, self._block, slot))
        nslots = total_bytes // slot
        staging = bytearray(nslots * slot)
        rid = c.attach_region(staging, self._block)
        with self._slot_cv:
            self._staging, self._staging_view = staging, memoryview(staging)
            self._region, self._slot_bytes, self._slot_max_blocks = rid, slot, max_op_blocks
            self._free = list(range(nslots))
            self._inflight, self._closing = 0, False

    def _free_slots(self) -> int:
        with self._slot_cv:
            return len(self._free)

    def _acquire(self, nblocks: int) -> int:
        if nblocks > self._slot_max_blocks:
            raise ValueError("op has %d blocks but the staging slot holds max_op_blocks=%d; raise "
                             "max_op_blocks (and staging_bytes if set) or lower batch_size"
                             % (nblocks, self._slot_max_blocks))
        end = time.monotonic() + self._timeout
        with self._slot_cv:
            while True:
                if self._closing or self._staging is None:
                    raise RuntimeError("backend is not open")
                if self._free:
                    self._inflight += 1
                    return self._free.pop()
                left = end - time.monotonic()
                if left <= 0:
                    raise TimeoutError("no free staging slot in %.1fs (raise max_inflight or "
                                       "staging_bytes)" % self._timeout)
                self._slot_cv.wait(left)

    def _release(self, slot: int) -> None:
        with self._slot_cv:
            if slot not in self._retired:  # timed-out op: the NIC may still write it
                self._free.append(slot)
            self._inflight -= 1
            self._slot_cv.notify_all()

    def close(self) -> None:
        with self._slot_cv:
            self._closing = True  # refuse new ops, wake waiters, then drain in-flight ones
            self._slot_cv.notify_all()
            end = time.monotonic() + self._timeout + 5
            while self._inflight > 0 and time.monotonic() < end:
                self._slot_cv.wait(0.1)
            rid, self._region = self._region, None
            self._staging = self._staging_view = None
            self._free = []
        c, self._client, self._scope = self._client, None, None
        if c is not None:
            if rid is not None:
                with self._attach_mu:
                    try:
                        c.detach_region(rid)
                    except MiraError:
                        pass
            c.close()

    # -- helpers ------------------------------------------------------------
    def _need(self) -> Client:
        if self._client is None:
            raise RuntimeError("backend is not open")
        return self._client

    def _wait(self, c: Client, ticket: int):
        end = time.monotonic() + self._timeout
        while True:
            with self._poll_mu:  # completions are shared by all threads: stash others'
                for comp in c.poll():
                    self._stash[comp.ticket] = comp
                comp = self._stash.pop(ticket, None)
            if comp is not None:
                return comp
            if time.monotonic() >= end:
                raise TimeoutError("ticket %d did not complete in %.1fs" % (ticket, self._timeout))
            c.wait_event(20)

    def _run(self, op: str, keys: Sequence[bytes], slot: int):
        c = self._need()
        n = len(keys)
        base = slot * self._slot_bytes
        kw = dict(parents=[None] * n, positions=list(range(n)),
                  offsets=[base + i * self._block for i in range(n)],
                  lengths=[self._block] * n, region=self._region)
        ticket = c.fetch(self._scope, keys, **kw) if op == "fetch" else c.put(self._scope, keys, **kw)
        try:
            return self._wait(c, ticket)
        except TimeoutError:
            with self._slot_cv:
                self._retired.add(slot)  # never reuse: the ticket may still be live
            raise

    def _account(self, kind: str, nbytes: int, t0: float) -> None:
        dt = time.perf_counter() - t0
        with self._stat_mu:
            self._stats[kind + "_ops"] += 1
            if nbytes:
                self._stats[kind + "_bytes"] += nbytes
            self._stats["last_op_s"] = dt
            self._stats["total_op_s"] += dt

    # -- KVTierBackend ------------------------------------------------------
    # The library refuses a batch that repeats a key; a random load generator can draw the same
    # key twice in one batch, so duplicates are folded here (first buffer wins for put; fetch
    # fans one result out to every position).
    def put(self, keys: Sequence[bytes], buffers: Sequence[Any]) -> None:
        if len(keys) != len(buffers):
            raise ValueError("keys/buffers length mismatch")
        seen: dict[bytes, int] = {}
        for i, k in enumerate(keys):
            seen.setdefault(bytes(k), i)
        if len(seen) != len(keys):
            idx = sorted(seen.values())
            keys, buffers = [keys[i] for i in idx], [buffers[i] for i in idx]
        self._put_unique(keys, buffers)

    def fetch(self, keys: Sequence[bytes], buffers: Sequence[Any]) -> list[str]:
        if len(keys) != len(buffers):
            raise ValueError("keys/buffers length mismatch")
        first: dict[bytes, int] = {}
        for i, k in enumerate(keys):
            first.setdefault(bytes(k), i)
        if len(first) == len(keys):
            return self._fetch_unique(keys, buffers)
        idx = sorted(first.values())
        res = dict(zip((bytes(keys[i]) for i in idx),
                       self._fetch_unique([keys[i] for i in idx], [buffers[i] for i in idx])))
        out = []
        for i, k in enumerate(keys):
            st = res[bytes(k)]
            if i != first[bytes(k)] and st == OK:  # copy the fetched block into the repeat
                memoryview(buffers[i]).cast("B")[:] = memoryview(buffers[first[bytes(k)]]).cast("B")
            out.append(st)
        return out

    def _put_unique(self, keys: Sequence[bytes], buffers: Sequence[Any]) -> None:
        if not keys:
            return
        t0 = time.perf_counter()
        bs = self._block
        mvs = []
        for i, b in enumerate(buffers):
            mv = memoryview(b).cast("B")
            if len(mv) != bs:
                raise ValueError("buffer %d is %d bytes, block_size is %d" % (i, len(mv), bs))
            mvs.append(mv)
        slot = self._acquire(len(keys))
        try:
            base = slot * self._slot_bytes
            for i, mv in enumerate(mvs):
                self._staging_view[base + i * bs:base + (i + 1) * bs] = mv
            comp = self._run("put", list(keys), slot)
        finally:
            self._release(slot)
        if any(s not in (_core.COMMITTED, _core.SKIPPED) for s in comp.statuses):
            raise RuntimeError("put failed: statuses %r" % (comp.statuses,))
        self._account("put", len(keys) * bs, t0)

    def _fetch_unique(self, keys: Sequence[bytes], buffers: Sequence[Any]) -> list[str]:
        if not keys:
            return []
        t0 = time.perf_counter()
        bs = self._block
        try:
            slot = self._acquire(len(keys))
        except TimeoutError:
            return [ERROR] * len(keys)
        out: list[str] = []
        got = 0
        try:
            base = slot * self._slot_bytes
            try:
                comp = self._run("fetch", list(keys), slot)
            except (MiraError, TimeoutError):
                return [ERROR] * len(keys)
            for i, s in enumerate(comp.statuses[:len(keys)]):
                if s == _core.HIT:
                    memoryview(buffers[i]).cast("B")[:bs] = \
                        self._staging_view[base + i * bs:base + (i + 1) * bs]
                    out.append(OK)
                    got += bs
                elif s == _core.MISS:
                    out.append(MISS)
                else:
                    out.append(ERROR)
        finally:
            self._release(slot)
        out += [ERROR] * (len(keys) - len(out))
        self._account("fetch", got, t0)
        return out

    def lookup(self, keys: Sequence[bytes]) -> list[bool]:
        c = self._need()
        t0 = time.perf_counter()
        res: list[bool] = []
        with self._lookup_mu:  # lookup_nb keeps per-key state in the client
            for k in keys:
                end = time.monotonic() + self._timeout
                ans = c.lookup_nb(self._scope, k)
                while ans == "PENDING":
                    if time.monotonic() >= end:
                        raise TimeoutError("lookup timed out")
                    c.wait_event(20)
                    ans = c.lookup_nb(self._scope, k)
                res.append(ans == "HIT")
        self._account("lookup", 0, t0)
        return res
