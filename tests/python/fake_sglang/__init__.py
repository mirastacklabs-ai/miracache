"""Stand-ins mirroring SGLang HiCache at main 18d862f. No sglang/torch.

``S/`` = ``python/sglang/srt/``. Names, signatures, call order and return types follow
upstream; the host pools use real ctypes memory and reproduce the upstream
``get_page_buffer_meta`` address arithmetic (absolute addresses, as ``data_ptr()``).
"""
import ctypes
from dataclasses import dataclass, field
from typing import Any, List, Optional

# ---- S/mem_cache/hicache_storage.py ---------------------------------------------


@dataclass
class HiCacheStorageConfig:  # hicache_storage.py:28-43 (same fields, order, defaults)
    tp_rank: int = 0
    tp_size: int = 1
    pp_rank: int = 0
    pp_size: int = 1
    attn_cp_rank: int = 0
    attn_cp_size: int = 1
    is_mla_model: bool = False
    enable_storage_metrics: bool = False
    is_page_first_layout: bool = True
    model_name: Optional[str] = "m"
    tp_lcm_size: Optional[int] = None
    should_split_heads: bool = False
    dp_rank: int = 0
    extra_config: Optional[dict] = None
    unified_suffixes: Optional[List[str]] = None
    dcp_size: int = 1
    dcp_rank: int = 0
    logical_page_size: Optional[int] = None
    unified_chunk_spans: Optional[List[tuple]] = None
    rank_replicated: Optional[bool] = None


@dataclass
class HiCacheStorageExtraInfo:  # hicache_storage.py:99-103
    prefix_keys: Optional[List[str]] = None
    extra_info: Optional[dict] = None


@dataclass
class PoolTransfer:  # hicache_storage.py:190 (fields used by the adapter)
    name: str
    host_indices: Any = None
    device_indices: Any = None
    keys: Optional[List[str]] = None


@dataclass
class PoolTransferResult:  # hicache_storage.py:244-262
    kv_hit_pages: int
    extra_pool_hit_pages: dict
    restorable_prefix_pages: Optional[List[int]] = None

    @classmethod
    def empty(cls):
        return cls(0, {})


# Parameter names (after self) and return annotation of the upstream methods.
REAL_SIGNATURES = {
    # hicache_storage.py:381-382
    "register_mem_pool_host": (["mem_pool_host"], None),
    # :399-404 (return PoolTransferResult)
    "batch_exists_v2": (["keys", "pool_transfers", "extra_info"], "PoolTransferResult"),
    # :432-436 (return dict[str, List[bool]])
    "batch_get_v2": (["transfers", "extra_info"], "dict[str, List[bool]]"),
    # :443-447
    "batch_set_v2": (["transfers", "extra_info"], "dict[str, List[bool]]"),
    # :454-459
    "batch_get_v1": (["keys", "host_indices", "extra_info"], "List[bool]"),
    # :466-471
    "batch_set_v1": (["keys", "host_indices", "extra_info"], "List[bool]"),
    # :479-540
    "get": (["key", "target_location", "target_sizes"], None),
    "batch_get": (["keys", "target_locations", "target_sizes"], None),
    "set": (["key", "value", "target_location", "target_sizes"], None),
    "batch_set": (["keys", "values", "target_locations", "target_sizes"], None),
    "exists": (["key"], None),
    # :543-545
    "batch_exists": (["keys", "extra_info"], "int"),
}


# ---- S/mem_cache/pool_host/{mha,mla}.py ------------------------------------------


class _Idx(list):
    """Index 'tensor': upstream uses len() and tolist() only."""

    def tolist(self):
        return list(self)


class _HostPool:
    ITEMSIZE = 2

    def _alloc(self, nbytes):
        self._mem = (ctypes.c_char * nbytes)()
        self.base = ctypes.addressof(self._mem)

    def tokens(self, page):
        """Token indices (a host_indices argument) for page number ``page``."""
        return _Idx(range(page * self.page_size, (page + 1) * self.page_size))

    def indices(self, pages):
        out = _Idx()
        for p in pages:
            out.extend(self.tokens(p))
        return out

    def read_page(self, page):
        ptrs, sizes = self.get_page_buffer_meta(self.tokens(page))
        return [ctypes.string_at(p, s) for p, s in zip(ptrs, sizes)]

    def write_page(self, page, blobs):
        ptrs, sizes = self.get_page_buffer_meta(self.tokens(page))
        for p, s, b in zip(ptrs, sizes, blobs):
            assert len(b) == s
            ctypes.memmove(p, b, s)


class FakeMHAHostPool(_HostPool):
    """MHATokenToKVPoolHost, mha.py:859-919. layouts: layer_first, page_first,
    page_first_direct, page_head. K and V are separate regions (v_offset)."""

    def __init__(self, page_size=64, pages=8, layout="page_first", layer_num=2, head_num=2, head_dim=4):
        self.page_size, self.layout = page_size, layout
        self.layer_num, self.head_num, self.head_dim = layer_num, head_num, head_dim
        self.size = page_size * pages
        self.itemsize = self.ITEMSIZE
        self._alloc(2 * layer_num * self.size * head_num * head_dim * self.itemsize)

    def get_page_buffer_meta(self, indices):
        assert len(indices) % self.page_size == 0
        ptr_list = []
        base = self.base
        indices = indices.tolist()
        v_offset = self.layer_num * self.size * self.head_num * self.head_dim * self.itemsize
        if self.layout == "layer_first":
            for index in range(0, len(indices), self.page_size):
                for layer_id in range(self.layer_num):
                    k_ptr = (base + indices[index] * self.head_num * self.head_dim * self.itemsize
                             + layer_id * self.size * self.head_num * self.head_dim * self.itemsize)
                    ptr_list.append(k_ptr)
                    ptr_list.append(k_ptr + v_offset)
            element_size = self.itemsize * self.page_size * self.head_num * self.head_dim
        elif self.layout in ["page_first", "page_first_direct", "page_head"]:
            for index in range(0, len(indices), self.page_size):
                k_ptr = base + indices[index] * self.layer_num * self.head_num * self.head_dim * self.itemsize
                ptr_list.append(k_ptr)
                ptr_list.append(k_ptr + v_offset)
            element_size = (self.layer_num * self.itemsize * self.page_size * self.head_num * self.head_dim)
        else:
            raise ValueError(f"Unsupported layout: {self.layout}")
        return ptr_list, [element_size] * len(ptr_list)


class FakeMLAHostPool(_HostPool):
    """MLATokenToKVPoolHost, mla.py:1364-1396 (non-split layouts), logical_page_size == page_size."""

    def __init__(self, page_size=64, pages=8, layout="page_first", layer_num=2, kv_cache_dim=8):
        self.page_size, self.layout = page_size, layout
        self.logical_page_size = page_size
        self.layer_num, self.kv_cache_dim = layer_num, kv_cache_dim
        self.size = page_size * pages
        self.itemsize = self.ITEMSIZE
        self._alloc(layer_num * self.size * kv_cache_dim * self.itemsize)

    def get_page_buffer_meta(self, indices):
        assert len(indices) % self.logical_page_size == 0
        ptr_list = []
        base = self.base
        indices = indices.tolist()
        page_starts = indices[:: self.logical_page_size]
        if self.layout == "layer_first":
            for index in page_starts:
                for layer_id in range(self.layer_num):
                    ptr_list.append(base + index * self.kv_cache_dim * self.itemsize
                                    + layer_id * self.size * self.kv_cache_dim * self.itemsize)
            element_size = self.itemsize * self.page_size * self.kv_cache_dim
        elif self.layout in ["page_first", "page_first_direct"]:
            for index in page_starts:
                ptr_list.append(base + index * self.layer_num * self.kv_cache_dim * self.itemsize)
            element_size = self.layer_num * self.itemsize * self.page_size * self.kv_cache_dim
        else:
            raise ValueError(f"Unsupported layout: {self.layout}")
        return ptr_list, [element_size] * len(ptr_list)


class FakeMLAKVSplitHostPool(_HostPool):
    """MLATokenToKVPoolHost layout ``page_first_kv_split`` (mla.py:1282-1363, dcp_size == 1):
    per page, in this order: k (k_width), v (qk_rope_head_dim; dropped when
    dsa_kv_cache_store_fp8), index_k (if an indexer), scale (if an indexer). Separate
    regions with different element sizes; page-major like every other layout."""

    def __init__(self, page_size=64, pages=8, layer_num=2, k_width=8, qk_rope_head_dim=4,
                 indexer_layers=1, index_k_width=4, skip_v=False):
        self.page_size = self.logical_page_size = page_size
        self.layout = "page_first_kv_split"
        self.layer_num, self.k_width, self.rope = layer_num, k_width, qk_rope_head_dim
        self.nil, self.ikw, self.skip_v = indexer_layers, index_k_width, skip_v
        self.size = page_size * pages
        self.itemsize = self.ITEMSIZE
        k = self.size * layer_num * k_width * self.itemsize
        v = self.size * layer_num * qk_rope_head_dim * self.itemsize
        ik = self.size * indexer_layers * index_k_width * self.itemsize
        sc = self.size * indexer_layers * 4
        self._alloc(k + v + ik + sc)
        self.k_base, self.v_base = self.base, self.base + k
        self.ik_base, self.sc_base = self.base + k + v, self.base + k + v + ik

    def get_page_buffer_meta(self, indices):
        assert len(indices) % self.logical_page_size == 0
        ptr_list, sizes = [], []
        indices = indices.tolist()
        ks = self.layer_num * self.itemsize * self.page_size * self.k_width
        vs = self.layer_num * self.itemsize * self.page_size * self.rope
        iks = self.nil * self.itemsize * self.page_size * self.ikw
        scs = self.nil * 4 * self.page_size
        for index in range(0, len(indices), self.page_size):
            i = indices[index]
            ptr_list.append(self.k_base + i * self.layer_num * self.k_width * self.itemsize)
            sizes.append(ks)
            if not self.skip_v:
                ptr_list.append(self.v_base + i * self.layer_num * self.rope * self.itemsize)
                sizes.append(vs)
            if self.nil:
                ptr_list.append(self.ik_base + i * self.nil * self.ikw * self.itemsize)
                sizes.append(iks)
                ptr_list.append(self.sc_base + i * self.nil * 4)
                sizes.append(scs)
        return ptr_list, sizes


# (name, pool factory, buffers per page)
def all_layouts(page_size=64, pages=8):
    return [
        ("mha_page_first", lambda: FakeMHAHostPool(page_size, pages, "page_first"), 2),
        ("mha_page_first_direct", lambda: FakeMHAHostPool(page_size, pages, "page_first_direct"), 2),
        ("mha_page_head", lambda: FakeMHAHostPool(page_size, pages, "page_head"), 2),
        ("mha_layer_first", lambda: FakeMHAHostPool(page_size, pages, "layer_first", layer_num=3), 6),
        ("mla_page_first", lambda: FakeMLAHostPool(page_size, pages, "page_first"), 1),
        ("mla_page_first_direct", lambda: FakeMLAHostPool(page_size, pages, "page_first_direct"), 1),
        ("mla_layer_first", lambda: FakeMLAHostPool(page_size, pages, "layer_first", layer_num=3), 3),
        ("mla_page_first_kv_split", lambda: FakeMLAKVSplitHostPool(page_size, pages), 4),
        ("mla_kv_split_fp8_no_v", lambda: FakeMLAKVSplitHostPool(page_size, pages, skip_v=True), 3),
        ("mla_kv_split_no_indexer",
         lambda: FakeMLAKVSplitHostPool(page_size, pages, indexer_layers=0), 2),
    ]


# ---- S/mem_cache/storage/backend_factory.py:165 + S/managers/cache_controller.py:664-667 ----


def build_dynamic_backend(backend_class, storage_config, host_pool):
    """Real call order: ``backend_class(storage_config, kwargs)`` with kwargs == {}
    (backend_factory.py:165, cache_controller.py:664-666), THEN
    ``register_mem_pool_host(host_pool)`` (cache_controller.py:667)."""
    backend = backend_class(storage_config, {})
    backend.register_mem_pool_host(host_pool)
    return backend
