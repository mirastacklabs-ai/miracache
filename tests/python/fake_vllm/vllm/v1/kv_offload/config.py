"""Fake of vllm/v1/kv_offload/config.py @65711a1: OffloadingGroupConfig :10-21,
OffloadingModelConfig :24-31, OffloadingCacheConfig :34-39, OffloadingParallelConfig :42-67,
OffloadingConfig :70-95 (all frozen dataclasses, field order as upstream)."""
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional, Tuple


@dataclass(frozen=True)
class OffloadingGroupConfig:
    tokens_per_block: int
    layer_names: Tuple[str, ...]
    group_id: int
    sliding_window_size_in_chunks: Optional[int] = None


@dataclass(frozen=True)
class OffloadingModelConfig:
    name: str
    dtype: str
    max_model_len: int = 0


@dataclass(frozen=True)
class OffloadingCacheConfig:
    tokens_per_hash: int
    blocks_per_chunk: int


@dataclass(frozen=True)
class OffloadingParallelConfig:
    rank: int
    world_size: int
    tp_size: int
    pp_size: int
    pcp_size: int
    dcp_size: int
    data_parallel_index: int
    data_parallel_size: int
    data_parallel_rank_local: Optional[int]
    is_parallelism_agnostic: bool


@dataclass(frozen=True)
class OffloadingConfig:
    groups: Tuple[OffloadingGroupConfig, ...]
    worker_kv_bytes_per_block: int
    enable_kv_cache_events: bool
    extra_config: Mapping[str, Any]
    engine_id: str
    model: OffloadingModelConfig
    cache: OffloadingCacheConfig
    parallel: OffloadingParallelConfig
    replicated_layout: bool = False
    canonical_layout: bool = False
    kv_cache_layout: Optional[str] = None
