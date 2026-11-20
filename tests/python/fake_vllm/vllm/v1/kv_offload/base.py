"""Fake of vllm/v1/kv_offload/base.py @65711a1: OffloadKey :36, ReqContext :~100-152
(set_state/get_state :142-146, set/get_offload_key_position :148-152), LookupResult :155-161,
OffloadPolicy, RequestOffloadingContext :173-175, OffloadingSpec.__init__ :775-796."""
import enum
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, NewType, Optional, TypeVar

from vllm.v1.kv_offload.config import OffloadingConfig

OffloadKey = NewType("OffloadKey", bytes)  # base.py:36; last 4 bytes = group index (research/16)
_T = TypeVar("_T")  # base.py:54


@dataclass
class ReqContext:
    req_id: str
    kv_transfer_params: Optional[Dict[str, Any]] = None
    kv_hints: Any = None
    load_tier_filter: Any = None  # TierFilter.ALL upstream
    _state: Dict[type, Any] = field(default_factory=dict, repr=False, init=False)
    _offload_key_positions: Dict[bytes, int] = field(default_factory=dict, repr=False, init=False)

    @property
    def num_computed_tokens(self) -> Optional[int]:
        return None

    @property
    def num_in_flight_tokens(self) -> Optional[int]:
        return None

    @property
    def num_prompt_tokens(self) -> Optional[int]:
        return None

    @property
    def num_tokens(self) -> Optional[int]:
        return None

    def set_state(self, val: Any) -> None:
        self._state[type(val)] = val

    def get_state(self, cls: "type[_T]") -> "Optional[_T]":
        return self._state.get(cls)

    def set_offload_key_position(self, key: bytes, end_token: int) -> None:
        self._offload_key_positions[key] = end_token

    def get_offload_key_position(self, key: bytes) -> Optional[int]:
        return self._offload_key_positions.get(key)


class LookupResult(Enum):
    MISS = auto()
    HIT = auto()
    HIT_PENDING = auto()
    RETRY = auto()


class OffloadPolicy(Enum):
    CHUNK_LEVEL = "chunk_level"
    REQUEST_LEVEL = "request_level"


@dataclass
class RequestOffloadingContext:
    policy: OffloadPolicy = OffloadPolicy.CHUNK_LEVEL


class OffloadingSpec:
    def __init__(self, config: OffloadingConfig):
        self.config = config
        self.extra_config = config.extra_config
        self.tokens_per_block = tuple(group.tokens_per_block for group in config.groups)
        self.tokens_per_hash = config.cache.tokens_per_hash
        self.blocks_per_chunk = config.cache.blocks_per_chunk
