"""Fake of vllm/v1/kv_offload/tiering/base.py @65711a1: JobId :39, TransferJob :74-83,
JobResult :86-105, SecondaryTierManager :145+ (__init__ :187-193, block_size_bytes :212-214,
lookup :221, submit_store :237, submit_load :265, get_finished_jobs :290, on_new_request :315,
on_request_finished :328, drain_jobs :374, shutdown). Set MISSING_DEFERRED_RELEASE for a
0.32/0.33-shaped JobResult (no deferred_release field)."""
import threading
import time
from abc import ABC, abstractmethod
from collections.abc import Collection, Iterable
from dataclasses import dataclass, field
from typing import Any, List, Optional

from vllm.v1.kv_offload.base import (LookupResult, ReqContext,  # noqa: F401
                                     RequestOffloadingContext)
from vllm.v1.kv_offload.tiering.backpressure import BackpressureDetector

JobId = int


@dataclass
class TransferJob:
    job_id: JobId
    keys: Collection[bytes]
    chunk_ids: Any  # np.ndarray upstream
    is_promotion: bool
    req_context: ReqContext
    submit_time: float = field(default_factory=time.monotonic)


@dataclass
class JobResult:
    job_id: JobId
    success: bool
    successful_keys: Optional[Collection[bytes]] = None
    transfer_time: Optional[float] = None
    transfer_bytes: Optional[int] = None
    deferred_release: Optional[threading.Event] = None


@dataclass
class JobResultV033:
    """0.32/0.33 shape: ends at transfer_bytes."""
    job_id: JobId
    success: bool
    successful_keys: Optional[Collection[bytes]] = None
    transfer_time: Optional[float] = None
    transfer_bytes: Optional[int] = None


class SecondaryTierManager(ABC):
    def __init__(self, offloading_spec: Any, primary_kv_view: memoryview, tier_type: str,
                 backpressure_detector: Optional[BackpressureDetector] = None) -> None:
        self._offloading_spec = offloading_spec
        self._primary_kv_view: memoryview = primary_kv_view
        assert primary_kv_view.strides is not None, "primary_kv_view.strides cannot be None"
        self._block_size_bytes: int = primary_kv_view.strides[0]
        self.tier_type = tier_type
        self.locality = None
        self._bp_detector = backpressure_detector

    @property
    def block_size_bytes(self) -> int:
        return self._block_size_bytes

    @property
    def bp_detector(self) -> Optional[BackpressureDetector]:
        return self._bp_detector

    @abstractmethod
    def lookup(self, key: bytes, req_context: ReqContext) -> LookupResult: ...

    @abstractmethod
    def submit_store(self, job_metadata: TransferJob) -> None: ...

    @abstractmethod
    def submit_load(self, job_metadata: TransferJob) -> None: ...

    @abstractmethod
    def get_finished_jobs(self) -> Iterable[JobResult]: ...

    def has_pending_work(self) -> bool:
        return False

    @abstractmethod
    def on_new_request(self, req_context: ReqContext) -> RequestOffloadingContext: ...

    def on_request_finished(self, req_context: ReqContext) -> None:
        return

    @abstractmethod
    def drain_jobs(self) -> None: ...

    def shutdown(self) -> None:
        return
