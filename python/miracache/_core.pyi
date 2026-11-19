from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

ABI_MAJOR: int
OK: int
E_INVALID: int
E_CONFIG: int
E_UNSUPPORTED: int
E_NOT_FOUND: int
E_ACCESS: int
E_CLOSED: int
E_NOMEM: int
E_INTERNAL: int
E_BUFFER: int
POLL_ERROR: int
HIT: int
MISS: int
COMMITTED: int
SKIPPED: int
REFUSED: int
ABORTED: int
TIMEOUT: int

class MiraError(Exception):
    code: int
    message: str
    def __init__(self, code: int, message: str = ...) -> None: ...

def library_path() -> Optional[str]: ...
def parse_metrics(text: str) -> Dict[str, float]: ...

class Scope:
    group: int
    serial: int

@dataclass
class Completion:
    ticket: int
    success: bool
    successful_keys: list
    deferred_release: bool
    released: bool
    kind: str
    statuses: List[int]

@dataclass
class StoreReply:
    status: str
    ticket: Optional[int]
    retry_after_ms: int

class Client:
    @classmethod
    def open(cls, config: str, secret_file: Optional[str] = ...) -> Client: ...
    @classmethod
    def open_loopback(cls, workers: int = ..., secret: Optional[bytes] = ...) -> Client: ...
    def attach_region(self, buf: Any, block_bytes: int = ...) -> int: ...
    def detach_region(self, region: int) -> None: ...
    def derive(self, meta: Mapping[str, Any], group: int) -> Scope: ...
    def fetch(self, scope: Scope, keys: Sequence[bytes], parents: Optional[Sequence[Optional[bytes]]] = ...,
              positions: Optional[Sequence[int]] = ..., offsets: Optional[Sequence[int]] = ...,
              deadline_ms: int = ..., lengths: Optional[Sequence[int]] = ...,
              region: Optional[int] = ...) -> int: ...
    def put(self, scope: Scope, keys: Sequence[bytes], parents: Any = ..., positions: Any = ...,
            offsets: Any = ..., deadline_ms: int = ..., lengths: Any = ..., region: Optional[int] = ...) -> int: ...
    def store(self, scope: Scope, keys: Sequence[bytes], parents: Any = ..., positions: Any = ...,
              offsets: Any = ..., lengths: Any = ..., region: Optional[int] = ...,
              deadline_ms: int = ...) -> StoreReply: ...
    def lookup_nb(self, scope: Scope, key: bytes, parent: Optional[bytes] = ...,
                  deadline_ms: int = ...) -> str: ...
    def lookup_many(self, scope: Scope, keys: Sequence[bytes], parents: Any = ...,
                    deadline_ms: int = ...) -> List[str]: ...
    def poll(self) -> List[Completion]: ...
    def event_fd(self) -> int: ...
    def wait_event(self, timeout_ms: int = ...) -> bool: ...
    def metrics(self) -> str: ...
    def metrics_dict(self) -> Dict[str, float]: ...
    def close(self) -> None: ...
    def __enter__(self) -> Client: ...
    def __exit__(self, *exc: Any) -> None: ...
