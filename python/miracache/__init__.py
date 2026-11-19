"""miracache Python package: ctypes binding over libmiracache.so (``_core``); engine adapters
live in ``miracache.vllm`` / ``miracache.sglang`` and do not need the library at import time."""
from ._core import Client, Completion, MiraError, Scope, StoreReply, library_path

__all__ = ["Client", "Completion", "MiraError", "Scope", "StoreReply", "library_path"]
