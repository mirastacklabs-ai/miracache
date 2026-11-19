"""Decorator that keeps exceptions from escaping public TierCore methods."""
from __future__ import annotations

import functools
import logging
from typing import Any, Callable

log = logging.getLogger("miracache.vllm")


def never_raise(fallback: Callable[..., Any]) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Wrap a method: on any Exception call ``fallback(self, exc, *args, **kwargs)``,
    bump ``self.counters['internal_error.<method>']`` and log once per method."""

    def deco(fn: Callable[..., Any]) -> Callable[..., Any]:
        name = fn.__name__

        @functools.wraps(fn)
        def wrapper(self: Any, *args: Any, **kwargs: Any) -> Any:
            try:
                return fn(self, *args, **kwargs)
            except Exception as exc:  # noqa: BLE001 - the whole point
                try:
                    key = "internal_error." + name
                    self.counters[key] = self.counters.get(key, 0) + 1
                    if key not in self._logged:
                        self._logged.add(key)
                        log.error("miracache %s failed: %r (further errors counted only)", name, exc)
                    return fallback(self, exc, *args, **kwargs)
                except Exception:  # noqa: BLE001
                    return None

        return wrapper

    return deco
