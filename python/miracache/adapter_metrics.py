"""Adapter-side metrics (A3.5 M2): four Python counters plus an optional ``/metrics`` HTTP server.

Counters (Prometheus text exposition 0.0.4, same format as the client library's)::

    miracache_adapter_hit_tokens_total          tokens of lookups answered HIT
    miracache_adapter_lookup_tokens_total       tokens of lookups answered HIT or MISS
    miracache_adapter_load_fail_total           blocks (keys) of load jobs that did not load
    miracache_recompute_avoided_tokens_total    tokens loaded from miracache instead of recomputed

No label ever carries a scope, session, key, salt or token value; the series are label-free.

Server: ``start_metrics_server`` binds ``metrics_port + rank`` (``metrics_port`` 0 = off) on
``metrics_host`` (default 127.0.0.1) in a daemon thread, answers ``GET /metrics`` only (404 for any
other path, 405 for other methods) and serves the client's metrics followed by the adapter's.
Importable without vLLM, SGLang or the native library.
"""
from __future__ import annotations

import logging
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional

log = logging.getLogger("miracache.metrics")

CONTENT_TYPE = "text/plain; version=0.0.4; charset=utf-8"
HANDLER_TIMEOUT_S = 5.0  # per-connection socket timeout (M01)
MAX_CONNECTIONS = 4      # concurrent handler threads; more get 503 (M01)

_COUNTERS = (
    ("miracache_adapter_hit_tokens_total", "Tokens of lookups answered HIT."),
    ("miracache_adapter_lookup_tokens_total", "Tokens of lookups answered HIT or MISS."),
    ("miracache_adapter_load_fail_total", "Blocks of load jobs that failed to load."),
    ("miracache_recompute_avoided_tokens_total", "Tokens loaded from miracache instead of recomputed."),
)
HIT_TOKENS, LOOKUP_TOKENS, LOAD_FAIL, RECOMPUTE_AVOIDED = (n for n, _ in _COUNTERS)


class AdapterMetrics:
    """Thread-safe counters; ``inc`` is one dict update under a lock (off the client hot path)."""

    def __init__(self) -> None:
        self._mu = threading.Lock()
        self._v: Dict[str, int] = {n: 0 for n, _ in _COUNTERS}

    def inc(self, name: str, n: int = 1) -> None:
        if n:
            with self._mu:
                self._v[name] += int(n)

    def values(self) -> Dict[str, int]:
        with self._mu:
            return dict(self._v)

    def render(self) -> str:
        v = self.values()
        out = []
        for name, help_ in _COUNTERS:
            out.append("# HELP %s %s\n# TYPE %s counter\n%s %d\n" % (name, help_, name, name, v[name]))
        return "".join(out)


def combined_text(client: Any, adapter: AdapterMetrics) -> str:
    """Client metrics (when the client has them) followed by the adapter counters."""
    text = ""
    fn = getattr(client, "metrics", None)
    if fn is not None:
        try:
            text = str(fn())
        except Exception as exc:  # noqa: BLE001 - a scrape must not fail on a closed/old client
            log.debug("client metrics unavailable: %r", exc)
    if text and not text.endswith("\n"):
        text += "\n"
    return text + adapter.render()


def rank_from_env() -> int:
    """Rank for port = base + rank when the engine gives none: MIRACACHE_RANK, LOCAL_RANK, RANK."""
    for name in ("MIRACACHE_RANK", "LOCAL_RANK", "RANK"):
        try:
            return max(0, int(os.environ[name]))
        except (KeyError, ValueError):
            continue
    return 0


class MetricsServer:
    """``GET /metrics`` over HTTP in a daemon thread."""

    def __init__(self, host: str, port: int, text_fn: Callable[[], str], *,
                 timeout: float = HANDLER_TIMEOUT_S, max_connections: int = MAX_CONNECTIONS) -> None:
        fn = text_fn
        io_timeout = float(timeout)

        class _Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            # M01: a peer that connects and says nothing (or stalls mid-request) frees its thread
            # after this long instead of holding it, and a file descriptor, forever.
            timeout = io_timeout

            def do_GET(self) -> None:  # noqa: N802
                if self.path.split("?", 1)[0] != "/metrics":
                    self._reply(404, b"not found\n")
                    return
                try:
                    body = fn().encode("utf-8")
                except Exception as exc:  # noqa: BLE001
                    log.warning("metrics render failed: %r", exc)
                    self._reply(500, b"error\n")
                    return
                self._reply(200, body, CONTENT_TYPE)

            def do_HEAD(self) -> None:  # noqa: N802
                self.send_error(405)

            do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD  # noqa: N815

            def _reply(self, code: int, body: bytes, ctype: str = "text/plain; charset=utf-8") -> None:
                self.send_response(code)
                self.send_header("Content-Type", ctype)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)
                self.close_connection = True

            def log_message(self, *a: Any) -> None:  # silence per-request stderr noise
                pass

        class _Server(ThreadingHTTPServer):
            daemon_threads = True
            # M01: at most ``max_connections`` handler threads; a connection over the cap gets a
            # 503 and is closed at once, so a scraper flood never grows threads/fds in the engine.
            _slots = threading.BoundedSemaphore(max(1, int(max_connections)))

            def process_request(self, request: Any, client_address: Any) -> None:
                if not self._slots.acquire(blocking=False):
                    try:
                        request.settimeout(1.0)
                        request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n"
                                        b"Retry-After: 1\r\nConnection: close\r\n\r\n")
                    except OSError:
                        pass
                    self.shutdown_request(request)
                    return
                try:
                    super().process_request(request, client_address)
                except BaseException:
                    self._slots.release()  # the thread never started
                    raise

            def process_request_thread(self, request: Any, client_address: Any) -> None:
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self._slots.release()

        self._srv = _Server((host, port), _Handler)
        self.host, self.port = self._srv.server_address[0], self._srv.server_address[1]
        self._th = threading.Thread(target=self._srv.serve_forever, name="miracache-metrics", daemon=True)
        self._th.start()

    def stop(self) -> None:
        try:
            self._srv.shutdown()
            self._srv.server_close()
        except Exception:  # noqa: BLE001
            pass
        self._th.join(timeout=2.0)


def start_metrics_server(cfg: Dict[str, Any], rank: int, text_fn: Callable[[], str]) -> Optional[MetricsServer]:
    """Starts the server from adapter config keys ``metrics_port`` (0/absent = off) and
    ``metrics_host`` (default 127.0.0.1). Listens on ``metrics_port + rank``. Never raises: a bind
    failure is logged and the engine runs without it."""
    try:
        base = int(cfg.get("metrics_port", 0) or 0)
        if base <= 0:
            return None
        port = base + max(0, int(rank))
        if port > 65535:
            log.warning("miracache metrics_port %d + rank %d is out of range; metrics endpoint off", base, rank)
            return None
        srv = MetricsServer(str(cfg.get("metrics_host", "127.0.0.1")), port, text_fn)
        log.info("miracache metrics on http://%s:%d/metrics", srv.host, srv.port)
        return srv
    except Exception as exc:  # noqa: BLE001
        log.warning("miracache metrics endpoint not started: %r", exc)
        return None
