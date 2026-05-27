import socket
from concurrent.futures import ThreadPoolExecutor, Future
from typing import Optional


class ReverseDNSCache:
    """Non-blocking reverse DNS cache. Lookups run in a background thread pool.
    lookup() returns immediately — either a cached hostname or None if not yet resolved."""

    def __init__(self, workers: int = 8, timeout: float = 2.0):
        self._cache: dict[str, Optional[str]] = {}
        self._pending: set[str] = set()
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="rdns")
        self._timeout = timeout

    def lookup(self, ip: str) -> Optional[str]:
        """Return cached hostname, or None. Submits a background lookup on first call."""
        if ip in self._cache:
            return self._cache[ip]
        if ip not in self._pending:
            self._pending.add(ip)
            self._pool.submit(self._resolve, ip)
        return None

    def _resolve(self, ip: str) -> None:
        try:
            host, _ = socket.getnameinfo((ip, 0), socket.NI_NAMEREQD)
            # Skip results that are just the IP back (no PTR record)
            result = host if host != ip else None
        except (socket.herror, socket.gaierror, OSError):
            result = None
        self._cache[ip] = result
        self._pending.discard(ip)

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
