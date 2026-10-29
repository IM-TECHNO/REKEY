"""Small in-memory sliding-window rate limiter and client-IP resolution.

State lives in this process only. That is correct for a single API replica (the supported
setup for now); with several replicas each one would allow its own quota, so a shared store
(Postgres or Redis) would be needed.
"""

import time
from collections import deque
from threading import Lock

from fastapi import HTTPException, Request

_MAX_KEYS = 50_000  # bound memory if someone sprays many addresses


def client_ip(request: Request) -> str:
    """The caller's address. Behind trusted proxies, the Nth entry from the right of
    X-Forwarded-For (N = REKEY_TRUSTED_PROXY_HOPS) is the address our outermost proxy saw.
    Entries further left are client-supplied and must never be trusted."""
    hops: int = request.app.state.settings.trusted_proxy_hops
    if hops > 0:
        parts = [
            p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()
        ]
        if len(parts) >= hops:
            return str(parts[-hops])
    return str(request.client.host) if request.client else ""


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = {}
        self._lock = Lock()

    def _prune(self, key: str, window: float, now: float) -> deque[float]:
        q = self._hits.setdefault(key, deque())
        while q and now - q[0] >= window:
            q.popleft()
        return q

    def count(self, key: str, window: float) -> int:
        with self._lock:
            return len(self._prune(key, window, time.monotonic()))

    def hit(self, key: str, window: float) -> int:
        """Record one event and return how many fall inside the window (including this one)."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > _MAX_KEYS:
                self._hits = {k: v for k, v in self._hits.items() if v and now - v[-1] < window}
            q = self._prune(key, window, now)
            q.append(now)
            return len(q)

    def retry_after(self, key: str, window: float) -> int:
        with self._lock:
            q = self._hits.get(key)
            if not q:
                return 1
            return max(1, int(window - (time.monotonic() - q[0])) + 1)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


def too_many(retry_after: int) -> HTTPException:
    return HTTPException(
        429, "too many requests, slow down", headers={"Retry-After": str(retry_after)}
    )


def limit(name: str, limit_attr: str, window: float = 60.0):  # type: ignore[no-untyped-def]
    """FastAPI dependency: at most `settings.<limit_attr>` calls per `window` seconds per IP.
    A limit of 0 disables it."""

    async def dependency(request: Request) -> None:
        allowed: int = getattr(request.app.state.settings, limit_attr)
        if allowed <= 0:
            return
        limiter: RateLimiter = request.app.state.limiter
        key = f"{name}:{client_ip(request)}"
        if limiter.hit(key, window) > allowed:
            raise too_many(limiter.retry_after(key, window))

    return dependency
