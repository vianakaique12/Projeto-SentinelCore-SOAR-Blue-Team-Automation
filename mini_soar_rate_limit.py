#!/usr/bin/env python3
"""Dual-backend rate limiter for SentinelCore SOAR.

Two implementations are provided:

InMemoryRateLimiter
    Sliding-window counter backed by a per-process dict and a threading.Lock.
    Simple and zero-dependency, but **not shared across OS processes**: each
    Uvicorn worker maintains its own counter, so the effective limit becomes
    ``configured_limit × num_workers``.  Suitable for development or
    single-worker deployments.

RedisRateLimiter
    Sliding-window counter backed by a Redis sorted set.  All workers share
    the same counter, so the configured limit is enforced globally regardless
    of how many workers are running.  An atomic Lua script is used so that the
    check-then-add sequence is race-free.

Factory
    ``get_rate_limiter()`` reads environment variables and returns the best
    available implementation, falling back to in-memory with a warning when
    Redis is unreachable.

Environment variables
---------------------
MINI_SOAR_RATE_LIMIT_BACKEND
    ``memory`` (default) or ``redis``.
MINI_SOAR_RATE_LIMIT_REDIS_URL
    Full Redis URL used by ``RedisRateLimiter``
    (default: ``redis://localhost:6379/0``).
WEB_CONCURRENCY / UVICORN_WORKERS
    If either is set to a value > 1 and the in-memory backend is active,
    a startup warning is emitted to remind the operator.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from abc import ABC, abstractmethod
from collections import defaultdict
from uuid import uuid4

_log = logging.getLogger("mini_soar.rate_limit")


# ── Lua script for atomic Redis sliding-window check-and-add ──────────────────
#
# Algorithm:
#   1. Remove all members with score (timestamp) < cutoff  → prune expired
#   2. Count remaining members
#   3. If count >= limit → reject (return 0)
#   4. Otherwise add this request and set a TTL on the key → allow (return 1)
#
# Using a Lua script ensures steps 2–4 are executed atomically on the Redis
# server, preventing TOCTOU races between concurrent workers.

_LUA_SLIDING_WINDOW = """
local key    = KEYS[1]
local now    = tonumber(ARGV[1])
local cutoff = tonumber(ARGV[2])
local limit  = tonumber(ARGV[3])
local ttl    = tonumber(ARGV[4])
local member = ARGV[5]

redis.call('ZREMRANGEBYSCORE', key, '-inf', cutoff)
local count = tonumber(redis.call('ZCARD', key))
if count >= limit then
    return 0
end
redis.call('ZADD', key, now, member)
redis.call('EXPIRE', key, ttl)
return 1
"""


# ── Abstract base ──────────────────────────────────────────────────────────────

class RateLimiter(ABC):
    """Abstract rate limiter interface."""

    @abstractmethod
    def is_allowed(self, client_id: str, limit: int, window_seconds: int) -> bool:
        """Return True if this request is within the allowed rate.

        Side effect: if True, the current request is recorded so it counts
        towards future calls.  If False, nothing is recorded.
        """

    @property
    @abstractmethod
    def backend_name(self) -> str:
        """Human-readable name of this backend (for observability)."""


# ── In-memory implementation ──────────────────────────────────────────────────

class InMemoryRateLimiter(RateLimiter):
    """Thread-safe in-process sliding-window rate limiter.

    Limitations
    -----------
    - State is **not shared** across OS processes.  With multiple Uvicorn
      workers (``--workers N``) each worker enforces the limit independently,
      so the actual throughput allowed is up to ``limit × N`` per window.
    - Memory grows proportionally to the number of distinct client IDs that
      have made requests in the current window.  Old buckets are pruned lazily
      when a client makes a new request.
    """

    def __init__(self) -> None:
        self._state: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    @property
    def backend_name(self) -> str:
        return "memory"

    def is_allowed(self, client_id: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            # Prune entries outside the window
            current = [t for t in self._state[client_id] if t >= cutoff]
            if len(current) >= limit:
                return False
            current.append(now)
            self._state[client_id] = current
            return True

    def current_count(self, client_id: str, window_seconds: int) -> int:
        """Return the number of recorded requests within *window_seconds* (test helper)."""
        now = time.time()
        cutoff = now - window_seconds
        with self._lock:
            return len([t for t in self._state[client_id] if t >= cutoff])

    def reset(self, client_id: str | None = None) -> None:
        """Clear rate-limit state (useful in tests)."""
        with self._lock:
            if client_id is None:
                self._state.clear()
            else:
                self._state.pop(client_id, None)


# ── Redis implementation ──────────────────────────────────────────────────────

class RedisRateLimiter(RateLimiter):
    """Globally-consistent sliding-window rate limiter backed by Redis.

    All workers sharing the same Redis instance enforce a single counter per
    client, so the configured limit is accurate regardless of concurrency.

    Each client gets a sorted set at ``mini_soar:rl:<client_id>``.  Members
    are unique per request (``<timestamp>:<random8>``), scored by request
    timestamp.  An atomic Lua script prunes expired members, checks the count,
    and conditionally inserts the new request.
    """

    def __init__(self, redis_url: str) -> None:
        import redis  # Local import — optional at module level

        self._redis = redis.from_url(redis_url, decode_responses=True)
        self._script = self._redis.register_script(_LUA_SLIDING_WINDOW)

    @property
    def backend_name(self) -> str:
        return "redis"

    def is_allowed(self, client_id: str, limit: int, window_seconds: int) -> bool:
        now = time.time()
        cutoff = now - window_seconds
        member = f"{now}:{uuid4().hex[:8]}"
        key = f"mini_soar:rl:{client_id}"
        # TTL = window + 1s so the key disappears shortly after the window expires
        ttl = window_seconds + 1
        result = self._script(
            keys=[key],
            args=[now, cutoff, limit, ttl, member],
        )
        return bool(result)

    def ping(self) -> None:
        """Raise if the Redis server is unreachable."""
        self._redis.ping()

    def current_count(self, client_id: str, window_seconds: int) -> int:
        """Return the number of recorded requests within *window_seconds* (test helper)."""
        now = time.time()
        cutoff = now - window_seconds
        key = f"mini_soar:rl:{client_id}"
        return self._redis.zcount(key, cutoff, "+inf")

    def reset(self, client_id: str | None = None) -> None:
        """Delete rate-limit keys (useful in tests)."""
        if client_id is None:
            for k in self._redis.scan_iter("mini_soar:rl:*"):
                self._redis.delete(k)
        else:
            self._redis.delete(f"mini_soar:rl:{client_id}")


# ── Factory ────────────────────────────────────────────────────────────────────

def get_rate_limiter() -> RateLimiter:
    """Return the appropriate rate limiter based on environment configuration.

    Resolution order:
    1. If ``MINI_SOAR_RATE_LIMIT_BACKEND=redis`` and the Redis server is
       reachable → ``RedisRateLimiter``.
    2. If Redis is requested but unavailable → log a warning and fall back to
       ``InMemoryRateLimiter``.
    3. Otherwise (``memory`` or unset) → ``InMemoryRateLimiter``.

    If multi-worker mode is detected (WEB_CONCURRENCY > 1 or UVICORN_WORKERS
    > 1) and the in-memory backend is selected, an additional warning is
    emitted advising the operator to switch to the Redis backend.
    """
    backend = os.getenv("MINI_SOAR_RATE_LIMIT_BACKEND", "memory").lower()
    redis_url = os.getenv(
        "MINI_SOAR_RATE_LIMIT_REDIS_URL", "redis://localhost:6379/0"
    )

    if backend == "redis":
        try:
            limiter = RedisRateLimiter(redis_url)
            limiter.ping()
            _log.info(
                "Rate limiter: Redis backend active (%s)", redis_url.split("@")[-1]
            )
            return limiter
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "Redis rate limiter unavailable (%s) — falling back to in-memory. "
                "Set MINI_SOAR_RATE_LIMIT_BACKEND=memory to suppress this warning.",
                exc,
            )

    _warn_if_multi_worker()
    return InMemoryRateLimiter()


def _warn_if_multi_worker() -> None:
    workers = max(
        int(os.getenv("WEB_CONCURRENCY", "1")),
        int(os.getenv("UVICORN_WORKERS", "1")),
    )
    if workers > 1:
        _log.warning(
            "In-memory rate limiter active with %d workers. "
            "Effective per-client limit is %d× the configured value. "
            "Use MINI_SOAR_RATE_LIMIT_BACKEND=redis for accurate "
            "multi-worker rate limiting.",
            workers,
            workers,
        )
