"""Tests for InMemoryRateLimiter, RedisRateLimiter, and get_rate_limiter()."""

from __future__ import annotations

import os
import threading
import time
from typing import Any
from unittest.mock import MagicMock, patch, call

import pytest

from mini_soar_rate_limit import (
    InMemoryRateLimiter,
    RedisRateLimiter,
    get_rate_limiter,
)


# ══════════════════════════════════════════════════════════════════════════════
# InMemoryRateLimiter
# ══════════════════════════════════════════════════════════════════════════════

class TestInMemoryRateLimiter:

    def setup_method(self):
        self.limiter = InMemoryRateLimiter()

    # ── Basic allow / block ──────────────────────────────────────────────────

    def test_first_request_is_always_allowed(self):
        assert self.limiter.is_allowed("client1", limit=5, window_seconds=60) is True

    def test_requests_up_to_limit_are_allowed(self):
        for _ in range(5):
            assert self.limiter.is_allowed("client1", limit=5, window_seconds=60) is True

    def test_request_over_limit_is_rejected(self):
        for _ in range(5):
            self.limiter.is_allowed("client1", limit=5, window_seconds=60)
        assert self.limiter.is_allowed("client1", limit=5, window_seconds=60) is False

    def test_different_clients_are_independent(self):
        for _ in range(5):
            self.limiter.is_allowed("alice", limit=5, window_seconds=60)
        # Alice is full but Bob should still be allowed
        assert self.limiter.is_allowed("alice", limit=5, window_seconds=60) is False
        assert self.limiter.is_allowed("bob",   limit=5, window_seconds=60) is True

    def test_limit_of_one_allows_only_first_request(self):
        assert self.limiter.is_allowed("client1", limit=1, window_seconds=60) is True
        assert self.limiter.is_allowed("client1", limit=1, window_seconds=60) is False

    # ── Window expiry ────────────────────────────────────────────────────────

    def test_entries_outside_window_do_not_count(self):
        """Inject old timestamps directly to simulate expired window."""
        # Manually insert 5 old entries (2 hours ago)
        old_ts = time.time() - 7200
        self.limiter._state["client1"] = [old_ts] * 5

        # All old entries should be pruned → request should be allowed
        assert self.limiter.is_allowed("client1", limit=5, window_seconds=3600) is True

    def test_mixed_old_and_new_entries(self):
        """3 old (expired) + 3 recent entries against limit=5 → should allow."""
        old_ts = time.time() - 7200
        new_ts = time.time() - 10
        self.limiter._state["client1"] = [old_ts, old_ts, old_ts, new_ts, new_ts, new_ts]

        # Only 3 entries are within the 1-hour window, so one more should be OK
        assert self.limiter.is_allowed("client1", limit=5, window_seconds=3600) is True
        # Now 4 — still under limit
        assert self.limiter.is_allowed("client1", limit=5, window_seconds=3600) is True
        # Now 5 — at limit, next should be rejected
        assert self.limiter.is_allowed("client1", limit=5, window_seconds=3600) is False

    # ── current_count helper ─────────────────────────────────────────────────

    def test_current_count_reflects_allowed_requests(self):
        for _ in range(3):
            self.limiter.is_allowed("client1", limit=10, window_seconds=60)
        assert self.limiter.current_count("client1", window_seconds=60) == 3

    def test_current_count_excludes_expired_entries(self):
        old_ts = time.time() - 7200
        self.limiter._state["client1"] = [old_ts, old_ts, old_ts]
        assert self.limiter.current_count("client1", window_seconds=3600) == 0

    # ── reset ────────────────────────────────────────────────────────────────

    def test_reset_specific_client(self):
        for _ in range(5):
            self.limiter.is_allowed("client1", limit=5, window_seconds=60)
        self.limiter.reset("client1")
        assert self.limiter.is_allowed("client1", limit=5, window_seconds=60) is True

    def test_reset_all_clients(self):
        for _ in range(5):
            self.limiter.is_allowed("alice", limit=5, window_seconds=60)
            self.limiter.is_allowed("bob",   limit=5, window_seconds=60)
        self.limiter.reset()
        assert self.limiter.is_allowed("alice", limit=5, window_seconds=60) is True
        assert self.limiter.is_allowed("bob",   limit=5, window_seconds=60) is True

    # ── Thread safety ────────────────────────────────────────────────────────

    def test_concurrent_requests_respect_limit(self):
        """100 concurrent threads each making one request against limit=50."""
        results: list[bool] = []
        lock = threading.Lock()

        def make_request():
            allowed = self.limiter.is_allowed("shared", limit=50, window_seconds=60)
            with lock:
                results.append(allowed)

        threads = [threading.Thread(target=make_request) for _ in range(100)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        allowed_count  = sum(1 for r in results if r)
        rejected_count = sum(1 for r in results if not r)
        assert allowed_count  == 50
        assert rejected_count == 50

    # ── backend_name ─────────────────────────────────────────────────────────

    def test_backend_name(self):
        assert self.limiter.backend_name == "memory"


# ══════════════════════════════════════════════════════════════════════════════
# RedisRateLimiter (mocked Redis client)
# ══════════════════════════════════════════════════════════════════════════════

def _make_redis_limiter() -> tuple[RedisRateLimiter, MagicMock]:
    """Return a RedisRateLimiter with a mocked redis client."""
    with patch("redis.from_url") as mock_from_url:
        mock_redis = MagicMock()
        mock_from_url.return_value = mock_redis

        # register_script returns a callable; we control its return value per test
        mock_script = MagicMock()
        mock_redis.register_script.return_value = mock_script

        limiter = RedisRateLimiter("redis://localhost:6379/0")
        return limiter, mock_script


class TestRedisRateLimiter:

    # ── Allow / block based on Lua script result ──────────────────────────────

    def test_lua_returns_1_means_allowed(self):
        limiter, mock_script = _make_redis_limiter()
        mock_script.return_value = 1
        assert limiter.is_allowed("client1", limit=10, window_seconds=60) is True

    def test_lua_returns_0_means_rejected(self):
        limiter, mock_script = _make_redis_limiter()
        mock_script.return_value = 0
        assert limiter.is_allowed("client1", limit=10, window_seconds=60) is False

    def test_lua_called_with_correct_key(self):
        limiter, mock_script = _make_redis_limiter()
        mock_script.return_value = 1
        limiter.is_allowed("192.168.1.1", limit=10, window_seconds=60)

        call_kwargs = mock_script.call_args
        keys = call_kwargs[1]["keys"] if call_kwargs[1] else call_kwargs[0][0]
        assert keys == ["mini_soar:rl:192.168.1.1"]

    def test_lua_args_include_limit_and_ttl(self):
        limiter, mock_script = _make_redis_limiter()
        mock_script.return_value = 1
        limiter.is_allowed("client1", limit=30, window_seconds=120)

        call_kwargs = mock_script.call_args
        args = call_kwargs[1]["args"] if call_kwargs[1] else call_kwargs[0][1]
        # args = [now, cutoff, limit, ttl, member]
        assert int(args[2]) == 30       # limit
        assert int(args[3]) == 121      # ttl = window + 1

    def test_lua_called_once_per_request(self):
        limiter, mock_script = _make_redis_limiter()
        mock_script.return_value = 1
        for _ in range(5):
            limiter.is_allowed("client1", limit=10, window_seconds=60)
        assert mock_script.call_count == 5

    # ── current_count ─────────────────────────────────────────────────────────

    def test_current_count_calls_zcount(self):
        limiter, _ = _make_redis_limiter()
        limiter._redis.zcount.return_value = 7
        count = limiter.current_count("client1", window_seconds=60)
        assert count == 7
        limiter._redis.zcount.assert_called_once()

    # ── reset ─────────────────────────────────────────────────────────────────

    def test_reset_specific_client_deletes_key(self):
        limiter, _ = _make_redis_limiter()
        limiter.reset("client1")
        limiter._redis.delete.assert_called_once_with("mini_soar:rl:client1")

    def test_reset_all_scans_and_deletes(self):
        limiter, _ = _make_redis_limiter()
        limiter._redis.scan_iter.return_value = [
            "mini_soar:rl:a", "mini_soar:rl:b"
        ]
        limiter.reset()
        assert limiter._redis.delete.call_count == 2

    # ── ping ──────────────────────────────────────────────────────────────────

    def test_ping_delegates_to_redis(self):
        limiter, _ = _make_redis_limiter()
        limiter.ping()
        limiter._redis.ping.assert_called_once()

    # ── backend_name ──────────────────────────────────────────────────────────

    def test_backend_name(self):
        limiter, _ = _make_redis_limiter()
        assert limiter.backend_name == "redis"

    # ── member uniqueness ─────────────────────────────────────────────────────

    def test_consecutive_calls_use_unique_members(self):
        """Two rapid calls must use different sorted-set members to avoid collision."""
        limiter, mock_script = _make_redis_limiter()
        mock_script.return_value = 1
        limiter.is_allowed("client1", limit=10, window_seconds=60)
        limiter.is_allowed("client1", limit=10, window_seconds=60)

        calls = mock_script.call_args_list
        member_0 = calls[0][1]["args"][4]
        member_1 = calls[1][1]["args"][4]
        assert member_0 != member_1


# ══════════════════════════════════════════════════════════════════════════════
# get_rate_limiter() factory
# ══════════════════════════════════════════════════════════════════════════════

class TestGetRateLimiter:

    def test_default_returns_in_memory(self, monkeypatch):
        monkeypatch.delenv("MINI_SOAR_RATE_LIMIT_BACKEND", raising=False)
        limiter = get_rate_limiter()
        assert isinstance(limiter, InMemoryRateLimiter)
        assert limiter.backend_name == "memory"

    def test_explicit_memory_returns_in_memory(self, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_RATE_LIMIT_BACKEND", "memory")
        limiter = get_rate_limiter()
        assert isinstance(limiter, InMemoryRateLimiter)

    def test_redis_backend_returns_redis_limiter_when_reachable(self, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_RATE_LIMIT_BACKEND", "redis")
        monkeypatch.setenv("MINI_SOAR_RATE_LIMIT_REDIS_URL", "redis://localhost:6379/0")

        with patch("mini_soar_rate_limit.RedisRateLimiter") as MockRL:
            mock_instance = MagicMock()
            mock_instance.backend_name = "redis"
            MockRL.return_value = mock_instance

            limiter = get_rate_limiter()

            MockRL.assert_called_once_with("redis://localhost:6379/0")
            mock_instance.ping.assert_called_once()
            assert limiter is mock_instance

    def test_redis_backend_falls_back_to_memory_when_unreachable(self, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_RATE_LIMIT_BACKEND", "redis")

        with patch("mini_soar_rate_limit.RedisRateLimiter") as MockRL:
            MockRL.side_effect = Exception("Connection refused")
            limiter = get_rate_limiter()
            assert isinstance(limiter, InMemoryRateLimiter)

    def test_redis_backend_falls_back_when_ping_fails(self, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_RATE_LIMIT_BACKEND", "redis")

        with patch("mini_soar_rate_limit.RedisRateLimiter") as MockRL:
            mock_instance = MagicMock()
            mock_instance.ping.side_effect = Exception("PONG timeout")
            MockRL.return_value = mock_instance

            limiter = get_rate_limiter()
            assert isinstance(limiter, InMemoryRateLimiter)

    def test_multi_worker_warning_logged(self, monkeypatch, caplog):
        monkeypatch.delenv("MINI_SOAR_RATE_LIMIT_BACKEND", raising=False)
        monkeypatch.setenv("WEB_CONCURRENCY", "4")

        import logging
        with caplog.at_level(logging.WARNING, logger="mini_soar.rate_limit"):
            get_rate_limiter()

        assert any("4" in record.message and "worker" in record.message.lower()
                   for record in caplog.records)

    def test_single_worker_no_warning(self, monkeypatch, caplog):
        monkeypatch.delenv("MINI_SOAR_RATE_LIMIT_BACKEND", raising=False)
        monkeypatch.setenv("WEB_CONCURRENCY", "1")
        monkeypatch.setenv("UVICORN_WORKERS", "1")

        import logging
        with caplog.at_level(logging.WARNING, logger="mini_soar.rate_limit"):
            get_rate_limiter()

        assert not any("worker" in r.message.lower() for r in caplog.records)
