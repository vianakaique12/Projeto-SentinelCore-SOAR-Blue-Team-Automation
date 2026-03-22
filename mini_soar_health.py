#!/usr/bin/env python3
"""Health check helpers for the SentinelCore SOAR API.

Each check function is independent, catches all exceptions internally, and
always returns a dict — it never raises.  A per-check timeout (default 2 s)
keeps /health from blocking under degraded infrastructure conditions.

Status semantics
----------------
healthy   Database is up AND Redis is either up or not configured.
degraded  Database is up BUT Redis is configured and down.
unhealthy Database is down (regardless of Redis or anything else).

HTTP codes: healthy/degraded → 200, unhealthy → 503.
"""

from __future__ import annotations

import time
from typing import Any


_DEFAULT_TIMEOUT: float = 2.0


# ── Individual check functions ─────────────────────────────────────────────────

def check_database_health(
    database_url: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Ping the configured database and measure latency.

    Supported backends: SQLite (``sqlite:///``) and PostgreSQL
    (``postgres://`` / ``postgresql://``).
    """
    if database_url.startswith("sqlite:///"):
        path = database_url.removeprefix("sqlite:///")
        return _check_sqlite(path, timeout)

    if database_url.startswith("postgres://") or database_url.startswith("postgresql://"):
        return _check_postgres(database_url, timeout)

    return {
        "status": "down",
        "type": "unknown",
        "latency_ms": None,
        "error": f"Unsupported database URL scheme: {database_url.split(':')[0]}",
    }


def _check_sqlite(path: str, timeout: float) -> dict[str, Any]:
    import sqlite3

    start = time.perf_counter()
    try:
        with sqlite3.connect(path, timeout=timeout) as conn:
            conn.execute("SELECT 1").fetchone()
        return {
            "status": "up",
            "type": "sqlite",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "down",
            "type": "sqlite",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
            "error": str(exc),
        }


def _check_postgres(dsn: str, timeout: float) -> dict[str, Any]:
    start = time.perf_counter()
    try:
        import psycopg  # optional dependency

        with psycopg.connect(dsn, connect_timeout=int(timeout)) as conn:
            conn.execute("SELECT 1").fetchone()
        return {
            "status": "up",
            "type": "postgres",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "down",
            "type": "postgres",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
            "error": str(exc),
        }


def check_redis_health(
    redis_url: str | None,
    timeout: float = _DEFAULT_TIMEOUT,
) -> dict[str, Any]:
    """Ping a Redis server and measure latency.

    Returns ``"not_configured"`` if *redis_url* is falsy — this is not an
    error state, it just means the async queue / Redis rate-limit backend
    is not in use.
    """
    if not redis_url:
        return {"status": "not_configured", "latency_ms": None, "error": None}

    start = time.perf_counter()
    try:
        import redis as redis_module

        client = redis_module.from_url(
            redis_url,
            socket_connect_timeout=timeout,
            socket_timeout=timeout,
            decode_responses=True,
        )
        client.ping()
        return {
            "status": "up",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
            "error": None,
        }
    except Exception as exc:
        return {
            "status": "down",
            "latency_ms": round((time.perf_counter() - start) * 1000, 2),
            "error": str(exc),
        }


def check_threat_intel_health(
    vt_api_key: str | None,
    abuse_api_key: str | None,
) -> dict[str, str]:
    """Report whether each threat-intel API key is configured.

    Intentionally does NOT make any outbound request — that would consume
    rate-limit quota on every health poll.
    """
    return {
        "virustotal": "configured" if vt_api_key else "not_configured",
        "abuseipdb":  "configured" if abuse_api_key else "not_configured",
    }


def check_rate_limit_health(
    backend: str,
    limit: int,
    window_seconds: int,
) -> dict[str, Any]:
    """Return the active rate-limit configuration (no I/O required)."""
    return {
        "backend":        backend,
        "limit":          limit,
        "window_seconds": window_seconds,
    }


# ── Aggregator ─────────────────────────────────────────────────────────────────

def _overall_status(db: dict[str, Any], redis: dict[str, Any]) -> str:
    """Derive the overall health status from individual check results."""
    if db["status"] != "up":
        return "unhealthy"
    if redis["status"] == "down":
        return "degraded"
    return "healthy"


def run_health_checks(
    database_url: str,
    redis_url: str | None,
    vt_api_key: str | None,
    abuse_api_key: str | None,
    rate_limit_backend: str,
    rate_limit_limit: int,
    rate_limit_window: int,
    demo_mode: bool,
    api_version: str,
    timeout: float = _DEFAULT_TIMEOUT,
) -> tuple[dict[str, Any], int]:
    """Run all health checks and return ``(response_payload, http_status_code)``."""
    from mini_soar_enrichment import utc_now_iso

    db_check    = check_database_health(database_url, timeout)
    redis_check = check_redis_health(redis_url, timeout)
    ti_check    = check_threat_intel_health(vt_api_key, abuse_api_key)
    rl_check    = check_rate_limit_health(rate_limit_backend, rate_limit_limit, rate_limit_window)

    overall = _overall_status(db_check, redis_check)
    http_code = 503 if overall == "unhealthy" else 200

    payload: dict[str, Any] = {
        "status":    overall,
        "timestamp": utc_now_iso(),
        "version":   api_version,
        "demo_mode": demo_mode,
        "checks": {
            "database":    db_check,
            "redis":       redis_check,
            "threat_intel": ti_check,
            "rate_limit":  rl_check,
        },
    }
    return payload, http_code
