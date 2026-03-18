#!/usr/bin/env python3
"""Persistence and idempotency storage for Mini SOAR."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any

try:
    import psycopg
except ModuleNotFoundError:  # Optional dependency.
    psycopg = None  # type: ignore[assignment]


def hash_ioc(ioc: str) -> str:
    return hashlib.sha256(ioc.lower().encode("utf-8")).hexdigest()


class BaseStore:
    def seen_recent_ioc(self, ioc: str, window_seconds: int) -> bool:
        raise NotImplementedError

    def mark_ioc_seen(self, ioc: str, ioc_type: str) -> None:
        raise NotImplementedError

    def save_finding(self, correlation_id: str, finding: dict[str, Any]) -> None:
        raise NotImplementedError


class NullStore(BaseStore):
    def seen_recent_ioc(self, ioc: str, window_seconds: int) -> bool:
        return False

    def mark_ioc_seen(self, ioc: str, ioc_type: str) -> None:
        return None

    def save_finding(self, correlation_id: str, finding: dict[str, Any]) -> None:
        return None


@dataclass
class SQLiteStore(BaseStore):
    path: str

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, check_same_thread=False)

    def _initialize(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS ioc_seen (
                    ioc_hash TEXT PRIMARY KEY,
                    ioc TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    first_seen INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    seen_count INTEGER NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    correlation_id TEXT NOT NULL,
                    ioc TEXT NOT NULL,
                    ioc_type TEXT NOT NULL,
                    priority TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    generated_at TEXT NOT NULL,
                    payload_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def seen_recent_ioc(self, ioc: str, window_seconds: int) -> bool:
        ioc_h = hash_ioc(ioc)
        cutoff = int(time.time()) - window_seconds
        with self._connect() as conn:
            row = conn.execute(
                "SELECT last_seen FROM ioc_seen WHERE ioc_hash = ?",
                (ioc_h,),
            ).fetchone()
        if not row:
            return False
        return int(row[0]) >= cutoff

    def mark_ioc_seen(self, ioc: str, ioc_type: str) -> None:
        ioc_h = hash_ioc(ioc)
        now_ts = int(time.time())
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO ioc_seen (ioc_hash, ioc, ioc_type, first_seen, last_seen, seen_count)
                    VALUES (?, ?, ?, ?, ?, 1)
                    ON CONFLICT(ioc_hash) DO UPDATE SET
                        ioc=excluded.ioc,
                        ioc_type=excluded.ioc_type,
                        last_seen=excluded.last_seen,
                        seen_count=ioc_seen.seen_count + 1
                    """,
                    (ioc_h, ioc, ioc_type, now_ts, now_ts),
                )
                conn.commit()

    def save_finding(self, correlation_id: str, finding: dict[str, Any]) -> None:
        with self._lock:
            with self._connect() as conn:
                conn.execute(
                    """
                    INSERT INTO findings (
                        correlation_id, ioc, ioc_type, priority, risk_score, generated_at, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        correlation_id,
                        str(finding.get("ioc", "")),
                        str(finding.get("ioc_type", "")),
                        str(finding.get("priority", "low")),
                        int(finding.get("risk_score", 0)),
                        str(finding.get("generated_at", "")),
                        json.dumps(finding, ensure_ascii=False),
                    ),
                )
                conn.commit()


@dataclass
class PostgresStore(BaseStore):
    dsn: str

    def __post_init__(self) -> None:
        if psycopg is None:
            raise RuntimeError("Postgres requested but `psycopg` is not installed.")
        self._lock = threading.Lock()
        self._initialize()

    def _connect(self):
        return psycopg.connect(self.dsn)

    def _initialize(self) -> None:
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ioc_seen (
                        ioc_hash TEXT PRIMARY KEY,
                        ioc TEXT NOT NULL,
                        ioc_type TEXT NOT NULL,
                        first_seen BIGINT NOT NULL,
                        last_seen BIGINT NOT NULL,
                        seen_count INTEGER NOT NULL
                    )
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS findings (
                        id BIGSERIAL PRIMARY KEY,
                        correlation_id TEXT NOT NULL,
                        ioc TEXT NOT NULL,
                        ioc_type TEXT NOT NULL,
                        priority TEXT NOT NULL,
                        risk_score INTEGER NOT NULL,
                        generated_at TEXT NOT NULL,
                        payload_json TEXT NOT NULL
                    )
                    """
                )
            conn.commit()

    def seen_recent_ioc(self, ioc: str, window_seconds: int) -> bool:
        ioc_h = hash_ioc(ioc)
        cutoff = int(time.time()) - window_seconds
        with self._connect() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT last_seen FROM ioc_seen WHERE ioc_hash = %s", (ioc_h,))
                row = cur.fetchone()
        if not row:
            return False
        return int(row[0]) >= cutoff

    def mark_ioc_seen(self, ioc: str, ioc_type: str) -> None:
        ioc_h = hash_ioc(ioc)
        now_ts = int(time.time())
        with self._lock:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO ioc_seen (ioc_hash, ioc, ioc_type, first_seen, last_seen, seen_count)
                        VALUES (%s, %s, %s, %s, %s, 1)
                        ON CONFLICT(ioc_hash) DO UPDATE SET
                            ioc=EXCLUDED.ioc,
                            ioc_type=EXCLUDED.ioc_type,
                            last_seen=EXCLUDED.last_seen,
                            seen_count=ioc_seen.seen_count + 1
                        """,
                        (ioc_h, ioc, ioc_type, now_ts, now_ts),
                    )
                conn.commit()

    def save_finding(self, correlation_id: str, finding: dict[str, Any]) -> None:
        with self._lock:
            with self._connect() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        INSERT INTO findings (
                            correlation_id, ioc, ioc_type, priority, risk_score, generated_at, payload_json
                        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """,
                        (
                            correlation_id,
                            str(finding.get("ioc", "")),
                            str(finding.get("ioc_type", "")),
                            str(finding.get("priority", "low")),
                            int(finding.get("risk_score", 0)),
                            str(finding.get("generated_at", "")),
                            json.dumps(finding, ensure_ascii=False),
                        ),
                    )
                conn.commit()


def create_store(database_url: str | None) -> BaseStore:
    if not database_url:
        return NullStore()

    if database_url.startswith("sqlite:///"):
        path = database_url.removeprefix("sqlite:///")
        return SQLiteStore(path=path)

    if database_url.startswith("postgres://") or database_url.startswith("postgresql://"):
        return PostgresStore(dsn=database_url)

    raise RuntimeError(f"Unsupported database URL: {database_url}")
