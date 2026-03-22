"""Tests for idempotency and deduplication (mini_soar_storage + process_ioc)."""

from __future__ import annotations

import os
import tempfile
import time
from typing import Any

import pytest

from mini_soar_storage import NullStore, SQLiteStore, hash_ioc
from mini_soar_core import RuntimeConfig, process_ioc


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _tmp_store() -> SQLiteStore:
    """Return a SQLiteStore backed by a temporary file."""
    fd, path = tempfile.mkstemp(suffix=".db")
    os.close(fd)
    return SQLiteStore(path=path)


def _cleanup(store: SQLiteStore) -> None:
    try:
        os.unlink(store.path)
    except OSError:
        pass


def _demo_config(store_path: str, window: int = 3600) -> RuntimeConfig:
    """RuntimeConfig in demo mode pointing at *store_path*."""
    return RuntimeConfig(
        demo_mode=True,
        enable_idempotency=True,
        idempotency_window_seconds=window,
        database_url=f"sqlite:///{store_path}",
        persist_findings=True,
        ticket_backend="none",
        log_level="WARNING",
        json_logs=False,
    )


_SAMPLE_FINDING: dict[str, Any] = {
    "ioc": "1.2.3.4",
    "ioc_type": "ip",
    "generated_at": "2024-01-01T00:00:00Z",
    "correlation_id": "test-corr",
    "risk_score": 55,
    "priority": "high",
    "reasons": ["VirusTotal malicious engines: 5 (medium)"],
    "virustotal": {"analysis_stats": {"malicious": 5}},
    "abuseipdb": None,
    "errors": [],
    "ticket": None,
    "integrations": [],
    "skipped": False,
    "mitre_attack": [],
    "runbook_steps": [],
}


# ── hash_ioc ────────────────────────────────────────────────────────────────────

def test_hash_ioc_same_ioc_and_type_is_stable():
    assert hash_ioc("1.2.3.4", "ip") == hash_ioc("1.2.3.4", "ip")


def test_hash_ioc_case_insensitive():
    assert hash_ioc("Evil.COM", "DOMAIN") == hash_ioc("evil.com", "domain")


def test_hash_ioc_different_types_produce_different_keys():
    assert hash_ioc("test", "ip") != hash_ioc("test", "domain")


def test_hash_ioc_without_type_is_backward_compatible():
    """Omitting ioc_type produces the same hash as passing an empty string."""
    assert hash_ioc("1.2.3.4") == hash_ioc("1.2.3.4", "")


# ── NullStore ───────────────────────────────────────────────────────────────────

def test_null_store_never_seen():
    store = NullStore()
    assert store.seen_recent_ioc("1.2.3.4", 3600, "ip") is False


def test_null_store_no_cached_finding():
    store = NullStore()
    assert store.get_cached_finding("1.2.3.4", "ip") is None


def test_null_store_mark_and_save_are_no_ops():
    store = NullStore()
    store.mark_ioc_seen("1.2.3.4", "ip")
    store.save_finding("corr-1", _SAMPLE_FINDING)
    # Still returns None — nothing was persisted
    assert store.seen_recent_ioc("1.2.3.4", 3600, "ip") is False
    assert store.get_cached_finding("1.2.3.4", "ip") is None


# ── SQLiteStore — seen_recent_ioc ───────────────────────────────────────────────

def test_sqlite_new_ioc_not_seen():
    store = _tmp_store()
    try:
        assert store.seen_recent_ioc("1.2.3.4", 3600, "ip") is False
    finally:
        _cleanup(store)


def test_sqlite_seen_within_window():
    store = _tmp_store()
    try:
        store.mark_ioc_seen("1.2.3.4", "ip")
        assert store.seen_recent_ioc("1.2.3.4", 3600, "ip") is True
    finally:
        _cleanup(store)


def test_sqlite_seen_outside_window():
    store = _tmp_store()
    try:
        store.mark_ioc_seen("1.2.3.4", "ip")
        # Backdate last_seen to 2 hours ago so it falls outside a 1-hour window
        import sqlite3
        with sqlite3.connect(store.path) as conn:
            conn.execute(
                "UPDATE ioc_seen SET last_seen = ? WHERE ioc = ?",
                (int(time.time()) - 7200, "1.2.3.4"),
            )
            conn.commit()
        assert store.seen_recent_ioc("1.2.3.4", 3600, "ip") is False
    finally:
        _cleanup(store)


def test_sqlite_seen_count_increments_on_each_mark():
    store = _tmp_store()
    try:
        store.mark_ioc_seen("1.2.3.4", "ip")
        store.mark_ioc_seen("1.2.3.4", "ip")
        store.mark_ioc_seen("1.2.3.4", "ip")
        import sqlite3
        with sqlite3.connect(store.path) as conn:
            (count,) = conn.execute(
                "SELECT seen_count FROM ioc_seen WHERE ioc = ?", ("1.2.3.4",)
            ).fetchone()
        assert count == 3
    finally:
        _cleanup(store)


def test_sqlite_different_ioc_types_are_independent():
    """Same IOC string with different types should NOT collide."""
    store = _tmp_store()
    try:
        store.mark_ioc_seen("ambiguous", "ip")
        assert store.seen_recent_ioc("ambiguous", 3600, "ip") is True
        assert store.seen_recent_ioc("ambiguous", 3600, "domain") is False
    finally:
        _cleanup(store)


# ── SQLiteStore — get_cached_finding ──────────────────────────────────────────

def test_sqlite_get_cached_returns_none_when_no_finding_saved():
    store = _tmp_store()
    try:
        store.mark_ioc_seen("1.2.3.4", "ip")
        assert store.get_cached_finding("1.2.3.4", "ip") is None
    finally:
        _cleanup(store)


def test_sqlite_get_cached_returns_stored_payload():
    store = _tmp_store()
    try:
        store.save_finding("corr-1", _SAMPLE_FINDING)
        cached = store.get_cached_finding("1.2.3.4", "ip")
        assert cached is not None
        assert cached["ioc"] == "1.2.3.4"
        assert cached["risk_score"] == 55
        assert cached["priority"] == "high"
    finally:
        _cleanup(store)


def test_sqlite_get_cached_returns_most_recent_finding():
    store = _tmp_store()
    try:
        old = {**_SAMPLE_FINDING, "risk_score": 20, "priority": "low"}
        new = {**_SAMPLE_FINDING, "risk_score": 90, "priority": "critical"}
        store.save_finding("corr-1", old)
        store.save_finding("corr-2", new)
        cached = store.get_cached_finding("1.2.3.4", "ip")
        assert cached is not None
        assert cached["risk_score"] == 90
        assert cached["priority"] == "critical"
    finally:
        _cleanup(store)


def test_sqlite_get_cached_does_not_return_finding_for_different_ioc():
    store = _tmp_store()
    try:
        store.save_finding("corr-1", _SAMPLE_FINDING)
        assert store.get_cached_finding("9.9.9.9", "ip") is None
    finally:
        _cleanup(store)


def test_sqlite_get_cached_does_not_return_finding_for_different_type():
    store = _tmp_store()
    try:
        store.save_finding("corr-1", _SAMPLE_FINDING)  # ioc_type="ip"
        # Querying the same value but a different type should return None
        assert store.get_cached_finding("1.2.3.4", "domain") is None
    finally:
        _cleanup(store)


# ── process_ioc integration ─────────────────────────────────────────────────────

def test_first_run_enriches_normally():
    """The first submission of an IOC must go through full enrichment."""
    store = _tmp_store()
    try:
        config = _demo_config(store.path)
        finding = process_ioc("8.8.8.8", config, store=store)
        assert finding["skipped"] is False
        assert finding.get("cached") is not True
        assert finding["risk_score"] > 0  # demo mode generates non-zero scores
        assert finding["ioc"] == "8.8.8.8"
    finally:
        _cleanup(store)


def test_second_run_within_window_returns_cached_finding():
    """Same IOC within the window must return the real cached finding, not a stub."""
    store = _tmp_store()
    try:
        config = _demo_config(store.path, window=3600)

        first  = process_ioc("8.8.8.8", config, store=store)
        second = process_ioc("8.8.8.8", config, store=store)

        assert second["skipped"] is True
        assert second["cached"] is True
        # The cached result must carry the original enrichment data, not zeros
        assert second["risk_score"] == first["risk_score"]
        assert second["priority"]   == first["priority"]
        assert second["virustotal"] == first["virustotal"]
        # Request-scoped fields are refreshed
        assert second["ioc"] == "8.8.8.8"
    finally:
        _cleanup(store)


def test_second_run_outside_window_reprocesses():
    """Same IOC outside the window must trigger fresh enrichment."""
    import sqlite3
    store = _tmp_store()
    try:
        config = _demo_config(store.path, window=3600)

        first = process_ioc("8.8.8.8", config, store=store)
        assert first["skipped"] is False

        # Backdate last_seen to 2 hours ago — outside the 1-hour window
        with sqlite3.connect(store.path) as conn:
            conn.execute(
                "UPDATE ioc_seen SET last_seen = ? WHERE ioc = ?",
                (int(time.time()) - 7200, "8.8.8.8"),
            )
            conn.commit()

        second = process_ioc("8.8.8.8", config, store=store)
        assert second["skipped"] is False
        assert second.get("cached") is not True
    finally:
        _cleanup(store)


def test_idempotency_disabled_always_reprocesses():
    """With enable_idempotency=False, every submission must be freshly enriched."""
    store = _tmp_store()
    try:
        config = _demo_config(store.path, window=3600)
        config = RuntimeConfig(
            demo_mode=True,
            enable_idempotency=False,
            idempotency_window_seconds=3600,
            database_url=f"sqlite:///{store.path}",
            persist_findings=True,
            ticket_backend="none",
            log_level="WARNING",
            json_logs=False,
        )

        first  = process_ioc("8.8.8.8", config, store=store)
        second = process_ioc("8.8.8.8", config, store=store)

        assert first["skipped"]  is False
        assert second["skipped"] is False
        assert second.get("cached") is not True
    finally:
        _cleanup(store)


def test_cached_finding_carries_mitre_and_runbook():
    """The cached finding must preserve mitre_attack and runbook_steps."""
    store = _tmp_store()
    try:
        config = _demo_config(store.path, window=3600)

        process_ioc("8.8.8.8", config, store=store)
        second = process_ioc("8.8.8.8", config, store=store)

        assert second["cached"] is True
        assert isinstance(second.get("mitre_attack"), list)
        assert isinstance(second.get("runbook_steps"), list)
        assert len(second["mitre_attack"]) > 0
        assert len(second["runbook_steps"]) > 0
    finally:
        _cleanup(store)


def test_different_iocs_within_window_are_independent():
    """Two distinct IOCs must each be enriched independently."""
    store = _tmp_store()
    try:
        config = _demo_config(store.path, window=3600)

        f1 = process_ioc("8.8.8.8",   config, store=store)
        f2 = process_ioc("1.1.1.1",   config, store=store)
        r1 = process_ioc("8.8.8.8",   config, store=store)
        r2 = process_ioc("1.1.1.1",   config, store=store)

        assert f1["skipped"] is False
        assert f2["skipped"] is False
        assert r1["cached"]  is True and r1["ioc"] == "8.8.8.8"
        assert r2["cached"]  is True and r2["ioc"] == "1.1.1.1"
    finally:
        _cleanup(store)


def test_persist_findings_false_falls_back_to_stub():
    """When persist_findings=False, a cache hit has no stored finding to return."""
    store = _tmp_store()
    try:
        config = RuntimeConfig(
            demo_mode=True,
            enable_idempotency=True,
            idempotency_window_seconds=3600,
            database_url=f"sqlite:///{store.path}",
            persist_findings=False,   # ← findings are NOT saved
            ticket_backend="none",
            log_level="WARNING",
            json_logs=False,
        )

        process_ioc("8.8.8.8", config, store=store)
        second = process_ioc("8.8.8.8", config, store=store)

        # Skipped, but no cached finding available → stub with cached=False
        assert second["skipped"] is True
        assert second.get("cached") is False
    finally:
        _cleanup(store)
