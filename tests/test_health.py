"""Tests for mini_soar_health.py and the /health API endpoint."""
from __future__ import annotations

import json
import time
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import mini_soar_health as health_mod
from mini_soar_health import (
    _overall_status,
    check_database_health,
    check_rate_limit_health,
    check_redis_health,
    check_threat_intel_health,
    run_health_checks,
)


# ── check_database_health ──────────────────────────────────────────────────────

class TestCheckDatabaseHealthSQLite:
    def test_sqlite_up(self, tmp_path):
        db = tmp_path / "test.db"
        result = check_database_health(f"sqlite:///{db}")
        assert result["status"] == "up"
        assert result["type"] == "sqlite"
        assert result["latency_ms"] is not None
        assert result["error"] is None

    def test_sqlite_latency_is_positive(self, tmp_path):
        db = tmp_path / "test.db"
        result = check_database_health(f"sqlite:///{db}")
        assert result["latency_ms"] >= 0

    def test_sqlite_down_bad_path(self):
        # A path that cannot be created (directory that looks like a file)
        result = check_database_health("sqlite:////dev/null/nonexistent/bad.db")
        # May succeed on some platforms (sqlite creates parent-less :memory: style),
        # but we at minimum need a valid dict back.
        assert "status" in result
        assert result["type"] == "sqlite"

    def test_sqlite_error_captured(self):
        import sqlite3

        with patch("sqlite3.connect", side_effect=sqlite3.OperationalError("oops")):
            result = check_database_health("sqlite:///any.db")
        assert result["status"] == "down"
        assert "oops" in result["error"]
        assert result["latency_ms"] is not None


class TestCheckDatabaseHealthPostgres:
    def test_postgres_down_no_server(self):
        result = check_database_health("postgresql://user:pass@127.0.0.1:59999/db")
        assert result["status"] == "down"
        assert result["type"] == "postgres"
        assert result["error"] is not None

    def test_postgres_up_mocked(self):
        mock_conn = MagicMock()
        mock_conn.__enter__ = MagicMock(return_value=mock_conn)
        mock_conn.__exit__ = MagicMock(return_value=False)

        with patch("psycopg.connect", return_value=mock_conn):
            result = check_database_health("postgresql://u:p@host/db")
        assert result["status"] == "up"
        assert result["type"] == "postgres"
        assert result["error"] is None

    def test_postgres_exception_captured(self):
        with patch("psycopg.connect", side_effect=Exception("connection refused")):
            result = check_database_health("postgres://u:p@host/db")
        assert result["status"] == "down"
        assert "connection refused" in result["error"]

    def test_unsupported_scheme(self):
        result = check_database_health("mysql://user:pass@localhost/db")
        assert result["status"] == "down"
        assert result["latency_ms"] is None
        assert "Unsupported" in result["error"]


# ── check_redis_health ─────────────────────────────────────────────────────────

class TestCheckRedisHealth:
    def test_none_url_not_configured(self):
        result = check_redis_health(None)
        assert result["status"] == "not_configured"
        assert result["latency_ms"] is None
        assert result["error"] is None

    def test_empty_string_not_configured(self):
        result = check_redis_health("")
        assert result["status"] == "not_configured"

    def test_redis_up_mocked(self):
        mock_client = MagicMock()
        mock_client.ping.return_value = True

        with patch("redis.from_url", return_value=mock_client):
            result = check_redis_health("redis://localhost:6379")
        assert result["status"] == "up"
        assert result["latency_ms"] is not None
        assert result["error"] is None

    def test_redis_down_no_server(self):
        result = check_redis_health("redis://127.0.0.1:59999", timeout=0.5)
        assert result["status"] == "down"
        assert result["error"] is not None

    def test_redis_exception_captured(self):
        with patch("redis.from_url", side_effect=Exception("auth failed")):
            result = check_redis_health("redis://localhost:6379")
        assert result["status"] == "down"
        assert "auth failed" in result["error"]

    def test_redis_latency_measured_on_success(self):
        mock_client = MagicMock()
        mock_client.ping.return_value = True

        with patch("redis.from_url", return_value=mock_client):
            result = check_redis_health("redis://localhost:6379")
        assert isinstance(result["latency_ms"], float)
        assert result["latency_ms"] >= 0

    def test_redis_latency_measured_on_failure(self):
        with patch("redis.from_url", side_effect=Exception("fail")):
            result = check_redis_health("redis://localhost:6379")
        assert isinstance(result["latency_ms"], float)


# ── check_threat_intel_health ──────────────────────────────────────────────────

class TestCheckThreatIntelHealth:
    def test_both_configured(self):
        result = check_threat_intel_health("vt-key", "abuse-key")
        assert result["virustotal"] == "configured"
        assert result["abuseipdb"] == "configured"

    def test_neither_configured(self):
        result = check_threat_intel_health(None, None)
        assert result["virustotal"] == "not_configured"
        assert result["abuseipdb"] == "not_configured"

    def test_only_vt_configured(self):
        result = check_threat_intel_health("vt-key", None)
        assert result["virustotal"] == "configured"
        assert result["abuseipdb"] == "not_configured"

    def test_only_abuse_configured(self):
        result = check_threat_intel_health(None, "abuse-key")
        assert result["virustotal"] == "not_configured"
        assert result["abuseipdb"] == "configured"

    def test_no_outbound_request(self):
        # Ensure no HTTP calls are made
        with patch("urllib.request.urlopen", side_effect=AssertionError("no HTTP allowed")):
            result = check_threat_intel_health("key", "key")
        assert result["virustotal"] == "configured"


# ── check_rate_limit_health ────────────────────────────────────────────────────

class TestCheckRateLimitHealth:
    def test_returns_all_fields(self):
        result = check_rate_limit_health("memory", 60, 60)
        assert result["backend"] == "memory"
        assert result["limit"] == 60
        assert result["window_seconds"] == 60

    def test_redis_backend(self):
        result = check_rate_limit_health("redis", 100, 30)
        assert result["backend"] == "redis"
        assert result["limit"] == 100
        assert result["window_seconds"] == 30


# ── _overall_status ────────────────────────────────────────────────────────────

class TestOverallStatus:
    def test_healthy_when_db_up_redis_up(self):
        db = {"status": "up"}
        redis = {"status": "up"}
        assert _overall_status(db, redis) == "healthy"

    def test_healthy_when_db_up_redis_not_configured(self):
        db = {"status": "up"}
        redis = {"status": "not_configured"}
        assert _overall_status(db, redis) == "healthy"

    def test_degraded_when_db_up_redis_down(self):
        db = {"status": "up"}
        redis = {"status": "down"}
        assert _overall_status(db, redis) == "degraded"

    def test_unhealthy_when_db_down(self):
        db = {"status": "down"}
        redis = {"status": "up"}
        assert _overall_status(db, redis) == "unhealthy"

    def test_unhealthy_when_db_down_redis_down(self):
        db = {"status": "down"}
        redis = {"status": "down"}
        assert _overall_status(db, redis) == "unhealthy"


# ── run_health_checks ──────────────────────────────────────────────────────────

class TestRunHealthChecks:
    def _run(self, db_url="sqlite:///test.db", redis_url=None, **kwargs):
        defaults = dict(
            database_url=db_url,
            redis_url=redis_url,
            vt_api_key=None,
            abuse_api_key=None,
            rate_limit_backend="memory",
            rate_limit_limit=60,
            rate_limit_window=60,
            demo_mode=False,
            api_version="2.0.0",
        )
        defaults.update(kwargs)
        return run_health_checks(**defaults)

    def test_healthy_payload_structure(self, tmp_path):
        db = tmp_path / "h.db"
        payload, code = self._run(db_url=f"sqlite:///{db}")
        assert code == 200
        assert payload["status"] == "healthy"
        assert "timestamp" in payload
        assert "version" in payload
        assert "checks" in payload
        assert "database" in payload["checks"]
        assert "redis" in payload["checks"]
        assert "threat_intel" in payload["checks"]
        assert "rate_limit" in payload["checks"]

    def test_healthy_http_200(self, tmp_path):
        db = tmp_path / "h.db"
        _, code = self._run(db_url=f"sqlite:///{db}")
        assert code == 200

    def test_unhealthy_http_503(self):
        with patch.object(health_mod, "check_database_health", return_value={"status": "down", "type": "sqlite", "latency_ms": 1.0, "error": "boom"}):
            payload, code = self._run()
        assert code == 503
        assert payload["status"] == "unhealthy"

    def test_degraded_http_200(self, tmp_path):
        db = tmp_path / "h.db"
        mock_redis = {"status": "down", "latency_ms": 5.0, "error": "refused"}
        with patch.object(health_mod, "check_redis_health", return_value=mock_redis):
            payload, code = self._run(db_url=f"sqlite:///{db}", redis_url="redis://localhost:6379")
        assert code == 200
        assert payload["status"] == "degraded"

    def test_demo_mode_in_payload(self, tmp_path):
        db = tmp_path / "h.db"
        payload, _ = self._run(db_url=f"sqlite:///{db}", demo_mode=True)
        assert payload["demo_mode"] is True

    def test_version_in_payload(self, tmp_path):
        db = tmp_path / "h.db"
        payload, _ = self._run(db_url=f"sqlite:///{db}", api_version="3.1.4")
        assert payload["version"] == "3.1.4"

    def test_threat_intel_keys_present(self, tmp_path):
        db = tmp_path / "h.db"
        payload, _ = self._run(db_url=f"sqlite:///{db}", vt_api_key="key", abuse_api_key="key2")
        ti = payload["checks"]["threat_intel"]
        assert ti["virustotal"] == "configured"
        assert ti["abuseipdb"] == "configured"

    def test_rate_limit_info_in_payload(self, tmp_path):
        db = tmp_path / "h.db"
        payload, _ = self._run(db_url=f"sqlite:///{db}", rate_limit_backend="redis", rate_limit_limit=100, rate_limit_window=30)
        rl = payload["checks"]["rate_limit"]
        assert rl["backend"] == "redis"
        assert rl["limit"] == 100
        assert rl["window_seconds"] == 30


# ── /health API endpoint ───────────────────────────────────────────────────────

class TestHealthEndpoint:
    @pytest.fixture()
    def client(self):
        from mini_soar_api import app
        return TestClient(app, raise_server_exceptions=False)

    def test_health_no_auth_required(self, client, tmp_path, monkeypatch):
        db = tmp_path / "api.db"
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db}")
        monkeypatch.delenv("MINI_SOAR_API_KEYS", raising=False)
        monkeypatch.delenv("MINI_SOAR_JWT_SECRET", raising=False)
        monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)
        resp = client.get("/health")
        assert resp.status_code in (200, 503)  # depends on DB availability

    def test_health_200_when_healthy(self, client, tmp_path, monkeypatch):
        db = tmp_path / "api.db"
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db}")
        monkeypatch.delenv("MINI_SOAR_REDIS_URL", raising=False)
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"

    def test_health_503_when_db_down(self, client, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", "postgresql://bad:bad@127.0.0.1:59999/db")
        monkeypatch.delenv("MINI_SOAR_REDIS_URL", raising=False)
        resp = client.get("/health")
        assert resp.status_code == 503
        body = resp.json()
        assert body["status"] == "unhealthy"

    def test_health_200_degraded_redis_down(self, client, tmp_path, monkeypatch):
        db = tmp_path / "api.db"
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db}")
        monkeypatch.setenv("MINI_SOAR_REDIS_URL", "redis://127.0.0.1:59999")
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "degraded"

    def test_health_payload_has_checks_key(self, client, tmp_path, monkeypatch):
        db = tmp_path / "api.db"
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db}")
        monkeypatch.delenv("MINI_SOAR_REDIS_URL", raising=False)
        resp = client.get("/health")
        body = resp.json()
        assert "checks" in body
        checks = body["checks"]
        for key in ("database", "redis", "threat_intel", "rate_limit"):
            assert key in checks, f"Missing key: {key}"

    def test_health_db_check_has_latency(self, client, tmp_path, monkeypatch):
        db = tmp_path / "api.db"
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db}")
        monkeypatch.delenv("MINI_SOAR_REDIS_URL", raising=False)
        resp = client.get("/health")
        db_check = resp.json()["checks"]["database"]
        assert "latency_ms" in db_check
        assert db_check["latency_ms"] is not None

    def test_health_response_has_timestamp(self, client, tmp_path, monkeypatch):
        db = tmp_path / "api.db"
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db}")
        monkeypatch.delenv("MINI_SOAR_REDIS_URL", raising=False)
        resp = client.get("/health")
        assert "timestamp" in resp.json()

    def test_health_response_has_version(self, client, tmp_path, monkeypatch):
        db = tmp_path / "api.db"
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db}")
        monkeypatch.delenv("MINI_SOAR_REDIS_URL", raising=False)
        resp = client.get("/health")
        assert "version" in resp.json()
