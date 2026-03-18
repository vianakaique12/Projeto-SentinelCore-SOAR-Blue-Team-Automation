from __future__ import annotations

from fastapi.testclient import TestClient

import mini_soar_api


def _fake_report(correlation_id: str | None = None) -> dict:
    return {
        "generated_at": "2026-01-01T00:00:00+00:00",
        "correlation_id": correlation_id,
        "summary": {
            "total_iocs": 1,
            "with_errors": 0,
            "high_or_critical": 0,
            "skipped_by_idempotency": 0,
            "tickets_opened": 0,
            "ticket_backend": "none",
            "ticket_threshold": 70,
            "integration_targets": [],
            "integration_threshold": 60,
            "integration_attempts": 0,
            "integration_success": 0,
            "integration_failed": 0,
            "avg_risk_score": 0.0,
        },
        "findings": [
            {
                "ioc": "8.8.8.8",
                "ioc_type": "ip",
                "generated_at": "2026-01-01T00:00:00+00:00",
                "correlation_id": correlation_id,
                "risk_score": 0,
                "priority": "low",
                "reasons": [],
                "virustotal": None,
                "abuseipdb": None,
                "errors": [],
                "ticket": None,
                "integrations": [],
                "skipped": False,
                "mitre_attack": [],
                "runbook_steps": [],
            }
        ],
    }


def test_api_auth_required_with_api_key(monkeypatch):
    monkeypatch.setenv("MINI_SOAR_REQUIRE_AUTH", "true")
    monkeypatch.setenv("MINI_SOAR_API_KEYS", "test-key")
    monkeypatch.setenv("VT_API_KEY", "dummy")
    mini_soar_api._rate_state.clear()

    monkeypatch.setattr(
        mini_soar_api,
        "run_pipeline",
        lambda **kwargs: _fake_report(kwargs.get("correlation_id")),
    )

    client = TestClient(mini_soar_api.app)

    denied = client.post("/analyze", json={"ioc": "8.8.8.8"})
    assert denied.status_code == 401

    ok = client.post(
        "/analyze",
        headers={"x-api-key": "test-key"},
        json={"ioc": "8.8.8.8", "ticket_backend": "none"},
    )
    assert ok.status_code == 200
    assert ok.json()["summary"]["total_iocs"] == 1


def test_api_rate_limit(monkeypatch):
    monkeypatch.setenv("MINI_SOAR_REQUIRE_AUTH", "false")
    monkeypatch.setenv("MINI_SOAR_API_KEYS", "")
    monkeypatch.setenv("MINI_SOAR_API_RATE_LIMIT", "1")
    monkeypatch.setenv("MINI_SOAR_API_RATE_WINDOW_SECONDS", "60")
    monkeypatch.setenv("VT_API_KEY", "dummy")
    mini_soar_api._rate_state.clear()

    monkeypatch.setattr(
        mini_soar_api,
        "run_pipeline",
        lambda **kwargs: _fake_report(kwargs.get("correlation_id")),
    )

    client = TestClient(mini_soar_api.app)
    first = client.post("/analyze", json={"ioc": "8.8.8.8"})
    second = client.post("/analyze", json={"ioc": "8.8.8.8"})

    assert first.status_code == 200
    assert second.status_code == 429

