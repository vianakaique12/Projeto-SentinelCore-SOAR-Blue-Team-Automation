"""Tests for GET /findings endpoint and query_findings storage method."""
from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mini_soar_storage import NullStore, SQLiteStore


# ── Helpers ────────────────────────────────────────────────────────────────────

def _make_finding(
    ioc: str = "1.2.3.4",
    ioc_type: str = "ip",
    priority: str = "low",
    risk_score: int = 10,
    generated_at: str = "2024-01-15T10:00:00Z",
) -> dict[str, Any]:
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "priority": priority,
        "risk_score": risk_score,
        "generated_at": generated_at,
    }


def _seed(store: SQLiteStore, findings: list[dict[str, Any]]) -> None:
    for f in findings:
        store.save_finding("corr-test", f)


# ── NullStore.query_findings ───────────────────────────────────────────────────

class TestNullStoreQueryFindings:
    def test_returns_empty_list_and_zero(self):
        store = NullStore()
        results, total = store.query_findings({})
        assert results == []
        assert total == 0

    def test_ignores_all_filters(self):
        store = NullStore()
        filters = {"priority": "critical", "ioc_type": "ip", "min_score": 90}
        results, total = store.query_findings(filters, limit=100, offset=0)
        assert results == []
        assert total == 0


# ── SQLiteStore.query_findings ─────────────────────────────────────────────────

class TestSQLiteQueryFindingsNoFilters:
    def test_returns_all_when_no_filters(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [_make_finding(ioc="1.1.1.1"), _make_finding(ioc="2.2.2.2")])
        results, total = store.query_findings({})
        assert total == 2
        assert len(results) == 2

    def test_empty_db_returns_zero(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        results, total = store.query_findings({})
        assert total == 0
        assert results == []

    def test_default_order_newest_first(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="first.com"),
            _make_finding(ioc="second.com"),
            _make_finding(ioc="third.com"),
        ])
        results, _ = store.query_findings({})
        # Newest inserted (highest id) comes first
        assert results[0]["ioc"] == "third.com"
        assert results[-1]["ioc"] == "first.com"


class TestSQLiteQueryFindingsFilterPriority:
    def test_filter_by_priority_high(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="a.com", priority="high"),
            _make_finding(ioc="b.com", priority="low"),
            _make_finding(ioc="c.com", priority="high"),
        ])
        results, total = store.query_findings({"priority": "high"})
        assert total == 2
        assert all(f["priority"] == "high" for f in results)

    def test_filter_by_priority_critical(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(priority="critical"),
            _make_finding(priority="medium"),
        ])
        results, total = store.query_findings({"priority": "critical"})
        assert total == 1
        assert results[0]["priority"] == "critical"

    def test_priority_no_match_returns_empty(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [_make_finding(priority="low")])
        results, total = store.query_findings({"priority": "critical"})
        assert total == 0
        assert results == []


class TestSQLiteQueryFindingsFilterIocType:
    def test_filter_by_ioc_type_domain(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="evil.com", ioc_type="domain"),
            _make_finding(ioc="1.2.3.4", ioc_type="ip"),
            _make_finding(ioc="bad.net", ioc_type="domain"),
        ])
        results, total = store.query_findings({"ioc_type": "domain"})
        assert total == 2
        assert all(f["ioc_type"] == "domain" for f in results)

    def test_filter_by_ioc_type_ip(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="10.0.0.1", ioc_type="ip"),
            _make_finding(ioc="evil.com", ioc_type="domain"),
        ])
        results, total = store.query_findings({"ioc_type": "ip"})
        assert total == 1
        assert results[0]["ioc"] == "10.0.0.1"


class TestSQLiteQueryFindingsFilterScore:
    def test_min_score(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="a", risk_score=10),
            _make_finding(ioc="b", risk_score=50),
            _make_finding(ioc="c", risk_score=90),
        ])
        results, total = store.query_findings({"min_score": 50})
        assert total == 2
        assert all(f["risk_score"] >= 50 for f in results)

    def test_max_score(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="a", risk_score=10),
            _make_finding(ioc="b", risk_score=50),
            _make_finding(ioc="c", risk_score=90),
        ])
        results, total = store.query_findings({"max_score": 50})
        assert total == 2
        assert all(f["risk_score"] <= 50 for f in results)

    def test_score_range(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="a", risk_score=10),
            _make_finding(ioc="b", risk_score=40),
            _make_finding(ioc="c", risk_score=70),
            _make_finding(ioc="d", risk_score=95),
        ])
        results, total = store.query_findings({"min_score": 30, "max_score": 75})
        assert total == 2
        scores = {f["risk_score"] for f in results}
        assert scores == {40, 70}

    def test_exact_score_boundary_inclusive(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [_make_finding(risk_score=50)])
        results, total = store.query_findings({"min_score": 50, "max_score": 50})
        assert total == 1


class TestSQLiteQueryFindingsFilterIoc:
    def test_partial_ioc_match(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="evil.example.com"),
            _make_finding(ioc="good.example.com"),
            _make_finding(ioc="1.2.3.4"),
        ])
        results, total = store.query_findings({"ioc": "example.com"})
        assert total == 2
        assert all("example.com" in f["ioc"] for f in results)

    def test_ioc_filter_no_match(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [_make_finding(ioc="1.2.3.4")])
        results, total = store.query_findings({"ioc": "evil"})
        assert total == 0

    def test_ioc_filter_full_value(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="1.2.3.4"),
            _make_finding(ioc="5.6.7.8"),
        ])
        results, total = store.query_findings({"ioc": "1.2.3.4"})
        assert total == 1
        assert results[0]["ioc"] == "1.2.3.4"


class TestSQLiteQueryFindingsFilterDate:
    def test_since_filter(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="old", generated_at="2023-01-01T00:00:00Z"),
            _make_finding(ioc="new", generated_at="2024-06-01T00:00:00Z"),
        ])
        results, total = store.query_findings({"since": "2024-01-01T00:00:00Z"})
        assert total == 1
        assert results[0]["ioc"] == "new"

    def test_until_filter(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="old", generated_at="2023-01-01T00:00:00Z"),
            _make_finding(ioc="new", generated_at="2024-06-01T00:00:00Z"),
        ])
        results, total = store.query_findings({"until": "2023-12-31T23:59:59Z"})
        assert total == 1
        assert results[0]["ioc"] == "old"

    def test_since_and_until_range(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="a", generated_at="2023-01-01T00:00:00Z"),
            _make_finding(ioc="b", generated_at="2024-03-15T12:00:00Z"),
            _make_finding(ioc="c", generated_at="2025-01-01T00:00:00Z"),
        ])
        results, total = store.query_findings({
            "since": "2024-01-01T00:00:00Z",
            "until": "2024-12-31T23:59:59Z",
        })
        assert total == 1
        assert results[0]["ioc"] == "b"


class TestSQLiteQueryFindingsPagination:
    def test_limit_restricts_results(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [_make_finding(ioc=f"host-{i}.com") for i in range(10)])
        results, total = store.query_findings({}, limit=3)
        assert total == 10
        assert len(results) == 3

    def test_offset_skips_results(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [_make_finding(ioc=f"host-{i}.com") for i in range(5)])
        results_page1, total = store.query_findings({}, limit=2, offset=0)
        results_page2, _     = store.query_findings({}, limit=2, offset=2)
        assert total == 5
        iocs_p1 = {f["ioc"] for f in results_page1}
        iocs_p2 = {f["ioc"] for f in results_page2}
        assert iocs_p1.isdisjoint(iocs_p2)

    def test_offset_beyond_total_returns_empty(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [_make_finding(ioc="a.com")])
        results, total = store.query_findings({}, limit=50, offset=100)
        assert total == 1
        assert results == []

    def test_total_unchanged_by_pagination(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [_make_finding(ioc=f"h{i}.com") for i in range(7)])
        _, total1 = store.query_findings({}, limit=3, offset=0)
        _, total2 = store.query_findings({}, limit=3, offset=3)
        assert total1 == total2 == 7


class TestSQLiteQueryFindingsCombinedFilters:
    def test_priority_and_ioc_type(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="1.1.1.1", ioc_type="ip",     priority="high"),
            _make_finding(ioc="evil.com", ioc_type="domain", priority="high"),
            _make_finding(ioc="2.2.2.2", ioc_type="ip",     priority="low"),
        ])
        results, total = store.query_findings({"priority": "high", "ioc_type": "ip"})
        assert total == 1
        assert results[0]["ioc"] == "1.1.1.1"

    def test_score_and_ioc_type(self, tmp_path):
        store = SQLiteStore(path=str(tmp_path / "db.sqlite"))
        _seed(store, [
            _make_finding(ioc="a.com", ioc_type="domain", risk_score=80),
            _make_finding(ioc="b.com", ioc_type="domain", risk_score=20),
            _make_finding(ioc="c.com", ioc_type="url",    risk_score=90),
        ])
        results, total = store.query_findings({"ioc_type": "domain", "min_score": 50})
        assert total == 1
        assert results[0]["ioc"] == "a.com"


# ── /findings API endpoint ─────────────────────────────────────────────────────

@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{tmp_path / 'api.db'}")
    monkeypatch.delenv("MINI_SOAR_API_KEYS", raising=False)
    monkeypatch.delenv("MINI_SOAR_JWT_SECRET", raising=False)
    monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)
    from mini_soar_api import app
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def seeded_client(tmp_path, monkeypatch):
    db_path = tmp_path / "api.db"
    monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.delenv("MINI_SOAR_API_KEYS", raising=False)
    monkeypatch.delenv("MINI_SOAR_JWT_SECRET", raising=False)
    monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)

    store = SQLiteStore(path=str(db_path))
    _seed(store, [
        _make_finding(ioc="1.1.1.1",   ioc_type="ip",     priority="low",      risk_score=10, generated_at="2024-01-01T00:00:00Z"),
        _make_finding(ioc="evil.com",  ioc_type="domain", priority="high",     risk_score=75, generated_at="2024-06-01T00:00:00Z"),
        _make_finding(ioc="bad.net",   ioc_type="domain", priority="critical", risk_score=95, generated_at="2024-09-01T00:00:00Z"),
        _make_finding(ioc="2.2.2.2",   ioc_type="ip",     priority="medium",   risk_score=45, generated_at="2024-03-01T00:00:00Z"),
        _make_finding(ioc="hash-abc",  ioc_type="hash",   priority="high",     risk_score=80, generated_at="2024-07-01T00:00:00Z"),
    ])

    from mini_soar_api import app
    return TestClient(app, raise_server_exceptions=False)


class TestFindingsEndpointAuth:
    def test_requires_auth_when_configured(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{tmp_path / 'a.db'}")
        monkeypatch.setenv("MINI_SOAR_API_KEYS", "secret-key")
        monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)
        from mini_soar_api import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/findings")
        assert resp.status_code == 401

    def test_authorized_with_api_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{tmp_path / 'a.db'}")
        monkeypatch.setenv("MINI_SOAR_API_KEYS", "my-key")
        monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)
        from mini_soar_api import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/findings", headers={"X-API-Key": "my-key"})
        assert resp.status_code == 200


class TestFindingsEndpointNoFilters:
    def test_returns_200(self, api_client):
        resp = api_client.get("/findings")
        assert resp.status_code == 200

    def test_response_structure(self, api_client):
        resp = api_client.get("/findings")
        body = resp.json()
        assert "total" in body
        assert "limit" in body
        assert "offset" in body
        assert "findings" in body

    def test_default_limit_in_response(self, api_client):
        resp = api_client.get("/findings")
        assert resp.json()["limit"] == 50

    def test_default_offset_in_response(self, api_client):
        resp = api_client.get("/findings")
        assert resp.json()["offset"] == 0

    def test_empty_db_total_zero(self, api_client):
        resp = api_client.get("/findings")
        assert resp.json()["total"] == 0
        assert resp.json()["findings"] == []

    def test_returns_all_seeded(self, seeded_client):
        resp = seeded_client.get("/findings")
        body = resp.json()
        assert body["total"] == 5
        assert len(body["findings"]) == 5


class TestFindingsEndpointFilterPriority:
    def test_filter_high(self, seeded_client):
        resp = seeded_client.get("/findings", params={"priority": "high"})
        body = resp.json()
        assert body["total"] == 2
        assert all(f["priority"] == "high" for f in body["findings"])

    def test_filter_critical(self, seeded_client):
        resp = seeded_client.get("/findings", params={"priority": "critical"})
        body = resp.json()
        assert body["total"] == 1
        assert body["findings"][0]["ioc"] == "bad.net"

    def test_filter_no_match(self, seeded_client):
        resp = seeded_client.get("/findings", params={"priority": "nonexistent"})
        assert resp.json()["total"] == 0


class TestFindingsEndpointFilterIocType:
    def test_filter_domain(self, seeded_client):
        resp = seeded_client.get("/findings", params={"ioc_type": "domain"})
        body = resp.json()
        assert body["total"] == 2
        assert all(f["ioc_type"] == "domain" for f in body["findings"])

    def test_filter_hash(self, seeded_client):
        resp = seeded_client.get("/findings", params={"ioc_type": "hash"})
        body = resp.json()
        assert body["total"] == 1
        assert body["findings"][0]["ioc"] == "hash-abc"


class TestFindingsEndpointFilterScore:
    def test_min_score(self, seeded_client):
        resp = seeded_client.get("/findings", params={"min_score": 75})
        body = resp.json()
        assert body["total"] == 3
        assert all(f["risk_score"] >= 75 for f in body["findings"])

    def test_max_score(self, seeded_client):
        resp = seeded_client.get("/findings", params={"max_score": 45})
        body = resp.json()
        assert body["total"] == 2
        assert all(f["risk_score"] <= 45 for f in body["findings"])

    def test_score_range(self, seeded_client):
        resp = seeded_client.get("/findings", params={"min_score": 40, "max_score": 80})
        body = resp.json()
        scores = {f["risk_score"] for f in body["findings"]}
        assert all(40 <= s <= 80 for s in scores)


class TestFindingsEndpointPagination:
    def test_limit_query_param(self, seeded_client):
        resp = seeded_client.get("/findings", params={"limit": 2})
        body = resp.json()
        assert body["total"] == 5
        assert len(body["findings"]) == 2
        assert body["limit"] == 2

    def test_offset_query_param(self, seeded_client):
        resp1 = seeded_client.get("/findings", params={"limit": 2, "offset": 0})
        resp2 = seeded_client.get("/findings", params={"limit": 2, "offset": 2})
        iocs1 = {f["ioc"] for f in resp1.json()["findings"]}
        iocs2 = {f["ioc"] for f in resp2.json()["findings"]}
        assert iocs1.isdisjoint(iocs2)

    def test_offset_in_response(self, seeded_client):
        resp = seeded_client.get("/findings", params={"limit": 2, "offset": 3})
        assert resp.json()["offset"] == 3

    def test_limit_max_200_enforced(self, api_client):
        resp = api_client.get("/findings", params={"limit": 999})
        assert resp.status_code == 422

    def test_limit_min_1_enforced(self, api_client):
        resp = api_client.get("/findings", params={"limit": 0})
        assert resp.status_code == 422


class TestFindingsEndpointFilterDate:
    def test_since(self, seeded_client):
        resp = seeded_client.get("/findings", params={"since": "2024-07-01T00:00:00Z"})
        body = resp.json()
        assert body["total"] == 2
        iocs = {f["ioc"] for f in body["findings"]}
        assert iocs == {"bad.net", "hash-abc"}

    def test_until(self, seeded_client):
        resp = seeded_client.get("/findings", params={"until": "2024-03-01T00:00:00Z"})
        body = resp.json()
        assert body["total"] == 2
        iocs = {f["ioc"] for f in body["findings"]}
        assert iocs == {"1.1.1.1", "2.2.2.2"}


class TestFindingsEndpointFilterIoc:
    def test_partial_ioc(self, seeded_client):
        # Both evil.com and bad.net contain "." — filter on "evil" matches only evil.com
        resp = seeded_client.get("/findings", params={"ioc": "evil"})
        body = resp.json()
        assert body["total"] == 1
        assert body["findings"][0]["ioc"] == "evil.com"

    def test_partial_ioc_matches_multiple(self, seeded_client):
        # "2" appears in "1.1.1.1" and "2.2.2.2" — both contain digits but "2.2" is unique
        resp = seeded_client.get("/findings", params={"ioc": ".net"})
        body = resp.json()
        assert body["total"] == 1
        assert body["findings"][0]["ioc"] == "bad.net"
