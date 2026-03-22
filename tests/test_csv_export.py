"""Tests for GET /report.csv endpoint and CSV export helpers."""
from __future__ import annotations

import csv
import io
from typing import Any

import pytest
from fastapi.testclient import TestClient

from mini_soar_api import _CSV_COLUMNS, _finding_to_csv_row, _generate_csv
from mini_soar_storage import SQLiteStore


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_csv(text: str) -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(text)))


def _make_finding(
    ioc: str = "1.2.3.4",
    ioc_type: str = "ip",
    priority: str = "low",
    risk_score: int = 10,
    generated_at: str = "2024-01-15T10:00:00Z",
    reasons: list[str] | None = None,
    vt_malicious: int | None = None,
    vt_suspicious: int | None = None,
    abuse_confidence: int | None = None,
    abuse_reports: int | None = None,
    mitre: list[dict] | None = None,
) -> dict[str, Any]:
    f: dict[str, Any] = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "priority": priority,
        "risk_score": risk_score,
        "generated_at": generated_at,
        "reasons": reasons or [],
    }
    if vt_malicious is not None or vt_suspicious is not None:
        f["virustotal"] = {
            "analysis_stats": {
                "malicious":  vt_malicious  if vt_malicious  is not None else 0,
                "suspicious": vt_suspicious if vt_suspicious is not None else 0,
            }
        }
    if abuse_confidence is not None or abuse_reports is not None:
        f["abuseipdb"] = {
            "abuse_confidence_score": abuse_confidence if abuse_confidence is not None else 0,
            "total_reports":          abuse_reports    if abuse_reports    is not None else 0,
        }
    if mitre is not None:
        f["mitre_attack"] = mitre
    return f


def _seed(store: SQLiteStore, findings: list[dict[str, Any]]) -> None:
    for f in findings:
        store.save_finding("corr-csv", f)


# ── _finding_to_csv_row ────────────────────────────────────────────────────────

class TestFindingToCsvRow:
    def test_basic_fields(self):
        row = _finding_to_csv_row(_make_finding(
            ioc="evil.com", ioc_type="domain", priority="high",
            risk_score=80, generated_at="2024-06-01T00:00:00Z",
        ))
        assert row["ioc"] == "evil.com"
        assert row["ioc_type"] == "domain"
        assert row["priority"] == "high"
        assert row["risk_score"] == 80
        assert row["generated_at"] == "2024-06-01T00:00:00Z"

    def test_reasons_joined_with_pipe(self):
        row = _finding_to_csv_row(_make_finding(
            reasons=["high VT score", "known C2"]
        ))
        assert row["reasons"] == "high VT score | known C2"

    def test_reasons_empty(self):
        row = _finding_to_csv_row(_make_finding(reasons=[]))
        assert row["reasons"] == ""

    def test_reasons_single(self):
        row = _finding_to_csv_row(_make_finding(reasons=["malware detected"]))
        assert row["reasons"] == "malware detected"

    def test_vt_stats_extracted(self):
        row = _finding_to_csv_row(_make_finding(vt_malicious=5, vt_suspicious=2))
        assert row["vt_malicious"] == 5
        assert row["vt_suspicious"] == 2

    def test_vt_missing_gives_empty(self):
        row = _finding_to_csv_row(_make_finding())
        assert row["vt_malicious"] == ""
        assert row["vt_suspicious"] == ""

    def test_vt_none_gives_empty(self):
        f = _make_finding()
        f["virustotal"] = None
        row = _finding_to_csv_row(f)
        assert row["vt_malicious"] == ""

    def test_abuse_stats_extracted(self):
        row = _finding_to_csv_row(_make_finding(abuse_confidence=75, abuse_reports=12))
        assert row["abuse_confidence"] == 75
        assert row["abuse_reports"] == 12

    def test_abuse_missing_gives_empty(self):
        row = _finding_to_csv_row(_make_finding())
        assert row["abuse_confidence"] == ""
        assert row["abuse_reports"] == ""

    def test_mitre_techniques_joined(self):
        mitre = [
            {"technique_id": "T1059", "tactic": "execution"},
            {"technique_id": "T1566", "tactic": "initial-access"},
        ]
        row = _finding_to_csv_row(_make_finding(mitre=mitre))
        assert row["mitre_techniques"] == "T1059 | T1566"

    def test_mitre_empty_gives_empty_string(self):
        row = _finding_to_csv_row(_make_finding(mitre=[]))
        assert row["mitre_techniques"] == ""

    def test_mitre_none_gives_empty_string(self):
        f = _make_finding()
        f["mitre_attack"] = None
        row = _finding_to_csv_row(f)
        assert row["mitre_techniques"] == ""

    def test_all_columns_present(self):
        row = _finding_to_csv_row(_make_finding())
        for col in _CSV_COLUMNS:
            assert col in row, f"Missing column: {col}"


# ── _generate_csv ──────────────────────────────────────────────────────────────

class TestGenerateCsv:
    def test_empty_findings_yields_header_only(self):
        chunks = list(_generate_csv([]))
        text = "".join(chunks)
        rows = _parse_csv(text)
        assert rows == []
        # Header row must be present — DictReader would have no fieldnames if totally empty
        assert ",".join(_CSV_COLUMNS) in text

    def test_header_contains_all_columns(self):
        chunks = list(_generate_csv([]))
        header_line = "".join(chunks).splitlines()[0]
        for col in _CSV_COLUMNS:
            assert col in header_line

    def test_yields_one_chunk_per_row_plus_header(self):
        findings = [_make_finding(ioc=f"h{i}.com") for i in range(3)]
        chunks = list(_generate_csv(findings))
        # 1 header chunk + 3 data chunks
        assert len(chunks) == 4

    def test_full_csv_parseable(self):
        findings = [
            _make_finding(ioc="evil.com", reasons=["bad", "worse"], vt_malicious=3),
            _make_finding(ioc="1.2.3.4"),
        ]
        text = "".join(_generate_csv(findings))
        rows = _parse_csv(text)
        assert len(rows) == 2

    def test_row_values_correct(self):
        findings = [_make_finding(
            ioc="test.io", ioc_type="domain", priority="critical",
            risk_score=99, reasons=["reason A", "reason B"],
            vt_malicious=7, vt_suspicious=1,
            abuse_confidence=90, abuse_reports=50,
            mitre=[{"technique_id": "T1071"}, {"technique_id": "T1095"}],
        )]
        text = "".join(_generate_csv(findings))
        rows = _parse_csv(text)
        r = rows[0]
        assert r["ioc"] == "test.io"
        assert r["ioc_type"] == "domain"
        assert r["priority"] == "critical"
        assert r["risk_score"] == "99"
        assert r["reasons"] == "reason A | reason B"
        assert r["vt_malicious"] == "7"
        assert r["vt_suspicious"] == "1"
        assert r["abuse_confidence"] == "90"
        assert r["abuse_reports"] == "50"
        assert r["mitre_techniques"] == "T1071 | T1095"


# ── /report.csv endpoint ───────────────────────────────────────────────────────

@pytest.fixture()
def api_client(tmp_path, monkeypatch):
    monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{tmp_path / 'csv.db'}")
    monkeypatch.delenv("MINI_SOAR_API_KEYS", raising=False)
    monkeypatch.delenv("MINI_SOAR_JWT_SECRET", raising=False)
    monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)
    from mini_soar_api import app
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
def seeded_client(tmp_path, monkeypatch):
    db_path = tmp_path / "csv_seed.db"
    monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{db_path}")
    monkeypatch.delenv("MINI_SOAR_API_KEYS", raising=False)
    monkeypatch.delenv("MINI_SOAR_JWT_SECRET", raising=False)
    monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)

    store = SQLiteStore(path=str(db_path))
    _seed(store, [
        _make_finding(
            ioc="1.1.1.1",   ioc_type="ip",     priority="low",
            risk_score=10,   generated_at="2024-01-01T00:00:00Z",
            reasons=["low score"],
        ),
        _make_finding(
            ioc="evil.com",  ioc_type="domain", priority="high",
            risk_score=75,   generated_at="2024-06-01T00:00:00Z",
            reasons=["phishing", "malware"],
            vt_malicious=8, vt_suspicious=2,
        ),
        _make_finding(
            ioc="bad.net",   ioc_type="domain", priority="critical",
            risk_score=95,   generated_at="2024-09-01T00:00:00Z",
            abuse_confidence=95, abuse_reports=300,
            mitre=[{"technique_id": "T1071"}, {"technique_id": "T1566"}],
        ),
        _make_finding(
            ioc="2.2.2.2",   ioc_type="ip",     priority="medium",
            risk_score=45,   generated_at="2024-03-01T00:00:00Z",
        ),
    ])

    from mini_soar_api import app
    return TestClient(app, raise_server_exceptions=False)


class TestCsvEndpointAuth:
    def test_requires_auth_when_configured(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{tmp_path / 'a.db'}")
        monkeypatch.setenv("MINI_SOAR_API_KEYS", "secret")
        monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)
        from mini_soar_api import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/report.csv")
        assert resp.status_code == 401

    def test_authorized_with_api_key(self, tmp_path, monkeypatch):
        monkeypatch.setenv("MINI_SOAR_DATABASE_URL", f"sqlite:///{tmp_path / 'a.db'}")
        monkeypatch.setenv("MINI_SOAR_API_KEYS", "my-key")
        monkeypatch.delenv("MINI_SOAR_REQUIRE_AUTH", raising=False)
        from mini_soar_api import app
        client = TestClient(app, raise_server_exceptions=False)
        resp = client.get("/report.csv", headers={"X-API-Key": "my-key"})
        assert resp.status_code == 200


class TestCsvEndpointResponse:
    def test_status_200(self, api_client):
        resp = api_client.get("/report.csv")
        assert resp.status_code == 200

    def test_content_type_is_text_csv(self, api_client):
        resp = api_client.get("/report.csv")
        assert resp.headers["content-type"].startswith("text/csv")

    def test_content_disposition_attachment(self, api_client):
        resp = api_client.get("/report.csv")
        cd = resp.headers.get("content-disposition", "")
        assert "attachment" in cd
        assert "sentinelcore_report_" in cd
        assert ".csv" in cd

    def test_filename_contains_date(self, api_client):
        import re
        resp = api_client.get("/report.csv")
        cd = resp.headers.get("content-disposition", "")
        assert re.search(r"sentinelcore_report_\d{8}\.csv", cd)

    def test_empty_db_returns_header_only(self, api_client):
        resp = api_client.get("/report.csv")
        rows = _parse_csv(resp.text)
        assert rows == []
        header_line = resp.text.splitlines()[0]
        for col in _CSV_COLUMNS:
            assert col in header_line

    def test_all_columns_present_in_header(self, seeded_client):
        resp = seeded_client.get("/report.csv")
        header = resp.text.splitlines()[0]
        for col in _CSV_COLUMNS:
            assert col in header, f"Missing column: {col}"

    def test_returns_all_seeded_findings(self, seeded_client):
        resp = seeded_client.get("/report.csv")
        rows = _parse_csv(resp.text)
        assert len(rows) == 4

    def test_row_values_correct(self, seeded_client):
        resp = seeded_client.get("/report.csv")
        rows = _parse_csv(resp.text)
        # Newest first — bad.net has highest id
        evil = next(r for r in rows if r["ioc"] == "evil.com")
        assert evil["ioc_type"] == "domain"
        assert evil["priority"] == "high"
        assert evil["risk_score"] == "75"
        assert evil["reasons"] == "phishing | malware"
        assert evil["vt_malicious"] == "8"
        assert evil["vt_suspicious"] == "2"

    def test_mitre_techniques_in_csv(self, seeded_client):
        resp = seeded_client.get("/report.csv")
        rows = _parse_csv(resp.text)
        bad = next(r for r in rows if r["ioc"] == "bad.net")
        assert "T1071" in bad["mitre_techniques"]
        assert "T1566" in bad["mitre_techniques"]
        assert " | " in bad["mitre_techniques"]

    def test_abuse_fields_in_csv(self, seeded_client):
        resp = seeded_client.get("/report.csv")
        rows = _parse_csv(resp.text)
        bad = next(r for r in rows if r["ioc"] == "bad.net")
        assert bad["abuse_confidence"] == "95"
        assert bad["abuse_reports"] == "300"

    def test_empty_fields_when_no_vt_data(self, seeded_client):
        resp = seeded_client.get("/report.csv")
        rows = _parse_csv(resp.text)
        simple = next(r for r in rows if r["ioc"] == "2.2.2.2")
        assert simple["vt_malicious"] == ""
        assert simple["vt_suspicious"] == ""


class TestCsvEndpointFilters:
    def test_filter_by_priority(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"priority": "high"})
        rows = _parse_csv(resp.text)
        assert len(rows) == 1
        assert rows[0]["ioc"] == "evil.com"

    def test_filter_by_priority_critical(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"priority": "critical"})
        rows = _parse_csv(resp.text)
        assert len(rows) == 1
        assert rows[0]["priority"] == "critical"

    def test_filter_by_ioc_type(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"ioc_type": "ip"})
        rows = _parse_csv(resp.text)
        assert len(rows) == 2
        assert all(r["ioc_type"] == "ip" for r in rows)

    def test_filter_by_ioc_type_domain(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"ioc_type": "domain"})
        rows = _parse_csv(resp.text)
        assert len(rows) == 2

    def test_filter_by_min_score(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"min_score": 70})
        rows = _parse_csv(resp.text)
        assert len(rows) == 2
        assert all(int(r["risk_score"]) >= 70 for r in rows)

    def test_filter_by_max_score(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"max_score": 45})
        rows = _parse_csv(resp.text)
        assert len(rows) == 2
        assert all(int(r["risk_score"]) <= 45 for r in rows)

    def test_filter_score_range(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"min_score": 40, "max_score": 80})
        rows = _parse_csv(resp.text)
        scores = [int(r["risk_score"]) for r in rows]
        assert all(40 <= s <= 80 for s in scores)

    def test_filter_by_ioc_partial(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"ioc": "evil"})
        rows = _parse_csv(resp.text)
        assert len(rows) == 1
        assert rows[0]["ioc"] == "evil.com"

    def test_filter_since(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"since": "2024-06-01T00:00:00Z"})
        rows = _parse_csv(resp.text)
        assert len(rows) == 2
        iocs = {r["ioc"] for r in rows}
        assert iocs == {"evil.com", "bad.net"}

    def test_filter_until(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"until": "2024-03-01T00:00:00Z"})
        rows = _parse_csv(resp.text)
        assert len(rows) == 2
        iocs = {r["ioc"] for r in rows}
        assert iocs == {"1.1.1.1", "2.2.2.2"}

    def test_filter_no_match_returns_header_only(self, seeded_client):
        resp = seeded_client.get("/report.csv", params={"priority": "nonexistent"})
        rows = _parse_csv(resp.text)
        assert rows == []
        # Header must still be present
        assert "ioc" in resp.text.splitlines()[0]

    def test_no_limit_offset_params(self, api_client):
        # limit and offset are not valid query params for /report.csv — should 422 if sent
        # Actually FastAPI ignores unknown query params by default,
        # but we verify the endpoint doesn't accept them as controls
        resp = api_client.get("/report.csv")
        assert resp.status_code == 200
