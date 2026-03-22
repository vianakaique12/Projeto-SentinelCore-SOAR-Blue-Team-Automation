"""Tests for mini_soar_feeds — CSV/STIX feed ingestion."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient

# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_raw_response(text: str) -> tuple[int, bytes, None]:
    return 200, text.encode(), None


def _make_error_response(msg: str) -> tuple[int, None, str]:
    return 0, None, msg


# ── CSVFeedIngester ───────────────────────────────────────────────────────────

class TestCSVFeedIngester:
    """Unit tests for CSVFeedIngester._parse_csv and fetch_iocs."""

    def setup_method(self):
        from mini_soar_feeds import CSVFeedIngester
        self.Cls = CSVFeedIngester

    def test_parse_simple_ioc_column(self):
        csv_text = "ioc\n1.2.3.4\nevil.com\nhttp://bad.net/path\n"
        ingester = self.Cls(url="http://x", ioc_column="ioc")
        iocs, err = ingester._parse_csv(csv_text)
        assert err is None
        assert iocs == ["1.2.3.4", "evil.com", "http://bad.net/path"]

    def test_parse_case_insensitive_column(self):
        csv_text = "IOC\nalpha.com\nbeta.com\n"
        ingester = self.Cls(url="http://x", ioc_column="ioc")
        iocs, err = ingester._parse_csv(csv_text)
        assert err is None
        assert "alpha.com" in iocs

    def test_parse_fallback_candidate_column(self):
        # No "ioc" column — should fall back to "indicator"
        csv_text = "indicator,score\n10.0.0.1,95\n192.168.1.1,50\n"
        ingester = self.Cls(url="http://x", ioc_column="ioc")
        iocs, err = ingester._parse_csv(csv_text)
        assert err is None
        assert "10.0.0.1" in iocs

    def test_parse_no_header_bare_values(self):
        # No column header — treat every line as an IOC
        csv_text = "10.10.10.10\nevil.example.com\n"
        ingester = self.Cls(url="http://x", ioc_column="ioc")
        iocs, err = ingester._parse_csv(csv_text)
        assert err is None
        assert "10.10.10.10" in iocs
        assert "evil.example.com" in iocs

    def test_parse_strips_comment_lines(self):
        csv_text = "# This is a comment\nioc\n8.8.8.8\n# another comment\n4.4.4.4\n"
        ingester = self.Cls(url="http://x", ioc_column="ioc")
        iocs, err = ingester._parse_csv(csv_text)
        assert err is None
        assert "8.8.8.8" in iocs
        assert "4.4.4.4" in iocs
        assert "# This is a comment" not in iocs

    def test_parse_empty_content_returns_error(self):
        ingester = self.Cls(url="http://x", ioc_column="ioc")
        iocs, err = ingester._parse_csv("   \n  \n")
        assert err is not None
        assert iocs == []

    def test_parse_deduplicates_iocs(self):
        csv_text = "ioc\n1.1.1.1\n1.1.1.1\n2.2.2.2\n"
        ingester = self.Cls(url="http://x", ioc_column="ioc")
        iocs, err = ingester._parse_csv(csv_text)
        assert err is None
        assert iocs.count("1.1.1.1") == 1

    def test_parse_skips_empty_values(self):
        csv_text = "ioc\n1.1.1.1\n\n2.2.2.2\n"
        ingester = self.Cls(url="http://x", ioc_column="ioc")
        iocs, err = ingester._parse_csv(csv_text)
        assert err is None
        assert "" not in iocs

    def test_fetch_iocs_success(self):
        from mini_soar_feeds import CSVFeedIngester
        ingester = CSVFeedIngester(url="http://feed.example.com/iocs.csv")
        csv_text = "ioc\n10.0.0.1\nevil.com\n"
        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)):
            iocs, err = ingester.fetch_iocs()
        assert err is None
        assert "10.0.0.1" in iocs
        assert "evil.com" in iocs

    def test_fetch_iocs_http_error(self):
        from mini_soar_feeds import CSVFeedIngester
        ingester = CSVFeedIngester(url="http://broken.example.com/")
        with patch("mini_soar_feeds.http_raw_request", return_value=_make_error_response("HTTP 404: not found")):
            iocs, err = ingester.fetch_iocs()
        assert iocs == []
        assert err is not None
        assert "404" in err

    def test_fetch_iocs_custom_column(self):
        from mini_soar_feeds import CSVFeedIngester
        ingester = CSVFeedIngester(url="http://x", ioc_column="observable")
        csv_text = "observable,confidence\n192.0.2.1,90\n203.0.113.5,70\n"
        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)):
            iocs, err = ingester.fetch_iocs()
        assert err is None
        assert "192.0.2.1" in iocs


# ── STIXFeedIngester ──────────────────────────────────────────────────────────

class TestSTIXFeedIngester:
    """Unit tests for STIXFeedIngester._parse_bundle and _extract_ioc_from_pattern."""

    def setup_method(self):
        from mini_soar_feeds import STIXFeedIngester
        self.Cls = STIXFeedIngester

    def _make_bundle(self, indicators: list[dict]) -> dict:
        return {
            "type": "bundle",
            "id": "bundle--test",
            "objects": indicators,
        }

    def _make_indicator(self, pattern: str) -> dict:
        return {
            "type": "indicator",
            "id": "indicator--test",
            "pattern": pattern,
            "pattern_type": "stix",
        }

    def test_parse_ipv4_pattern(self):
        bundle = self._make_bundle([
            self._make_indicator("[ipv4-addr:value = '1.2.3.4']"),
        ])
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert "1.2.3.4" in iocs

    def test_parse_domain_pattern(self):
        bundle = self._make_bundle([
            self._make_indicator("[domain-name:value = 'evil.example.com']"),
        ])
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert "evil.example.com" in iocs

    def test_parse_url_pattern(self):
        bundle = self._make_bundle([
            self._make_indicator("[url:value = 'http://evil.com/payload']"),
        ])
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert "http://evil.com/payload" in iocs

    def test_parse_file_hash_pattern(self):
        bundle = self._make_bundle([
            self._make_indicator("[file:hashes.MD5 = 'abc123deadbeef0000000000000000ab']"),
        ])
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert "abc123deadbeef0000000000000000ab" in iocs

    def test_parse_multiple_indicators(self):
        bundle = self._make_bundle([
            self._make_indicator("[ipv4-addr:value = '10.0.0.1']"),
            self._make_indicator("[domain-name:value = 'bad.example.com']"),
            self._make_indicator("[url:value = 'http://bad.example.com/x']"),
        ])
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert len(iocs) == 3

    def test_parse_skips_non_indicator_objects(self):
        bundle = self._make_bundle([
            {"type": "malware", "id": "malware--1", "name": "EvilBot"},
            self._make_indicator("[ipv4-addr:value = '5.5.5.5']"),
        ])
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert iocs == ["5.5.5.5"]

    def test_parse_deduplicates_iocs(self):
        bundle = self._make_bundle([
            self._make_indicator("[ipv4-addr:value = '1.1.1.1']"),
            self._make_indicator("[ipv4-addr:value = '1.1.1.1']"),
        ])
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert iocs.count("1.1.1.1") == 1

    def test_parse_invalid_pattern_skipped(self):
        bundle = self._make_bundle([
            {"type": "indicator", "pattern": "NOT A VALID PATTERN"},
        ])
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert iocs == []

    def test_parse_empty_objects_list(self):
        bundle = {"type": "bundle", "objects": []}
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(bundle)
        assert err is None
        assert iocs == []

    def test_parse_missing_objects_key(self):
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle({"type": "bundle"})
        assert err is None
        assert iocs == []

    def test_parse_non_dict_bundle(self):
        ingester = self.Cls(url="http://x")
        iocs, err = ingester._parse_bundle(["not", "a", "bundle"])
        assert err is not None
        assert iocs == []

    def test_fetch_iocs_success(self):
        from mini_soar_feeds import STIXFeedIngester
        ingester = STIXFeedIngester(url="http://stix.example.com/bundle.json")
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.1']"},
            ],
        }
        raw = json.dumps(bundle).encode()
        with patch("mini_soar_feeds.http_raw_request", return_value=(200, raw, None)):
            iocs, err = ingester.fetch_iocs()
        assert err is None
        assert "203.0.113.1" in iocs

    def test_fetch_iocs_json_parse_error(self):
        from mini_soar_feeds import STIXFeedIngester
        ingester = STIXFeedIngester(url="http://x")
        with patch("mini_soar_feeds.http_raw_request", return_value=(200, b"not json {{", None)):
            iocs, err = ingester.fetch_iocs()
        assert iocs == []
        assert err is not None

    def test_fetch_iocs_http_error(self):
        from mini_soar_feeds import STIXFeedIngester
        ingester = STIXFeedIngester(url="http://broken.example.com/")
        with patch("mini_soar_feeds.http_raw_request", return_value=_make_error_response("HTTP 500")):
            iocs, err = ingester.fetch_iocs()
        assert iocs == []
        assert err is not None


# ── _detect_format ────────────────────────────────────────────────────────────

class TestDetectFormat:
    def test_detects_stix_bundle(self):
        from mini_soar_feeds import _detect_format
        bundle = json.dumps({"type": "bundle", "objects": []}).encode()
        assert _detect_format("http://x", bundle) == "stix"

    def test_detects_csv_for_plain_text(self):
        from mini_soar_feeds import _detect_format
        assert _detect_format("http://x", b"ioc\n1.2.3.4\n") == "csv"

    def test_detects_csv_for_json_non_stix(self):
        from mini_soar_feeds import _detect_format
        raw = json.dumps({"data": [1, 2, 3]}).encode()
        assert _detect_format("http://x", raw) == "csv"


# ── Feed Status Registry ──────────────────────────────────────────────────────

class TestFeedStatusRegistry:
    def test_initially_empty(self):
        from mini_soar_feeds import _feed_registry
        # May not be empty if other tests ran, so just check type
        from mini_soar_feeds import get_feed_statuses
        statuses = get_feed_statuses()
        assert isinstance(statuses, list)

    def test_status_updated_after_ingest(self):
        from mini_soar_feeds import ingest_feeds, _feed_registry, _registry_lock
        csv_text = "ioc\n1.3.3.7\n"
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store):
            from mini_soar_core import build_config_from_env
            cfg = build_config_from_env()
            cfg.enable_idempotency = True
            result = ingest_feeds(["http://test-feed.example.com/iocs.csv"], fmt="csv", config=cfg)

        with _registry_lock:
            status = _feed_registry.get("http://test-feed.example.com/iocs.csv")
        assert status is not None
        assert status.last_ioc_count == 1
        assert status.poll_count >= 1


# ── ingest_feeds orchestrator ─────────────────────────────────────────────────

class TestIngestFeeds:
    def _mock_config(self):
        from mini_soar_core import RuntimeConfig
        cfg = RuntimeConfig()
        cfg.enable_idempotency = False
        return cfg

    def test_returns_summary_keys(self):
        from mini_soar_feeds import ingest_feeds
        csv_text = "ioc\n8.8.8.8\n8.8.4.4\n"
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store):
            result = ingest_feeds(["http://x/iocs.csv"], fmt="csv", config=self._mock_config())

        assert "feeds_polled" in result
        assert "total_iocs_found" in result
        assert "total_new_iocs" in result
        assert "results" in result
        assert result["feeds_polled"] == 1

    def test_counts_iocs_correctly(self):
        from mini_soar_feeds import ingest_feeds
        csv_text = "ioc\n1.1.1.1\n2.2.2.2\n3.3.3.3\n"
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store):
            cfg = self._mock_config()
            result = ingest_feeds(["http://x/iocs.csv"], fmt="csv", config=cfg)

        assert result["total_iocs_found"] == 3

    def test_idempotency_filters_seen_iocs(self):
        from mini_soar_feeds import ingest_feeds
        csv_text = "ioc\n10.0.0.1\n10.0.0.2\n"
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        # First IOC seen, second is new
        mock_store.seen_recent_ioc.side_effect = lambda ioc, **kw: ioc == "10.0.0.1"

        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store):
            from mini_soar_core import RuntimeConfig
            cfg = RuntimeConfig()
            cfg.enable_idempotency = True
            cfg.idempotency_window_seconds = 3600
            result = ingest_feeds(["http://x/iocs.csv"], fmt="csv", config=cfg)

        # Only 1 new IOC should reach pipeline
        assert result["total_new_iocs"] == 1
        called_iocs = mock_pipeline.call_args[0][0]
        assert "10.0.0.2" in called_iocs
        assert "10.0.0.1" not in called_iocs

    def test_http_error_recorded_in_result(self):
        from mini_soar_feeds import ingest_feeds
        with patch("mini_soar_feeds.http_raw_request", return_value=_make_error_response("HTTP 404")), \
             patch("mini_soar_feeds.create_store", return_value=MagicMock(seen_recent_ioc=lambda *a, **kw: False)):
            result = ingest_feeds(["http://bad.example.com/iocs.csv"], fmt="csv", config=self._mock_config())

        assert result["results"][0]["error"] is not None
        assert result["total_new_iocs"] == 0

    def test_multiple_feeds_aggregated(self):
        from mini_soar_feeds import ingest_feeds
        csv_a = "ioc\n192.0.2.1\n"
        csv_b = "ioc\n198.51.100.1\n198.51.100.2\n"
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        responses = [_make_raw_response(csv_a), _make_raw_response(csv_b)]
        with patch("mini_soar_feeds.http_raw_request", side_effect=responses), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store):
            result = ingest_feeds(
                ["http://feed-a.example.com/", "http://feed-b.example.com/"],
                fmt="csv",
                config=self._mock_config(),
            )

        assert result["feeds_polled"] == 2
        assert result["total_iocs_found"] == 3

    def test_auto_format_detects_stix(self):
        from mini_soar_feeds import ingest_feeds
        bundle = {
            "type": "bundle",
            "objects": [
                {"type": "indicator", "pattern": "[ipv4-addr:value = '203.0.113.10']"},
            ],
        }
        raw = json.dumps(bundle).encode()
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=(200, raw, None)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store):
            result = ingest_feeds(["http://stix.example.com/bundle.json"], fmt="auto", config=self._mock_config())

        assert result["results"][0]["format"] == "stix"
        assert result["total_iocs_found"] == 1

    def test_pipeline_error_recorded(self):
        from mini_soar_feeds import ingest_feeds
        csv_text = "ioc\n5.5.5.5\n"
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)), \
             patch("mini_soar_feeds.run_pipeline", side_effect=RuntimeError("pipeline boom")), \
             patch("mini_soar_feeds.create_store", return_value=mock_store):
            result = ingest_feeds(["http://x/iocs.csv"], fmt="csv", config=self._mock_config())

        assert "pipeline boom" in (result["results"][0]["error"] or "")


# ── API endpoints ─────────────────────────────────────────────────────────────

@pytest.fixture()
def client():
    from mini_soar_api import app
    return TestClient(app, raise_server_exceptions=True)


class TestFeedIngestEndpoint:
    def test_post_feeds_ingest_success(self, client):
        csv_text = "ioc\n10.20.30.40\n"
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store), \
             patch("mini_soar_api.build_config_from_env") as mock_cfg:
            from mini_soar_core import RuntimeConfig
            cfg = RuntimeConfig()
            cfg.enable_idempotency = False
            mock_cfg.return_value = cfg

            r = client.post("/feeds/ingest", json={"urls": ["http://x/iocs.csv"], "format": "csv"})

        assert r.status_code == 200
        data = r.json()
        assert "feeds_polled" in data
        assert data["feeds_polled"] == 1

    def test_post_feeds_ingest_no_urls_returns_422(self, client):
        with patch.dict("os.environ", {"MINI_SOAR_FEED_URLS": ""}):
            r = client.post("/feeds/ingest", json={"urls": []})
        assert r.status_code == 422

    def test_post_feeds_ingest_uses_env_urls(self, client):
        csv_text = "ioc\n1.2.3.4\n"
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store), \
             patch("mini_soar_api.feed_urls_from_env", return_value=["http://env-feed.example.com/iocs.csv"]), \
             patch("mini_soar_api.build_config_from_env") as mock_cfg:
            from mini_soar_core import RuntimeConfig
            cfg = RuntimeConfig()
            cfg.enable_idempotency = False
            mock_cfg.return_value = cfg

            r = client.post("/feeds/ingest", json={"urls": []})

        assert r.status_code == 200
        assert r.json()["feeds_polled"] == 1

    def test_post_feeds_ingest_empty_body(self, client):
        """Sending no body at all when env URLs are configured should work."""
        csv_text = "ioc\n9.9.9.9\n"
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=_make_raw_response(csv_text)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store), \
             patch("mini_soar_api.feed_urls_from_env", return_value=["http://x/iocs.csv"]), \
             patch("mini_soar_api.build_config_from_env") as mock_cfg:
            from mini_soar_core import RuntimeConfig
            cfg = RuntimeConfig()
            cfg.enable_idempotency = False
            mock_cfg.return_value = cfg

            r = client.post("/feeds/ingest")

        assert r.status_code == 200

    def test_post_feeds_ingest_stix_format(self, client):
        bundle = {
            "type": "bundle",
            "objects": [{"type": "indicator", "pattern": "[ipv4-addr:value = '1.2.3.4']"}],
        }
        raw = json.dumps(bundle).encode()
        mock_pipeline = MagicMock(return_value={"findings": [], "summary": {}})
        mock_store = MagicMock()
        mock_store.seen_recent_ioc.return_value = False

        with patch("mini_soar_feeds.http_raw_request", return_value=(200, raw, None)), \
             patch("mini_soar_feeds.run_pipeline", mock_pipeline), \
             patch("mini_soar_feeds.create_store", return_value=mock_store), \
             patch("mini_soar_api.build_config_from_env") as mock_cfg:
            from mini_soar_core import RuntimeConfig
            cfg = RuntimeConfig()
            cfg.enable_idempotency = False
            mock_cfg.return_value = cfg

            r = client.post("/feeds/ingest", json={
                "urls": ["http://x/bundle.json"],
                "format": "stix",
            })

        assert r.status_code == 200
        data = r.json()
        assert data["total_iocs_found"] == 1

    def test_post_feeds_ingest_invalid_format_value(self, client):
        r = client.post("/feeds/ingest", json={
            "urls": ["http://x/iocs.csv"],
            "format": "xml",  # invalid
        })
        assert r.status_code == 422


class TestFeedStatusEndpoint:
    def test_get_feeds_status_empty(self, client):
        with patch("mini_soar_api.get_feed_statuses", return_value=[]):
            r = client.get("/feeds/status")
        assert r.status_code == 200
        data = r.json()
        assert "feeds" in data
        assert "count" in data
        assert data["count"] == 0

    def test_get_feeds_status_returns_registered_feeds(self, client):
        mock_statuses = [
            {
                "url": "http://x/iocs.csv",
                "format": "csv",
                "last_polled_at": "2024-01-01T00:00:00+00:00",
                "last_ioc_count": 100,
                "last_new_ioc_count": 10,
                "total_ingested": 10,
                "last_error": None,
                "poll_count": 1,
            }
        ]
        with patch("mini_soar_api.get_feed_statuses", return_value=mock_statuses):
            r = client.get("/feeds/status")
        assert r.status_code == 200
        data = r.json()
        assert data["count"] == 1
        assert data["feeds"][0]["url"] == "http://x/iocs.csv"
        assert data["feeds"][0]["last_ioc_count"] == 100

    def test_get_feeds_status_schema_fields(self, client):
        mock_statuses = [
            {
                "url": "http://y/feed.json",
                "format": "stix",
                "last_polled_at": "2024-06-15T12:00:00+00:00",
                "last_ioc_count": 50,
                "last_new_ioc_count": 5,
                "total_ingested": 42,
                "last_error": "HTTP 503: service unavailable",
                "poll_count": 7,
            }
        ]
        with patch("mini_soar_api.get_feed_statuses", return_value=mock_statuses):
            r = client.get("/feeds/status")
        feed = r.json()["feeds"][0]
        for key in ("url", "format", "last_polled_at", "last_ioc_count",
                    "last_new_ioc_count", "total_ingested", "last_error", "poll_count"):
            assert key in feed, f"Missing key: {key}"
