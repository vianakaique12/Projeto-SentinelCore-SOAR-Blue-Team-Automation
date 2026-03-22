"""Tests for GreyNoise, Shodan, and OTX threat intelligence sources."""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest

import mini_soar_enrichment as enr
from mini_soar_enrichment import (
    greynoise_lookup,
    greynoise_mock,
    otx_lookup,
    otx_mock,
    shodan_lookup,
    shodan_mock,
)
from mini_soar_scoring import DEFAULT_SCORING_CONFIG, _SHODAN_SUSPICIOUS_PORTS, score_finding


# ── Helpers ────────────────────────────────────────────────────────────────────

def _mock_http(status: int, data: dict | None, error: str | None = None):
    """Patch http_json_request to return a fixed response."""
    return patch(
        "mini_soar_enrichment.http_json_request",
        return_value=(status, data, error),
    )


# ══════════════════════════════════════════════════════════════════════════════
# greynoise_lookup
# ══════════════════════════════════════════════════════════════════════════════

class TestGreynoiseLookup:
    def test_malicious_classification(self):
        payload = {"classification": "malicious", "noise": True, "riot": False, "name": "Scanner", "link": "https://gn.io/ip/1.1.1.1"}
        with _mock_http(200, payload):
            result, error = greynoise_lookup("1.1.1.1", "key", timeout=5)
        assert error is None
        assert result["classification"] == "malicious"
        assert result["noise"] is True
        assert result["riot"] is False
        assert result["status"] == 200

    def test_benign_riot_classification(self):
        payload = {"classification": "benign", "noise": False, "riot": True, "name": "Cloudflare", "link": "https://gn.io/ip/1.1.1.1"}
        with _mock_http(200, payload):
            result, error = greynoise_lookup("1.1.1.1", "key", timeout=5)
        assert error is None
        assert result["classification"] == "benign"
        assert result["riot"] is True

    def test_unknown_classification(self):
        payload = {"classification": "unknown", "noise": False, "riot": False}
        with _mock_http(200, payload):
            result, error = greynoise_lookup("8.8.8.8", "key", timeout=5)
        assert error is None
        assert result["classification"] == "unknown"

    def test_http_error_propagated(self):
        with _mock_http(401, None, "HTTP 401: Unauthorized"):
            result, error = greynoise_lookup("1.1.1.1", "bad-key", timeout=5)
        assert result is None
        assert "401" in error

    def test_network_error_propagated(self):
        with _mock_http(0, None, "Network error: connection refused"):
            result, error = greynoise_lookup("1.1.1.1", "key", timeout=1)
        assert result is None
        assert error is not None

    def test_non_dict_response(self):
        with patch("mini_soar_enrichment.http_json_request", return_value=(200, ["bad"], None)):
            result, error = greynoise_lookup("1.1.1.1", "key", timeout=5)
        assert result is None
        assert "Unexpected" in error

    def test_missing_fields_default_to_safe_values(self):
        with _mock_http(200, {}):
            result, error = greynoise_lookup("1.1.1.1", "key", timeout=5)
        assert error is None
        assert result["classification"] == "unknown"
        assert result["noise"] is False
        assert result["riot"] is False

    def test_name_and_link_included(self):
        payload = {"classification": "malicious", "noise": True, "riot": False,
                   "name": "Bad Actor", "link": "https://gn.io/viz/ip/bad"}
        with _mock_http(200, payload):
            result, error = greynoise_lookup("bad.ip", "key", timeout=5)
        assert result["name"] == "Bad Actor"
        assert result["link"] == "https://gn.io/viz/ip/bad"


# ══════════════════════════════════════════════════════════════════════════════
# shodan_lookup
# ══════════════════════════════════════════════════════════════════════════════

class TestShodanLookup:
    def test_ports_and_vulns(self):
        payload = {
            "ports": [80, 443, 4444],
            "vulns": {"CVE-2021-44228": {}, "CVE-2022-1234": {}},
            "os": "Linux",
            "org": "Evil Corp",
            "isp": "Evil ISP",
        }
        with _mock_http(200, payload):
            result, error = shodan_lookup("1.2.3.4", "key", timeout=5)
        assert error is None
        assert 4444 in result["ports"]
        assert "CVE-2021-44228" in result["vulns"]
        assert result["os"] == "Linux"
        assert result["org"] == "Evil Corp"

    def test_ports_sorted(self):
        payload = {"ports": [9200, 22, 443, 80], "vulns": {}, "os": None, "org": None, "isp": None}
        with _mock_http(200, payload):
            result, _ = shodan_lookup("1.2.3.4", "key", timeout=5)
        assert result["ports"] == sorted(result["ports"])

    def test_vulns_as_list(self):
        payload = {"ports": [], "vulns": ["CVE-2020-1234", "CVE-2021-5678"], "os": None, "org": None, "isp": None}
        with _mock_http(200, payload):
            result, error = shodan_lookup("1.2.3.4", "key", timeout=5)
        assert error is None
        assert "CVE-2020-1234" in result["vulns"]

    def test_empty_ports_and_vulns(self):
        payload = {"ports": [], "vulns": {}, "os": None, "org": None, "isp": None}
        with _mock_http(200, payload):
            result, error = shodan_lookup("1.2.3.4", "key", timeout=5)
        assert error is None
        assert result["ports"] == []
        assert result["vulns"] == []

    def test_http_error_propagated(self):
        with _mock_http(403, None, "HTTP 403: Forbidden"):
            result, error = shodan_lookup("1.2.3.4", "bad-key", timeout=5)
        assert result is None
        assert "403" in error

    def test_non_dict_response(self):
        with patch("mini_soar_enrichment.http_json_request", return_value=(200, "bad", None)):
            result, error = shodan_lookup("1.2.3.4", "key", timeout=5)
        assert result is None
        assert "Unexpected" in error

    def test_status_included(self):
        payload = {"ports": [], "vulns": {}, "os": None, "org": None, "isp": None}
        with _mock_http(200, payload):
            result, _ = shodan_lookup("1.2.3.4", "key", timeout=5)
        assert result["status"] == 200


# ══════════════════════════════════════════════════════════════════════════════
# otx_lookup
# ══════════════════════════════════════════════════════════════════════════════

class TestOtxLookup:
    def test_ip_type_mapped_correctly(self):
        payload = {"pulse_info": {"count": 7}}
        with _mock_http(200, payload) as m:
            result, error = otx_lookup("1.2.3.4", "ip", "key", timeout=5)
        assert error is None
        assert result["pulse_count"] == 7
        called_url = m.call_args[1]["url"] if m.call_args[1] else m.call_args[0][0]
        assert "IPv4" in called_url

    def test_domain_type_mapped(self):
        payload = {"pulse_info": {"count": 3}}
        with _mock_http(200, payload) as m:
            result, error = otx_lookup("evil.com", "domain", "key", timeout=5)
        assert error is None
        called_url = m.call_args[1]["url"] if m.call_args[1] else m.call_args[0][0]
        assert "/domain/" in called_url

    def test_url_type_mapped(self):
        payload = {"pulse_info": {"count": 0}}
        with _mock_http(200, payload) as m:
            result, _ = otx_lookup("http://evil.com/path", "url", "key", timeout=5)
        called_url = m.call_args[1]["url"] if m.call_args[1] else m.call_args[0][0]
        assert "/url/" in called_url

    def test_hash_type_mapped_to_file(self):
        payload = {"pulse_info": {"count": 2}}
        with _mock_http(200, payload) as m:
            result, _ = otx_lookup("abc123", "hash", "key", timeout=5)
        called_url = m.call_args[1]["url"] if m.call_args[1] else m.call_args[0][0]
        assert "/file/" in called_url

    def test_unsupported_type_returns_error(self):
        result, error = otx_lookup("something", "unknown", "key", timeout=5)
        assert result is None
        assert "does not support" in error

    def test_zero_pulses(self):
        payload = {"pulse_info": {"count": 0}}
        with _mock_http(200, payload):
            result, error = otx_lookup("clean.com", "domain", "key", timeout=5)
        assert error is None
        assert result["pulse_count"] == 0

    def test_missing_pulse_info_defaults_to_zero(self):
        with _mock_http(200, {}):
            result, error = otx_lookup("1.2.3.4", "ip", "key", timeout=5)
        assert error is None
        assert result["pulse_count"] == 0

    def test_http_error_propagated(self):
        with _mock_http(401, None, "HTTP 401: Unauthorized"):
            result, error = otx_lookup("1.2.3.4", "ip", "bad-key", timeout=5)
        assert result is None
        assert error is not None

    def test_non_dict_response(self):
        with patch("mini_soar_enrichment.http_json_request", return_value=(200, None, None)):
            result, error = otx_lookup("1.2.3.4", "ip", "key", timeout=5)
        assert result is None
        assert "Unexpected" in error

    def test_ioc_type_in_result(self):
        payload = {"pulse_info": {"count": 1}}
        with _mock_http(200, payload):
            result, _ = otx_lookup("evil.com", "domain", "key", timeout=5)
        assert result["ioc_type"] == "domain"


# ══════════════════════════════════════════════════════════════════════════════
# Mock functions
# ══════════════════════════════════════════════════════════════════════════════

class TestGreynoiseMock:
    def test_returns_dict_and_no_error(self):
        result, error = greynoise_mock("1.2.3.4")
        assert error is None
        assert isinstance(result, dict)

    def test_deterministic(self):
        r1, _ = greynoise_mock("evil.com")
        r2, _ = greynoise_mock("evil.com")
        assert r1 == r2

    def test_different_iocs_may_differ(self):
        r1, _ = greynoise_mock("1.1.1.1")
        r2, _ = greynoise_mock("8.8.8.8")
        assert r1 != r2

    def test_required_fields(self):
        result, _ = greynoise_mock("1.2.3.4")
        for field in ("classification", "noise", "riot", "name", "link", "status"):
            assert field in result

    def test_classification_valid_values(self):
        for ioc in ["a", "b", "c", "d", "e", "f"]:
            result, _ = greynoise_mock(ioc)
            assert result["classification"] in {"benign", "malicious", "unknown"}

    def test_status_200(self):
        result, _ = greynoise_mock("test.io")
        assert result["status"] == 200


class TestShodanMock:
    def test_returns_dict_and_no_error(self):
        result, error = shodan_mock("1.2.3.4")
        assert error is None
        assert isinstance(result, dict)

    def test_deterministic(self):
        r1, _ = shodan_mock("1.2.3.4")
        r2, _ = shodan_mock("1.2.3.4")
        assert r1 == r2

    def test_required_fields(self):
        result, _ = shodan_mock("1.2.3.4")
        for field in ("ports", "vulns", "os", "org", "isp", "status"):
            assert field in result

    def test_ports_is_sorted_list(self):
        result, _ = shodan_mock("1.2.3.4")
        assert result["ports"] == sorted(result["ports"])

    def test_vulns_is_list(self):
        result, _ = shodan_mock("1.2.3.4")
        assert isinstance(result["vulns"], list)

    def test_status_200(self):
        result, _ = shodan_mock("1.2.3.4")
        assert result["status"] == 200


class TestOtxMock:
    def test_returns_dict_and_no_error(self):
        result, error = otx_mock("evil.com", "domain")
        assert error is None
        assert isinstance(result, dict)

    def test_deterministic(self):
        r1, _ = otx_mock("evil.com", "domain")
        r2, _ = otx_mock("evil.com", "domain")
        assert r1 == r2

    def test_required_fields(self):
        result, _ = otx_mock("1.2.3.4", "ip")
        for field in ("pulse_count", "ioc_type", "status"):
            assert field in result

    def test_unsupported_type_returns_error(self):
        result, error = otx_mock("something", "unknown")
        assert result is None
        assert error is not None

    def test_pulse_count_non_negative(self):
        for ioc in ["a.com", "1.1.1.1", "hash123", "http://x.com"]:
            result, _ = otx_mock(ioc, "domain")
            assert result["pulse_count"] >= 0

    def test_all_supported_types(self):
        for ioc_type in ("ip", "domain", "url", "hash"):
            result, error = otx_mock("test", ioc_type)
            assert error is None
            assert result["ioc_type"] == ioc_type


# ══════════════════════════════════════════════════════════════════════════════
# score_finding with new sources
# ══════════════════════════════════════════════════════════════════════════════

class TestScoreFindingGreyNoise:
    def test_malicious_adds_score(self):
        gn = {"classification": "malicious", "noise": False, "riot": False}
        score, reasons = score_finding(None, None, greynoise=gn)
        assert score == DEFAULT_SCORING_CONFIG["greynoise"]["malicious_score"]
        assert any("malicious" in r for r in reasons)

    def test_benign_reduces_score(self):
        # Start with some score from VT, then GreyNoise benign reduces it
        vt = {"analysis_stats": {"malicious": 5, "suspicious": 0}}
        base_score, _ = score_finding(vt, None)
        reduced_score, reasons = score_finding(vt, None, greynoise={"classification": "benign", "noise": False, "riot": False})
        assert reduced_score < base_score
        assert any("benign" in r.lower() for r in reasons)

    def test_riot_reduces_score(self):
        vt = {"analysis_stats": {"malicious": 3, "suspicious": 0}}
        base_score, _ = score_finding(vt, None)
        reduced_score, reasons = score_finding(vt, None, greynoise={"classification": "unknown", "noise": False, "riot": True})
        assert reduced_score < base_score
        assert any("riot" in r.lower() or "benign" in r.lower() for r in reasons)

    def test_noise_adds_score(self):
        gn = {"classification": "unknown", "noise": True, "riot": False}
        score, reasons = score_finding(None, None, greynoise=gn)
        assert score == DEFAULT_SCORING_CONFIG["greynoise"]["noise_score"]
        assert any("scanning" in r.lower() for r in reasons)

    def test_malicious_and_noise_cumulative(self):
        gn = {"classification": "malicious", "noise": True, "riot": False}
        score, _ = score_finding(None, None, greynoise=gn)
        expected = (
            DEFAULT_SCORING_CONFIG["greynoise"]["malicious_score"]
            + DEFAULT_SCORING_CONFIG["greynoise"]["noise_score"]
        )
        assert score == expected

    def test_benign_never_below_zero(self):
        gn = {"classification": "benign", "noise": False, "riot": False}
        score, _ = score_finding(None, None, greynoise=gn)
        assert score >= 0

    def test_none_greynoise_no_effect(self):
        score_without, _ = score_finding(None, None)
        score_with_none, _ = score_finding(None, None, greynoise=None)
        assert score_without == score_with_none


class TestScoreFindingShodan:
    def test_vulns_add_score(self):
        sh = {"ports": [], "vulns": ["CVE-2021-44228"]}
        score, reasons = score_finding(None, None, shodan=sh)
        assert score == DEFAULT_SCORING_CONFIG["shodan"]["vuln_score"]
        assert any("CVE" in r for r in reasons)

    def test_suspicious_ports_add_score(self):
        sh = {"ports": [4444], "vulns": []}
        score, reasons = score_finding(None, None, shodan=sh)
        assert score == DEFAULT_SCORING_CONFIG["shodan"]["suspicious_port_score"]
        assert any("4444" in r for r in reasons)

    def test_multiple_suspicious_ports_capped(self):
        # All 10 suspicious ports open — capped at suspicious_port_max_points
        sh = {"ports": list(_SHODAN_SUSPICIOUS_PORTS), "vulns": []}
        score, _ = score_finding(None, None, shodan=sh)
        assert score <= DEFAULT_SCORING_CONFIG["shodan"]["suspicious_port_max_points"]

    def test_safe_ports_do_not_add_score(self):
        sh = {"ports": [80, 443], "vulns": []}
        score, _ = score_finding(None, None, shodan=sh)
        assert score == 0

    def test_vulns_and_ports_cumulative(self):
        sh = {"ports": [4444], "vulns": ["CVE-2021-44228"]}
        score, _ = score_finding(None, None, shodan=sh)
        expected = (
            DEFAULT_SCORING_CONFIG["shodan"]["vuln_score"]
            + DEFAULT_SCORING_CONFIG["shodan"]["suspicious_port_score"]
        )
        assert score == expected

    def test_none_shodan_no_effect(self):
        score, _ = score_finding(None, None, shodan=None)
        assert score == 0

    def test_multiple_cves_in_reason(self):
        sh = {"ports": [], "vulns": ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3", "CVE-2021-4"]}
        _, reasons = score_finding(None, None, shodan=sh)
        cve_reason = next(r for r in reasons if "CVE" in r)
        assert "…" in cve_reason  # truncated at 3


class TestScoreFindingOTX:
    def test_high_pulse_count(self):
        otx = {"pulse_count": 10, "ioc_type": "ip"}
        score, reasons = score_finding(None, None, otx=otx)
        assert score == DEFAULT_SCORING_CONFIG["otx"]["pulse_high_score"]
        assert any("OTX" in r and "high" in r for r in reasons)

    def test_medium_pulse_count(self):
        otx = {"pulse_count": 3, "ioc_type": "domain"}
        score, reasons = score_finding(None, None, otx=otx)
        assert score == DEFAULT_SCORING_CONFIG["otx"]["pulse_medium_score"]
        assert any("OTX" in r and "medium" in r for r in reasons)

    def test_low_pulse_count(self):
        otx = {"pulse_count": 1, "ioc_type": "domain"}
        score, reasons = score_finding(None, None, otx=otx)
        assert score == DEFAULT_SCORING_CONFIG["otx"]["pulse_low_score"]
        assert any("OTX" in r and "low" in r for r in reasons)

    def test_zero_pulses_no_contribution(self):
        otx = {"pulse_count": 0, "ioc_type": "domain"}
        score, reasons = score_finding(None, None, otx=otx)
        assert score == 0
        assert not any("OTX" in r for r in reasons)

    def test_none_otx_no_effect(self):
        score, _ = score_finding(None, None, otx=None)
        assert score == 0

    def test_exactly_at_high_threshold(self):
        threshold = DEFAULT_SCORING_CONFIG["otx"]["pulse_high_threshold"]
        otx = {"pulse_count": threshold}
        score, _ = score_finding(None, None, otx=otx)
        assert score == DEFAULT_SCORING_CONFIG["otx"]["pulse_high_score"]


class TestScoreFindingAllSources:
    def test_all_sources_cumulative(self):
        vt  = {"analysis_stats": {"malicious": 5, "suspicious": 0}}
        gn  = {"classification": "malicious", "noise": True, "riot": False}
        sh  = {"ports": [4444], "vulns": ["CVE-2021-44228"]}
        otx = {"pulse_count": 10}
        score, reasons = score_finding(vt, None, greynoise=gn, shodan=sh, otx=otx)
        # Score should be significantly higher than any single source alone
        vt_only, _ = score_finding(vt, None)
        assert score > vt_only
        assert len(reasons) >= 4

    def test_backward_compat_no_new_sources(self):
        """Existing callers that don't pass new sources get identical results."""
        vt = {"analysis_stats": {"malicious": 5, "suspicious": 2}, "reputation": -10}
        old_score, old_reasons = score_finding(vt, None)
        new_score, new_reasons = score_finding(vt, None, greynoise=None, shodan=None, otx=None)
        assert old_score == new_score
        assert old_reasons == new_reasons

    def test_score_capped_at_max(self):
        """Even with all sources firing at max, score stays ≤ 100."""
        vt    = {"analysis_stats": {"malicious": 20, "suspicious": 10}, "reputation": -50}
        abuse = {"abuse_confidence_score": 100, "total_reports": 100}
        gn    = {"classification": "malicious", "noise": True, "riot": False}
        sh    = {"ports": list(_SHODAN_SUSPICIOUS_PORTS), "vulns": ["CVE-2021-1"]}
        otx   = {"pulse_count": 100}
        score, _ = score_finding(vt, abuse, greynoise=gn, shodan=sh, otx=otx)
        assert score <= 100


# ══════════════════════════════════════════════════════════════════════════════
# process_ioc integration
# ══════════════════════════════════════════════════════════════════════════════

class TestProcessIocNewSources:
    def _make_config(self, **kwargs):
        from mini_soar_core import RuntimeConfig
        defaults = dict(
            demo_mode=False,
            vt_api_key=None,
            abuse_api_key=None,
            greynoise_api_key=None,
            shodan_api_key=None,
            otx_api_key=None,
            enable_idempotency=False,
            persist_findings=False,
        )
        defaults.update(kwargs)
        return RuntimeConfig(**defaults)

    def test_greynoise_included_when_key_set_and_ip(self):
        cfg = self._make_config(greynoise_api_key="gn-key")
        gn_data = {"status": 200, "classification": "malicious", "noise": True, "riot": False, "name": None, "link": None}
        with patch("mini_soar_core.greynoise_lookup", return_value=(gn_data, None)) as mock_gn:
            from mini_soar_core import process_ioc
            finding = process_ioc("1.2.3.4", cfg)
        mock_gn.assert_called_once()
        assert finding["greynoise"] == gn_data
        assert "greynoise" in finding["sources_queried"]

    def test_greynoise_skipped_for_non_ip(self):
        cfg = self._make_config(greynoise_api_key="gn-key")
        with patch("mini_soar_core.greynoise_lookup") as mock_gn:
            from mini_soar_core import process_ioc
            process_ioc("evil.com", cfg)
        mock_gn.assert_not_called()

    def test_greynoise_skipped_without_key(self):
        cfg = self._make_config(greynoise_api_key=None)
        with patch("mini_soar_core.greynoise_lookup") as mock_gn:
            from mini_soar_core import process_ioc
            process_ioc("1.2.3.4", cfg)
        mock_gn.assert_not_called()

    def test_shodan_included_when_key_set_and_ip(self):
        cfg = self._make_config(shodan_api_key="sh-key")
        sh_data = {"status": 200, "ports": [80], "vulns": [], "os": None, "org": None, "isp": None}
        with patch("mini_soar_core.shodan_lookup", return_value=(sh_data, None)) as mock_sh:
            from mini_soar_core import process_ioc
            finding = process_ioc("1.2.3.4", cfg)
        mock_sh.assert_called_once()
        assert finding["shodan"] == sh_data
        assert "shodan" in finding["sources_queried"]

    def test_shodan_skipped_for_non_ip(self):
        cfg = self._make_config(shodan_api_key="sh-key")
        with patch("mini_soar_core.shodan_lookup") as mock_sh:
            from mini_soar_core import process_ioc
            process_ioc("evil.com", cfg)
        mock_sh.assert_not_called()

    def test_shodan_skipped_without_key(self):
        cfg = self._make_config(shodan_api_key=None)
        with patch("mini_soar_core.shodan_lookup") as mock_sh:
            from mini_soar_core import process_ioc
            process_ioc("1.2.3.4", cfg)
        mock_sh.assert_not_called()

    def test_otx_included_when_key_set(self):
        cfg = self._make_config(otx_api_key="otx-key")
        otx_data = {"status": 200, "pulse_count": 7, "ioc_type": "domain"}
        with patch("mini_soar_core.otx_lookup", return_value=(otx_data, None)) as mock_otx:
            from mini_soar_core import process_ioc
            finding = process_ioc("evil.com", cfg)
        mock_otx.assert_called_once()
        assert finding["otx"] == otx_data
        assert "otx" in finding["sources_queried"]

    def test_otx_skipped_without_key(self):
        cfg = self._make_config(otx_api_key=None)
        with patch("mini_soar_core.otx_lookup") as mock_otx:
            from mini_soar_core import process_ioc
            process_ioc("evil.com", cfg)
        mock_otx.assert_not_called()

    def test_otx_called_for_all_ioc_types(self):
        cfg = self._make_config(otx_api_key="otx-key")
        otx_data = {"status": 200, "pulse_count": 0, "ioc_type": "domain"}
        for ioc in ["evil.com", "http://x.com/p", "abc123hash"]:
            with patch("mini_soar_core.otx_lookup", return_value=(otx_data, None)) as mock_otx:
                from mini_soar_core import process_ioc
                process_ioc(ioc, cfg)
            mock_otx.assert_called_once()

    def test_sources_queried_empty_when_no_keys(self):
        cfg = self._make_config()
        from mini_soar_core import process_ioc
        finding = process_ioc("1.2.3.4", cfg)
        assert finding["sources_queried"] == []

    def test_error_from_new_source_does_not_crash(self):
        cfg = self._make_config(greynoise_api_key="key", shodan_api_key="key", otx_api_key="key")
        with (
            patch("mini_soar_core.greynoise_lookup", return_value=(None, "timeout")),
            patch("mini_soar_core.shodan_lookup",    return_value=(None, "auth error")),
            patch("mini_soar_core.otx_lookup",       return_value=(None, "rate limited")),
        ):
            from mini_soar_core import process_ioc
            finding = process_ioc("1.2.3.4", cfg)
        assert finding["greynoise"] is None
        assert finding["shodan"] is None
        assert finding["otx"] is None
        assert any("GreyNoise" in e for e in finding["errors"])
        assert any("Shodan" in e for e in finding["errors"])
        assert any("OTX" in e for e in finding["errors"])

    def test_demo_mode_always_includes_ip_sources(self):
        cfg = self._make_config(demo_mode=True)
        from mini_soar_core import process_ioc
        finding = process_ioc("1.2.3.4", cfg)
        assert finding["greynoise"] is not None
        assert finding["shodan"] is not None
        assert finding["otx"] is not None
        assert "greynoise" in finding["sources_queried"]
        assert "shodan" in finding["sources_queried"]
        assert "otx" in finding["sources_queried"]

    def test_demo_mode_domain_skips_ip_only_sources(self):
        cfg = self._make_config(demo_mode=True)
        from mini_soar_core import process_ioc
        finding = process_ioc("evil.com", cfg)
        # greynoise and shodan are ip-only; otx covers all types
        assert finding["greynoise"] is None
        assert finding["shodan"] is None
        assert finding["otx"] is not None
