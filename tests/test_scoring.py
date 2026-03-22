"""Tests for configurable scoring weights (mini_soar_scoring)."""

from __future__ import annotations

import json
import os
import tempfile

from mini_soar_scoring import DEFAULT_SCORING_CONFIG, load_scoring_config, score_finding


# ── Helpers ─────────────────────────────────────────────────────────────────────

def _vt(malicious: int = 0, suspicious: int = 0, reputation: int | None = None) -> dict:
    result: dict = {"analysis_stats": {"malicious": malicious, "suspicious": suspicious}}
    if reputation is not None:
        result["reputation"] = reputation
    return result


def _abuse(confidence: int = 0, reports: int = 0) -> dict:
    return {"abuse_confidence_score": confidence, "total_reports": reports}


def _write_json(data: dict) -> str:
    """Write *data* to a temporary JSON file; caller must delete it."""
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    json.dump(data, fh)
    fh.close()
    return fh.name


# ── Default config — backward-compatibility ─────────────────────────────────────

def test_default_vt_malicious_high():
    score, reasons = score_finding(_vt(malicious=10), None)
    assert score == 70
    assert "high" in reasons[0]


def test_default_vt_malicious_medium():
    score, reasons = score_finding(_vt(malicious=5), None)
    assert score == 50
    assert "medium" in reasons[0]


def test_default_vt_malicious_low():
    score, reasons = score_finding(_vt(malicious=1), None)
    assert score == 30
    assert "low" in reasons[0]


def test_default_vt_no_malicious():
    score, reasons = score_finding(_vt(malicious=0), None)
    assert score == 0
    assert reasons == []


def test_default_vt_suspicious_high():
    score, _ = score_finding(_vt(suspicious=5), None)
    assert score == 15


def test_default_vt_suspicious_low():
    score, _ = score_finding(_vt(suspicious=2), None)
    assert score == 5


def test_default_vt_suspicious_none():
    score, reasons = score_finding(_vt(suspicious=0), None)
    assert score == 0
    assert reasons == []


def test_default_vt_negative_reputation():
    score, reasons = score_finding(_vt(reputation=-10), None)
    assert score == 10
    assert "reputation" in reasons[0].lower()


def test_default_vt_reputation_capped_at_max_points():
    score, _ = score_finding(_vt(reputation=-999), None)
    assert score == 20  # negative_reputation_max_points default


def test_default_vt_positive_reputation_ignored():
    score, reasons = score_finding(_vt(reputation=5), None)
    assert score == 0
    assert reasons == []


def test_default_abuse_very_high_confidence():
    score, reasons = score_finding(None, _abuse(confidence=90))
    assert score == 35
    assert "very high" in reasons[0]


def test_default_abuse_high_confidence():
    score, reasons = score_finding(None, _abuse(confidence=60))
    assert score == 25
    assert "(high)" in reasons[0]


def test_default_abuse_medium_confidence():
    score, reasons = score_finding(None, _abuse(confidence=30))
    assert score == 10
    assert "medium" in reasons[0]


def test_default_abuse_below_medium_no_confidence_score():
    score, reasons = score_finding(None, _abuse(confidence=29))
    assert score == 0
    assert reasons == []


def test_default_abuse_reports_high():
    score, _ = score_finding(None, _abuse(reports=50))
    assert score == 15


def test_default_abuse_reports_low():
    score, _ = score_finding(None, _abuse(reports=10))
    assert score == 7


def test_default_abuse_reports_below_threshold():
    score, reasons = score_finding(None, _abuse(reports=9))
    assert score == 0
    assert reasons == []


def test_default_combined_vt_and_abuse():
    score, reasons = score_finding(_vt(malicious=10), _abuse(confidence=90))
    assert score == min(70 + 35, 100)
    assert len(reasons) == 2


def test_default_score_capped_at_100():
    score, _ = score_finding(
        _vt(malicious=15, suspicious=10, reputation=-50),
        _abuse(confidence=95, reports=100),
    )
    assert score == 100


def test_no_data_returns_zero():
    score, reasons = score_finding(None, None)
    assert score == 0
    assert reasons == []


# ── Custom config via dict ────────────────────────────────────────────────────

def test_custom_higher_malicious_threshold_downgrades_to_medium():
    """Raising the high threshold means 10 malicious hits medium instead of high."""
    cfg = {
        **DEFAULT_SCORING_CONFIG,
        "virustotal": {
            **DEFAULT_SCORING_CONFIG["virustotal"],
            "malicious_high_threshold": 20,
        },
    }
    score, reasons = score_finding(_vt(malicious=10), None, scoring_config=cfg)
    assert score == 50
    assert "medium" in reasons[0]


def test_custom_lower_malicious_score_reduces_output():
    cfg = {
        **DEFAULT_SCORING_CONFIG,
        "virustotal": {
            **DEFAULT_SCORING_CONFIG["virustotal"],
            "malicious_high_score": 40,
        },
    }
    score, _ = score_finding(_vt(malicious=15), None, scoring_config=cfg)
    assert score == 40


def test_custom_max_score_clamps_result():
    cfg = {**DEFAULT_SCORING_CONFIG, "max_score": 50}
    score, _ = score_finding(
        _vt(malicious=15, suspicious=5),
        _abuse(confidence=95, reports=60),
        scoring_config=cfg,
    )
    assert score == 50


def test_custom_abuse_confidence_threshold():
    cfg = {
        **DEFAULT_SCORING_CONFIG,
        "abuseipdb": {
            **DEFAULT_SCORING_CONFIG["abuseipdb"],
            "confidence_very_high_threshold": 50,
            "confidence_very_high_score": 40,
        },
    }
    score, reasons = score_finding(None, _abuse(confidence=55), scoring_config=cfg)
    assert score == 40
    assert "very high" in reasons[0]


def test_custom_reputation_max_points():
    cfg = {
        **DEFAULT_SCORING_CONFIG,
        "virustotal": {
            **DEFAULT_SCORING_CONFIG["virustotal"],
            "negative_reputation_max_points": 5,
        },
    }
    score, _ = score_finding(_vt(reputation=-100), None, scoring_config=cfg)
    assert score == 5


def test_none_scoring_config_equals_default():
    """Passing None is identical to passing the default config."""
    vt = _vt(malicious=7, suspicious=3)
    abuse = _abuse(confidence=75, reports=30)
    score_none, reasons_none = score_finding(vt, abuse, scoring_config=None)
    score_def, reasons_def = score_finding(vt, abuse, scoring_config=DEFAULT_SCORING_CONFIG)
    assert score_none == score_def
    assert reasons_none == reasons_def


# ── load_scoring_config ───────────────────────────────────────────────────────

def test_load_none_returns_defaults():
    assert load_scoring_config(None) == DEFAULT_SCORING_CONFIG


def test_load_nonexistent_path_returns_defaults():
    assert load_scoring_config("/no/such/file_xyz.json") == DEFAULT_SCORING_CONFIG


def test_load_valid_full_json():
    custom = {
        "virustotal": {**DEFAULT_SCORING_CONFIG["virustotal"], "malicious_high_score": 80},
        "abuseipdb": DEFAULT_SCORING_CONFIG["abuseipdb"],
        "max_score": 100,
    }
    path = _write_json(custom)
    try:
        cfg = load_scoring_config(path)
        assert cfg["virustotal"]["malicious_high_score"] == 80
        assert cfg["abuseipdb"] == DEFAULT_SCORING_CONFIG["abuseipdb"]
    finally:
        os.unlink(path)


def test_load_partial_config_merges_with_defaults():
    """Only override one key; all others should remain at default values."""
    partial = {"virustotal": {"malicious_high_score": 99}}
    path = _write_json(partial)
    try:
        cfg = load_scoring_config(path)
        assert cfg["virustotal"]["malicious_high_score"] == 99
        assert cfg["virustotal"]["malicious_high_threshold"] == (
            DEFAULT_SCORING_CONFIG["virustotal"]["malicious_high_threshold"]
        )
        assert cfg["abuseipdb"] == DEFAULT_SCORING_CONFIG["abuseipdb"]
        assert cfg["max_score"] == DEFAULT_SCORING_CONFIG["max_score"]
    finally:
        os.unlink(path)


def test_load_invalid_json_falls_back_to_defaults():
    fh = tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    )
    fh.write("not valid json {{{")
    fh.close()
    try:
        assert load_scoring_config(fh.name) == DEFAULT_SCORING_CONFIG
    finally:
        os.unlink(fh.name)


def test_load_string_field_fails_validation_and_falls_back():
    invalid = {
        "virustotal": {
            **DEFAULT_SCORING_CONFIG["virustotal"],
            "malicious_high_score": "not-an-int",
        },
        "abuseipdb": DEFAULT_SCORING_CONFIG["abuseipdb"],
        "max_score": 100,
    }
    path = _write_json(invalid)
    try:
        assert load_scoring_config(path) == DEFAULT_SCORING_CONFIG
    finally:
        os.unlink(path)


def test_load_negative_field_fails_validation_and_falls_back():
    invalid = {
        "virustotal": {
            **DEFAULT_SCORING_CONFIG["virustotal"],
            "malicious_high_score": -5,
        },
        "abuseipdb": DEFAULT_SCORING_CONFIG["abuseipdb"],
        "max_score": 100,
    }
    path = _write_json(invalid)
    try:
        assert load_scoring_config(path) == DEFAULT_SCORING_CONFIG
    finally:
        os.unlink(path)


def test_load_non_dict_json_falls_back():
    path = _write_json([1, 2, 3])
    try:
        assert load_scoring_config(path) == DEFAULT_SCORING_CONFIG
    finally:
        os.unlink(path)


def test_load_invalid_max_score_falls_back():
    invalid = {**DEFAULT_SCORING_CONFIG, "max_score": 0}
    path = _write_json(invalid)
    try:
        assert load_scoring_config(path) == DEFAULT_SCORING_CONFIG
    finally:
        os.unlink(path)


# ── Integration: load from file then score ────────────────────────────────────

def test_file_config_lowers_threshold_and_affects_score():
    """Custom high threshold of 5 → malicious=5 should now give high score."""
    custom = {
        "virustotal": {
            **DEFAULT_SCORING_CONFIG["virustotal"],
            "malicious_high_threshold": 5,
            "malicious_high_score": 60,
        },
        "abuseipdb": DEFAULT_SCORING_CONFIG["abuseipdb"],
        "max_score": 100,
    }
    path = _write_json(custom)
    try:
        cfg = load_scoring_config(path)
        score, reasons = score_finding(_vt(malicious=5), None, scoring_config=cfg)
        assert score == 60
        assert "high" in reasons[0]
    finally:
        os.unlink(path)


def test_project_scoring_config_json_is_valid():
    """The committed scoring_config.json must load cleanly and equal defaults."""
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    path = os.path.join(project_root, "scoring_config.json")
    cfg = load_scoring_config(path)
    assert cfg == DEFAULT_SCORING_CONFIG
