#!/usr/bin/env python3
"""Configurable risk scoring for SentinelCore SOAR.

Default weights and thresholds match the original hardcoded values, so
dropping this module in is fully backward-compatible.

A custom config can be loaded from a JSON file via load_scoring_config().
Partial configs are merged with defaults, so only the keys you want to
override need to be present in the file.
"""

from __future__ import annotations

import json
import logging
from typing import Any

_log = logging.getLogger("mini_soar.scoring")


# ── Defaults (mirror of original hardcoded values) ─────────────────────────────

DEFAULT_SCORING_CONFIG: dict[str, Any] = {
    "virustotal": {
        "malicious_high_threshold": 10,
        "malicious_high_score": 70,
        "malicious_medium_threshold": 3,
        "malicious_medium_score": 50,
        "malicious_low_threshold": 1,
        "malicious_low_score": 30,
        "suspicious_high_threshold": 5,
        "suspicious_high_score": 15,
        "suspicious_low_threshold": 1,
        "suspicious_low_score": 5,
        "negative_reputation_max_points": 20,
    },
    "abuseipdb": {
        "confidence_very_high_threshold": 90,
        "confidence_very_high_score": 35,
        "confidence_high_threshold": 60,
        "confidence_high_score": 25,
        "confidence_medium_threshold": 30,
        "confidence_medium_score": 10,
        "reports_high_threshold": 50,
        "reports_high_score": 15,
        "reports_low_threshold": 10,
        "reports_low_score": 7,
    },
    # ── GreyNoise ─────────────────────────────────────────────────────────────
    # Benign/RIOT classification reduces score (IP is a known CDN or legitimate
    # scanner) while malicious classification increases it.  Noise means the IP
    # has been seen actively scanning the internet.
    "greynoise": {
        "malicious_score": 25,
        "benign_reduction": 20,
        "noise_score": 10,
    },
    # ── Shodan ────────────────────────────────────────────────────────────────
    # CVEs on the host and suspicious open ports both increase the score.
    "shodan": {
        "vuln_score": 20,
        "suspicious_port_score": 10,
        "suspicious_port_max_points": 20,
    },
    # ── OTX AlienVault ────────────────────────────────────────────────────────
    # The pulse_count reflects how many threat intelligence reports (pulses)
    # mention this IOC.  Higher counts → higher risk.
    "otx": {
        "pulse_high_threshold": 5,
        "pulse_high_score": 20,
        "pulse_medium_threshold": 2,
        "pulse_medium_score": 10,
        "pulse_low_threshold": 1,
        "pulse_low_score": 5,
    },
    "max_score": 100,
}

# Ports that commonly indicate C2 activity, exposed admin services, or
# vulnerable databases.  Used by the Shodan scorer.
_SHODAN_SUSPICIOUS_PORTS: frozenset[int] = frozenset({
    4444, 5555, 6666, 1080, 3389, 9200, 27017, 6379, 5900, 8443,
})

_VT_INT_KEYS: frozenset[str] = frozenset({
    "malicious_high_threshold", "malicious_high_score",
    "malicious_medium_threshold", "malicious_medium_score",
    "malicious_low_threshold", "malicious_low_score",
    "suspicious_high_threshold", "suspicious_high_score",
    "suspicious_low_threshold", "suspicious_low_score",
    "negative_reputation_max_points",
})

_ABUSE_INT_KEYS: frozenset[str] = frozenset({
    "confidence_very_high_threshold", "confidence_very_high_score",
    "confidence_high_threshold", "confidence_high_score",
    "confidence_medium_threshold", "confidence_medium_score",
    "reports_high_threshold", "reports_high_score",
    "reports_low_threshold", "reports_low_score",
})


# ── Validation ─────────────────────────────────────────────────────────────────

def _validate_scoring_config(cfg: dict[str, Any]) -> list[str]:
    """Return a list of validation error messages (empty means valid)."""
    errors: list[str] = []

    if not isinstance(cfg.get("max_score"), int) or cfg["max_score"] <= 0:
        errors.append("max_score must be a positive integer")

    vt = cfg.get("virustotal")
    if not isinstance(vt, dict):
        errors.append("virustotal section must be a dict")
    else:
        for key in _VT_INT_KEYS:
            if key not in vt:
                errors.append(f"virustotal.{key} is missing")
            elif not isinstance(vt[key], int) or vt[key] < 0:
                errors.append(f"virustotal.{key} must be a non-negative integer")

    abuse = cfg.get("abuseipdb")
    if not isinstance(abuse, dict):
        errors.append("abuseipdb section must be a dict")
    else:
        for key in _ABUSE_INT_KEYS:
            if key not in abuse:
                errors.append(f"abuseipdb.{key} is missing")
            elif not isinstance(abuse[key], int) or abuse[key] < 0:
                errors.append(f"abuseipdb.{key} must be a non-negative integer")

    return errors


# ── Loader ─────────────────────────────────────────────────────────────────────

def load_scoring_config(path: str | None) -> dict[str, Any]:
    """Load scoring configuration from a JSON file.

    - Returns DEFAULT_SCORING_CONFIG when *path* is None.
    - Returns DEFAULT_SCORING_CONFIG when the file does not exist (silent).
    - Falls back to DEFAULT_SCORING_CONFIG and logs a warning for malformed
      files or invalid field types.
    - Partial configs are merged with defaults so only overridden keys need
      to be present.
    """
    if path is None:
        return DEFAULT_SCORING_CONFIG

    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except FileNotFoundError:
        return DEFAULT_SCORING_CONFIG
    except Exception as exc:
        _log.warning("Failed to parse scoring config %r: %s — using defaults", path, exc)
        return DEFAULT_SCORING_CONFIG

    if not isinstance(raw, dict):
        _log.warning("Scoring config %r is not a JSON object — using defaults", path)
        return DEFAULT_SCORING_CONFIG

    # Merge: unknown top-level keys are ignored; section keys are overlaid on defaults
    merged: dict[str, Any] = {
        "max_score": raw.get("max_score", DEFAULT_SCORING_CONFIG["max_score"]),
        "virustotal": {
            **DEFAULT_SCORING_CONFIG["virustotal"],
            **{k: v for k, v in raw.get("virustotal", {}).items()},
        },
        "abuseipdb": {
            **DEFAULT_SCORING_CONFIG["abuseipdb"],
            **{k: v for k, v in raw.get("abuseipdb", {}).items()},
        },
        "greynoise": {
            **DEFAULT_SCORING_CONFIG["greynoise"],
            **{k: v for k, v in raw.get("greynoise", {}).items()},
        },
        "shodan": {
            **DEFAULT_SCORING_CONFIG["shodan"],
            **{k: v for k, v in raw.get("shodan", {}).items()},
        },
        "otx": {
            **DEFAULT_SCORING_CONFIG["otx"],
            **{k: v for k, v in raw.get("otx", {}).items()},
        },
    }

    validation_errors = _validate_scoring_config(merged)
    if validation_errors:
        _log.warning(
            "Scoring config %r has %d validation error(s): %s — using defaults",
            path, len(validation_errors), "; ".join(validation_errors),
        )
        return DEFAULT_SCORING_CONFIG

    return merged


# ── Scorer ─────────────────────────────────────────────────────────────────────

def score_finding(
    vt: dict[str, Any] | None,
    abuse: dict[str, Any] | None,
    scoring_config: dict[str, Any] | None = None,
    *,
    greynoise: dict[str, Any] | None = None,
    shodan: dict[str, Any] | None = None,
    otx: dict[str, Any] | None = None,
) -> tuple[int, list[str]]:
    """Compute a 0–100 risk score and list of reasons from enrichment data.

    When *scoring_config* is None the function uses DEFAULT_SCORING_CONFIG,
    preserving full backward compatibility with callers that omit the argument.

    The three new keyword-only parameters (*greynoise*, *shodan*, *otx*) are
    optional and default to None, maintaining full backward compatibility.
    """
    cfg = scoring_config if scoring_config is not None else DEFAULT_SCORING_CONFIG
    vt_cfg    = cfg.get("virustotal", DEFAULT_SCORING_CONFIG["virustotal"])
    abuse_cfg = cfg.get("abuseipdb",  DEFAULT_SCORING_CONFIG["abuseipdb"])
    gn_cfg    = cfg.get("greynoise",  DEFAULT_SCORING_CONFIG["greynoise"])
    sh_cfg    = cfg.get("shodan",     DEFAULT_SCORING_CONFIG["shodan"])
    otx_cfg   = cfg.get("otx",        DEFAULT_SCORING_CONFIG["otx"])
    max_score = int(cfg.get("max_score", 100))

    score = 0
    reasons: list[str] = []

    if vt:
        stats      = vt.get("analysis_stats", {})
        malicious  = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        reputation = vt.get("reputation")

        m_high_t = int(vt_cfg["malicious_high_threshold"])
        m_high_s = int(vt_cfg["malicious_high_score"])
        m_med_t  = int(vt_cfg["malicious_medium_threshold"])
        m_med_s  = int(vt_cfg["malicious_medium_score"])
        m_low_t  = int(vt_cfg["malicious_low_threshold"])
        m_low_s  = int(vt_cfg["malicious_low_score"])

        if malicious >= m_high_t:
            score += m_high_s
            reasons.append(f"VirusTotal malicious engines: {malicious} (high)")
        elif malicious >= m_med_t:
            score += m_med_s
            reasons.append(f"VirusTotal malicious engines: {malicious} (medium)")
        elif malicious >= m_low_t:
            score += m_low_s
            reasons.append(f"VirusTotal malicious engines: {malicious} (low)")

        s_high_t = int(vt_cfg["suspicious_high_threshold"])
        s_high_s = int(vt_cfg["suspicious_high_score"])
        s_low_t  = int(vt_cfg["suspicious_low_threshold"])
        s_low_s  = int(vt_cfg["suspicious_low_score"])
        rep_max  = int(vt_cfg["negative_reputation_max_points"])

        if suspicious >= s_high_t:
            score += s_high_s
            reasons.append(f"VirusTotal suspicious engines: {suspicious}")
        elif suspicious >= s_low_t:
            score += s_low_s
            reasons.append(f"VirusTotal suspicious engines: {suspicious}")

        if isinstance(reputation, int) and reputation < 0:
            rep_points = min(abs(reputation), rep_max)
            score += rep_points
            reasons.append(f"Negative reputation in VirusTotal: {reputation}")

    if abuse:
        abuse_conf    = int(abuse.get("abuse_confidence_score", 0))
        total_reports = int(abuse.get("total_reports", 0))

        c_vh_t = int(abuse_cfg["confidence_very_high_threshold"])
        c_vh_s = int(abuse_cfg["confidence_very_high_score"])
        c_h_t  = int(abuse_cfg["confidence_high_threshold"])
        c_h_s  = int(abuse_cfg["confidence_high_score"])
        c_m_t  = int(abuse_cfg["confidence_medium_threshold"])
        c_m_s  = int(abuse_cfg["confidence_medium_score"])
        r_h_t  = int(abuse_cfg["reports_high_threshold"])
        r_h_s  = int(abuse_cfg["reports_high_score"])
        r_l_t  = int(abuse_cfg["reports_low_threshold"])
        r_l_s  = int(abuse_cfg["reports_low_score"])

        if abuse_conf >= c_vh_t:
            score += c_vh_s
            reasons.append(f"AbuseIPDB confidence score: {abuse_conf} (very high)")
        elif abuse_conf >= c_h_t:
            score += c_h_s
            reasons.append(f"AbuseIPDB confidence score: {abuse_conf} (high)")
        elif abuse_conf >= c_m_t:
            score += c_m_s
            reasons.append(f"AbuseIPDB confidence score: {abuse_conf} (medium)")

        if total_reports >= r_h_t:
            score += r_h_s
            reasons.append(f"AbuseIPDB reports: {total_reports}")
        elif total_reports >= r_l_t:
            score += r_l_s
            reasons.append(f"AbuseIPDB reports: {total_reports}")

    if greynoise:
        classification = str(greynoise.get("classification", "unknown"))
        noise = bool(greynoise.get("noise", False))
        riot  = bool(greynoise.get("riot", False))

        gn_malicious_score  = int(gn_cfg.get("malicious_score",  25))
        gn_benign_reduction = int(gn_cfg.get("benign_reduction", 20))
        gn_noise_score      = int(gn_cfg.get("noise_score",      10))

        if classification == "malicious":
            score += gn_malicious_score
            reasons.append(f"GreyNoise classification: malicious")
        elif classification == "benign" or riot:
            label = "RIOT/benign CDN" if riot else "benign"
            score = max(0, score - gn_benign_reduction)
            reasons.append(f"GreyNoise classification: {label} (score reduced)")

        if noise:
            score += gn_noise_score
            reasons.append("GreyNoise: IP actively scanning the internet")

    if shodan:
        vulns = shodan.get("vulns") or []
        ports = [int(p) for p in (shodan.get("ports") or [])]

        sh_vuln_score        = int(sh_cfg.get("vuln_score",               20))
        sh_port_score        = int(sh_cfg.get("suspicious_port_score",    10))
        sh_port_max          = int(sh_cfg.get("suspicious_port_max_points", 20))

        if vulns:
            score += sh_vuln_score
            reasons.append(f"Shodan: {len(vulns)} CVE(s) found ({', '.join(vulns[:3])}{'…' if len(vulns) > 3 else ''})")

        suspicious_open = [p for p in ports if p in _SHODAN_SUSPICIOUS_PORTS]
        if suspicious_open:
            port_points = min(len(suspicious_open) * sh_port_score, sh_port_max)
            score += port_points
            reasons.append(f"Shodan: suspicious open port(s): {', '.join(str(p) for p in suspicious_open)}")

    if otx:
        pulse_count = int(otx.get("pulse_count", 0))

        otx_high_t = int(otx_cfg.get("pulse_high_threshold",   5))
        otx_high_s = int(otx_cfg.get("pulse_high_score",      20))
        otx_med_t  = int(otx_cfg.get("pulse_medium_threshold", 2))
        otx_med_s  = int(otx_cfg.get("pulse_medium_score",    10))
        otx_low_t  = int(otx_cfg.get("pulse_low_threshold",    1))
        otx_low_s  = int(otx_cfg.get("pulse_low_score",        5))

        if pulse_count >= otx_high_t:
            score += otx_high_s
            reasons.append(f"OTX: {pulse_count} pulse(s) referencing this IOC (high)")
        elif pulse_count >= otx_med_t:
            score += otx_med_s
            reasons.append(f"OTX: {pulse_count} pulse(s) referencing this IOC (medium)")
        elif pulse_count >= otx_low_t:
            score += otx_low_s
            reasons.append(f"OTX: {pulse_count} pulse(s) referencing this IOC (low)")

    return min(score, max_score), reasons
