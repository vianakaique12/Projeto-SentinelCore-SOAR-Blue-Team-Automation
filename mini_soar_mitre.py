#!/usr/bin/env python3
"""MITRE ATT&CK mapping and runbook generation for SentinelCore SOAR.

Techniques are mapped in two passes:
1. Base mapping by IOC type (always applied as fallback).
2. Enrichment-driven mapping using VirusTotal and AbuseIPDB findings.

Duplicate technique IDs are deduplicated while preserving insertion order.
"""

from __future__ import annotations

from typing import Any


# ── Technique catalogue ────────────────────────────────────────────────────────

_T: dict[str, dict[str, str]] = {
    "T1027":    {"technique_id": "T1027",    "name": "Obfuscated Files or Information"},
    "T1041":    {"technique_id": "T1041",    "name": "Exfiltration Over C2 Channel"},
    "T1059":    {"technique_id": "T1059",    "name": "Command and Scripting Interpreter"},
    "T1071":    {"technique_id": "T1071",    "name": "Application Layer Protocol"},
    "T1071.001":{"technique_id": "T1071.001","name": "Application Layer Protocol: Web"},
    "T1090":    {"technique_id": "T1090",    "name": "Proxy"},
    "T1189":    {"technique_id": "T1189",    "name": "Drive-by Compromise"},
    "T1204":    {"technique_id": "T1204",    "name": "User Execution"},
    "T1486":    {"technique_id": "T1486",    "name": "Data Encrypted for Impact"},
    "T1566":    {"technique_id": "T1566",    "name": "Phishing"},
    "T1572":    {"technique_id": "T1572",    "name": "Protocol Tunneling"},
    "T1583.003":{"technique_id": "T1583.003","name": "Acquire Infrastructure: Virtual Private Server"},
    "T1595":    {"technique_id": "T1595",    "name": "Active Scanning"},
    "T1598":    {"technique_id": "T1598",    "name": "Phishing for Information"},
}


def _t(*ids: str) -> list[dict[str, str]]:
    """Look up one or more technique IDs from the catalogue."""
    return [_T[tid] for tid in ids if tid in _T]


# ── Base mapping (by IOC type) ─────────────────────────────────────────────────

_BASE_BY_TYPE: dict[str, list[dict[str, str]]] = {
    "ip":      _t("T1071", "T1041"),
    "domain":  _t("T1566", "T1071.001"),
    "url":     _t("T1566", "T1071.001"),
    "hash":    _t("T1204", "T1059"),
    "unknown": _t("T1595"),
}


# ── Enrichment-driven helpers ──────────────────────────────────────────────────

def _vt_labels(vt: dict[str, Any]) -> set[str]:
    """Extract lowercase category/label tokens from a VT result dict."""
    tokens: set[str] = set()
    for field in ("categories", "tags", "popular_threat_names", "last_analysis_results"):
        value = vt.get(field)
        if isinstance(value, dict):
            for v in value.values():
                if isinstance(v, str):
                    tokens.update(v.lower().split())
                elif isinstance(v, dict):
                    for vv in v.values():
                        if isinstance(vv, str):
                            tokens.update(vv.lower().split())
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, str):
                    tokens.update(item.lower().split())
    return tokens


def _enrich_from_virustotal(
    ioc_type: str,
    risk_score: int,
    vt: dict[str, Any],
) -> list[dict[str, str]]:
    """Return additional MITRE techniques inferred from VirusTotal data."""
    extras: list[dict[str, str]] = []
    stats = vt.get("analysis_stats") or {}
    malicious = int(stats.get("malicious", 0))
    labels = _vt_labels(vt)

    _malware_keywords = {"malware", "trojan", "ransomware", "backdoor", "spyware", "worm", "rat"}
    _phishing_keywords = {"phishing", "social-engineering", "social_engineering", "fraud", "spam"}

    if labels & _malware_keywords or malicious >= 3:
        extras.extend(_t("T1204", "T1059"))

    if labels & _phishing_keywords:
        extras.extend(_t("T1566", "T1598"))

    if ioc_type == "hash" and malicious >= 10:
        extras.extend(_t("T1486", "T1027"))

    if ioc_type == "url" and risk_score >= 60:
        extras.extend(_t("T1189"))

    return extras


def _enrich_from_abuseipdb(abuse: dict[str, Any]) -> list[dict[str, str]]:
    """Return additional MITRE techniques inferred from AbuseIPDB data."""
    extras: list[dict[str, str]] = []
    usage_type = str(abuse.get("usage_type") or "").lower()
    confidence = int(abuse.get("abuse_confidence_score", 0))
    reports = int(abuse.get("total_reports", 0))

    if "hosting" in usage_type or "data center" in usage_type or "transit" in usage_type:
        extras.extend(_t("T1583.003", "T1090"))

    if confidence >= 90 and reports >= 50:
        extras.extend(_t("T1071", "T1572"))

    return extras


# ── Public API ─────────────────────────────────────────────────────────────────

def map_finding_to_mitre(finding: dict[str, Any]) -> list[dict[str, str]]:
    """Map a finding to MITRE ATT&CK techniques.

    Starts with base techniques for the IOC type, then enriches dynamically
    using VirusTotal and AbuseIPDB results. Duplicates are removed while
    preserving insertion order (base techniques first).
    """
    ioc_type = str(finding.get("ioc_type", "unknown"))
    risk_score = int(finding.get("risk_score", 0))
    vt = finding.get("virustotal") or {}
    abuse = finding.get("abuseipdb") or {}

    techniques: list[dict[str, str]] = list(_BASE_BY_TYPE.get(ioc_type, _t("T1595")))

    if vt:
        techniques.extend(_enrich_from_virustotal(ioc_type, risk_score, vt))

    if abuse:
        techniques.extend(_enrich_from_abuseipdb(abuse))

    # Deduplicate by technique_id, preserving order
    seen: set[str] = set()
    unique: list[dict[str, str]] = []
    for tech in techniques:
        tid = tech["technique_id"]
        if tid not in seen:
            seen.add(tid)
            unique.append(tech)

    return unique


# ── Runbook ────────────────────────────────────────────────────────────────────

def _technique_ids(finding: dict[str, Any]) -> set[str]:
    return {t["technique_id"] for t in finding.get("mitre_attack") or []}


def build_runbook_steps(finding: dict[str, Any]) -> list[str]:
    """Generate incident response runbook steps.

    Steps are tailored to the specific MITRE techniques identified during
    enrichment, with fallback steps based on IOC type and priority.
    """
    ioc = str(finding.get("ioc", "unknown"))
    ioc_type = str(finding.get("ioc_type", "unknown"))
    priority = str(finding.get("priority", "low"))
    tids = _technique_ids(finding)

    steps: list[str] = [
        f"Validate IOC context in SIEM/EDR and confirm if {ioc_type} '{ioc}' appears in recent logs.",
        "Correlate with endpoint, network, and identity telemetry for affected assets/users.",
        "Check if IOC is present in threat intel blocklists and existing detection rules.",
    ]

    # ── Technique-specific steps ───────────────────────────────────────────────

    if "T1566" in tids or "T1598" in tids:
        steps.append(
            "Search mail gateway and proxy logs for the phishing URL/domain; identify recipients and clickers."
        )
        steps.append(
            "Reset credentials for any user that interacted with the phishing resource."
        )

    if "T1189" in tids:
        steps.append(
            "Identify endpoints that visited the URL and scan for drive-by download payloads or browser exploits."
        )

    if "T1204" in tids or "T1059" in tids:
        steps.append(
            "Search EDR telemetry for process execution events related to this IOC; look for child processes."
        )
        steps.append(
            "Isolate affected endpoints and collect memory dump and disk image for forensic analysis."
        )

    if "T1486" in tids:
        steps.append(
            "Check for encrypted files and shadow copy deletion on affected hosts — activate ransomware playbook."
        )
        steps.append(
            "Disconnect affected systems from the network immediately to prevent lateral encryption spread."
        )

    if "T1027" in tids:
        steps.append(
            "Submit the file/hash to sandbox detonation and static analysis to unpack obfuscated payload."
        )

    if "T1583.003" in tids or "T1090" in tids:
        steps.append(
            "Trace network connections through proxy/VPS infrastructure; identify C2 endpoints."
        )

    if "T1572" in tids or "T1041" in tids:
        steps.append(
            "Capture and inspect network traffic for C2 beaconing or tunneled protocols (DNS, HTTPS, ICMP)."
        )

    # ── IOC-type containment steps (fallback if no specific technique) ─────────

    if ioc_type == "ip":
        steps.append("Block IP in firewall/proxy if malicious activity is confirmed.")
    elif ioc_type in {"domain", "url"}:
        steps.append("Block domain/URL in DNS sinkhole and secure web gateway controls.")
    elif ioc_type == "hash":
        steps.append("Quarantine matching file hash on all endpoints via EDR policy.")

    # ── Escalation for high/critical ──────────────────────────────────────────

    if priority in {"high", "critical"}:
        steps.extend([
            "Open P1 incident with incident commander and notify on-call security team.",
            "Collect volatile evidence (RAM, running processes, network connections) before isolation.",
            "Preserve disk image and all relevant logs for forensic chain of custody.",
        ])

    steps.append("Document timeline, actions, IOCs, and lessons learned in the incident ticket.")
    return steps
