"""Tests for dynamic MITRE ATT&CK mapping and runbook generation."""

from __future__ import annotations

from mini_soar_mitre import build_runbook_steps, map_finding_to_mitre


# ── Helpers ────────────────────────────────────────────────────────────────────

def _finding(
    ioc_type: str = "ip",
    ioc: str = "1.2.3.4",
    priority: str = "low",
    risk_score: int = 0,
    virustotal: dict | None = None,
    abuseipdb: dict | None = None,
    mitre_attack: list | None = None,
) -> dict:
    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "priority": priority,
        "risk_score": risk_score,
        "virustotal": virustotal,
        "abuseipdb": abuseipdb,
        "mitre_attack": mitre_attack or [],
    }


def _tids(finding: dict) -> set[str]:
    return {t["technique_id"] for t in map_finding_to_mitre(finding)}


# ── Base mapping tests ─────────────────────────────────────────────────────────

def test_base_ip_techniques():
    tids = _tids(_finding(ioc_type="ip"))
    assert "T1071" in tids
    assert "T1041" in tids


def test_base_domain_techniques():
    tids = _tids(_finding(ioc_type="domain", ioc="evil.com"))
    assert "T1566" in tids
    assert "T1071.001" in tids


def test_base_url_techniques():
    tids = _tids(_finding(ioc_type="url", ioc="http://evil.com/payload"))
    assert "T1566" in tids
    assert "T1071.001" in tids


def test_base_hash_techniques():
    tids = _tids(_finding(ioc_type="hash", ioc="aabbccdd" * 4))
    assert "T1204" in tids
    assert "T1059" in tids


def test_base_unknown_ioc_type():
    tids = _tids(_finding(ioc_type="unknown"))
    assert "T1595" in tids


# ── VT-driven enrichment tests ─────────────────────────────────────────────────

def test_vt_malware_label_adds_execution_techniques():
    vt = {"analysis_stats": {"malicious": 5}, "categories": {"engine1": "malware"}}
    tids = _tids(_finding(ioc_type="ip", virustotal=vt))
    assert "T1204" in tids
    assert "T1059" in tids


def test_vt_trojan_label_adds_execution_techniques():
    vt = {"analysis_stats": {"malicious": 4}, "categories": {"engine1": "trojan"}}
    tids = _tids(_finding(ioc_type="domain", ioc="evil.com", virustotal=vt))
    assert "T1204" in tids
    assert "T1059" in tids


def test_vt_phishing_label_adds_phishing_techniques():
    vt = {"analysis_stats": {"malicious": 2}, "categories": {"engine1": "phishing"}}
    tids = _tids(_finding(ioc_type="url", ioc="http://phish.com", virustotal=vt))
    assert "T1566" in tids
    assert "T1598" in tids


def test_vt_fraud_label_adds_phishing_techniques():
    vt = {"analysis_stats": {"malicious": 1}, "categories": {"engine1": "fraud"}}
    tids = _tids(_finding(ioc_type="domain", ioc="fraud.com", virustotal=vt))
    assert "T1566" in tids
    assert "T1598" in tids


def test_vt_hash_high_malicious_adds_ransomware_techniques():
    vt = {"analysis_stats": {"malicious": 15, "suspicious": 2}}
    tids = _tids(_finding(ioc_type="hash", ioc="a" * 32, virustotal=vt))
    assert "T1486" in tids
    assert "T1027" in tids


def test_vt_hash_low_malicious_does_not_add_ransomware():
    vt = {"analysis_stats": {"malicious": 5, "suspicious": 1}}
    tids = _tids(_finding(ioc_type="hash", ioc="b" * 32, virustotal=vt))
    assert "T1486" not in tids


def test_vt_url_high_score_adds_driveby():
    vt = {"analysis_stats": {"malicious": 6}}
    tids = _tids(_finding(ioc_type="url", ioc="http://evil.com", risk_score=75, virustotal=vt))
    assert "T1189" in tids


def test_vt_url_low_score_no_driveby():
    vt = {"analysis_stats": {"malicious": 1}}
    tids = _tids(_finding(ioc_type="url", ioc="http://maybe.com", risk_score=30, virustotal=vt))
    assert "T1189" not in tids


# ── AbuseIPDB-driven enrichment tests ─────────────────────────────────────────

def test_abuse_hosting_usage_adds_vps_proxy():
    abuse = {"usage_type": "Data Center/Web Hosting/Transit", "abuse_confidence_score": 20, "total_reports": 3}
    tids = _tids(_finding(ioc_type="ip", abuseipdb=abuse))
    assert "T1583.003" in tids
    assert "T1090" in tids


def test_abuse_isp_usage_does_not_add_vps():
    abuse = {"usage_type": "Fixed Line ISP", "abuse_confidence_score": 10, "total_reports": 1}
    tids = _tids(_finding(ioc_type="ip", abuseipdb=abuse))
    assert "T1583.003" not in tids
    assert "T1090" not in tids


def test_abuse_high_confidence_and_reports_adds_c2_tunneling():
    abuse = {"usage_type": "ISP", "abuse_confidence_score": 95, "total_reports": 80}
    tids = _tids(_finding(ioc_type="ip", abuseipdb=abuse))
    assert "T1071" in tids
    assert "T1572" in tids


def test_abuse_high_confidence_but_low_reports_no_tunneling():
    abuse = {"usage_type": "ISP", "abuse_confidence_score": 95, "total_reports": 10}
    tids = _tids(_finding(ioc_type="ip", abuseipdb=abuse))
    assert "T1572" not in tids


def test_abuse_low_confidence_no_tunneling():
    abuse = {"usage_type": "ISP", "abuse_confidence_score": 50, "total_reports": 100}
    tids = _tids(_finding(ioc_type="ip", abuseipdb=abuse))
    assert "T1572" not in tids


# ── Deduplication tests ────────────────────────────────────────────────────────

def test_no_duplicate_techniques():
    # Both base (hash → T1204) and VT malware trigger T1204 — should appear once
    vt = {"analysis_stats": {"malicious": 5}, "categories": {"e": "malware"}}
    result = map_finding_to_mitre(_finding(ioc_type="hash", ioc="a" * 32, virustotal=vt))
    tids = [t["technique_id"] for t in result]
    assert len(tids) == len(set(tids)), f"Duplicate technique IDs found: {tids}"


def test_combined_vt_and_abuse_deduplication():
    # Both VT and abuse can trigger T1071 — should appear once
    vt = {"analysis_stats": {"malicious": 3}, "categories": {}}
    abuse = {"usage_type": "Data Center", "abuse_confidence_score": 95, "total_reports": 60}
    result = map_finding_to_mitre(_finding(ioc_type="ip", virustotal=vt, abuseipdb=abuse))
    tids = [t["technique_id"] for t in result]
    assert len(tids) == len(set(tids))


# ── Runbook tests ──────────────────────────────────────────────────────────────

def test_runbook_base_steps_always_present():
    finding = _finding(ioc_type="ip")
    steps = build_runbook_steps(finding)
    assert any("SIEM" in s or "logs" in s for s in steps)
    assert any("blocklist" in s or "detection rules" in s for s in steps)
    assert any("timeline" in s or "incident ticket" in s for s in steps)


def test_runbook_phishing_steps():
    finding = _finding(ioc_type="url", ioc="http://phish.com", mitre_attack=[
        {"technique_id": "T1566", "name": "Phishing"},
    ])
    steps = build_runbook_steps(finding)
    assert any("phishing" in s.lower() or "mail gateway" in s.lower() for s in steps)
    assert any("credential" in s.lower() or "reset" in s.lower() for s in steps)


def test_runbook_driveby_steps():
    finding = _finding(ioc_type="url", ioc="http://evil.com", mitre_attack=[
        {"technique_id": "T1189", "name": "Drive-by Compromise"},
    ])
    steps = build_runbook_steps(finding)
    assert any("drive-by" in s.lower() or "browser" in s.lower() for s in steps)


def test_runbook_malware_execution_steps():
    finding = _finding(ioc_type="hash", ioc="a" * 32, mitre_attack=[
        {"technique_id": "T1204", "name": "User Execution"},
        {"technique_id": "T1059", "name": "Command and Scripting Interpreter"},
    ])
    steps = build_runbook_steps(finding)
    assert any("EDR" in s or "process" in s.lower() for s in steps)
    assert any("isolat" in s.lower() or "forensic" in s.lower() for s in steps)


def test_runbook_ransomware_steps():
    finding = _finding(ioc_type="hash", ioc="b" * 32, priority="critical", mitre_attack=[
        {"technique_id": "T1486", "name": "Data Encrypted for Impact"},
    ])
    steps = build_runbook_steps(finding)
    assert any("ransomware" in s.lower() or "encrypt" in s.lower() for s in steps)
    assert any("disconnect" in s.lower() or "network" in s.lower() for s in steps)


def test_runbook_obfuscation_steps():
    finding = _finding(ioc_type="hash", ioc="c" * 32, mitre_attack=[
        {"technique_id": "T1027", "name": "Obfuscated Files or Information"},
    ])
    steps = build_runbook_steps(finding)
    assert any("sandbox" in s.lower() or "unpack" in s.lower() or "obfuscat" in s.lower() for s in steps)


def test_runbook_c2_tunneling_steps():
    finding = _finding(ioc_type="ip", mitre_attack=[
        {"technique_id": "T1572", "name": "Protocol Tunneling"},
        {"technique_id": "T1041", "name": "Exfiltration Over C2 Channel"},
    ])
    steps = build_runbook_steps(finding)
    assert any("C2" in s or "beacon" in s.lower() or "tunnel" in s.lower() for s in steps)


def test_runbook_escalation_on_critical():
    finding = _finding(ioc_type="ip", priority="critical")
    steps = build_runbook_steps(finding)
    assert any("P1" in s or "incident commander" in s.lower() or "on-call" in s.lower() for s in steps)
    assert any("forensic" in s.lower() or "evidence" in s.lower() for s in steps)


def test_runbook_no_escalation_on_low():
    finding = _finding(ioc_type="ip", priority="low")
    steps = build_runbook_steps(finding)
    assert not any("incident commander" in s.lower() for s in steps)


def test_runbook_ip_containment():
    finding = _finding(ioc_type="ip")
    steps = build_runbook_steps(finding)
    assert any("firewall" in s.lower() or "block ip" in s.lower() for s in steps)


def test_runbook_hash_quarantine():
    finding = _finding(ioc_type="hash", ioc="d" * 32)
    steps = build_runbook_steps(finding)
    assert any("quarantine" in s.lower() or "hash" in s.lower() for s in steps)
