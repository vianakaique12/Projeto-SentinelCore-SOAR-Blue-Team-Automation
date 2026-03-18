#!/usr/bin/env python3
"""MITRE ATT&CK mapping and runbook helpers."""

from __future__ import annotations

from typing import Any


def map_finding_to_mitre(finding: dict[str, Any]) -> list[dict[str, str]]:
    ioc_type = str(finding.get("ioc_type", "unknown"))
    priority = str(finding.get("priority", "low"))

    mapping: list[dict[str, str]] = []
    if ioc_type in {"domain", "url"}:
        mapping.append({"technique_id": "T1566", "name": "Phishing"})
        mapping.append({"technique_id": "T1071.001", "name": "Application Layer Protocol: Web"})
    elif ioc_type == "ip":
        mapping.append({"technique_id": "T1071", "name": "Application Layer Protocol"})
        mapping.append({"technique_id": "T1041", "name": "Exfiltration Over C2 Channel"})
    elif ioc_type == "hash":
        mapping.append({"technique_id": "T1204", "name": "User Execution"})
        mapping.append({"technique_id": "T1059", "name": "Command and Scripting Interpreter"})
    else:
        mapping.append({"technique_id": "T1595", "name": "Active Scanning"})

    if priority in {"high", "critical"}:
        mapping.append({"technique_id": "T1486", "name": "Data Encrypted for Impact"})
    return mapping


def build_runbook_steps(finding: dict[str, Any]) -> list[str]:
    ioc = str(finding.get("ioc", "unknown"))
    ioc_type = str(finding.get("ioc_type", "unknown"))
    priority = str(finding.get("priority", "low"))

    steps = [
        f"Validate IOC context in SIEM/EDR and confirm if {ioc_type} '{ioc}' appears in recent logs.",
        "Correlate with endpoint, network, and identity telemetry for affected assets/users.",
        "Check if IOC is present in threat intel blocklists and existing detection rules.",
    ]

    if ioc_type == "ip":
        steps.append("Block IP in firewall/proxy if malicious activity is confirmed.")
    elif ioc_type in {"domain", "url"}:
        steps.append("Block domain/URL in DNS and secure web gateway controls.")
    elif ioc_type == "hash":
        steps.append("Quarantine matching file hash on endpoints and trigger malware triage.")

    if priority in {"high", "critical"}:
        steps.extend(
            [
                "Open incident with incident commander and notify on-call team.",
                "Collect volatile evidence and preserve artifacts for forensics.",
            ]
        )

    steps.append("Document timeline, actions, and lessons learned in incident ticket.")
    return steps

