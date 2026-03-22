#!/usr/bin/env python3
"""Ticketing layer for SentinelCore SOAR.

Handles automatic ticket creation when IOC risk scores exceed the configured
threshold. Supported backends: file (JSONL), webhook (generic HTTP), Jira.
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mini_soar_enrichment import http_json_request, utc_now_iso

if TYPE_CHECKING:
    from mini_soar_core import RuntimeConfig


@dataclass
class TicketResult:
    backend: str
    ok: bool
    reference: str | None = None
    error: str | None = None


# ── Text / payload builders ────────────────────────────────────────────────────

def finding_to_text(finding: dict[str, Any]) -> str:
    """Render a finding dict as human-readable plain text for ticket descriptions."""
    lines = [
        f"IOC: {finding['ioc']}",
        f"Type: {finding['ioc_type']}",
        f"Risk score: {finding['risk_score']}",
        f"Priority: {finding['priority']}",
        f"Generated at: {finding['generated_at']}",
        "",
        "Reasons:",
    ]
    if finding["reasons"]:
        lines.extend([f"- {reason}" for reason in finding["reasons"]])
    else:
        lines.append("- No strong indicators found.")

    lines.extend([
        "",
        "VirusTotal:",
        json.dumps(finding.get("virustotal"), indent=2, ensure_ascii=False),
        "",
        "AbuseIPDB:",
        json.dumps(finding.get("abuseipdb"), indent=2, ensure_ascii=False),
        "",
        "Automation source: mini_soar",
    ])
    return "\n".join(lines)


def build_ticket_payload(finding: dict[str, Any]) -> dict[str, Any]:
    """Build a normalized ticket payload dict from a finding."""
    return {
        "summary": (
            f"[MiniSOAR][{finding['priority'].upper()}] IOC {finding['ioc']} "
            f"({finding['ioc_type']}) score={finding['risk_score']}"
        ),
        "description": finding_to_text(finding),
        "labels": ["mini-soar", "soc", finding["priority"], finding["ioc_type"]],
    }


# ── Backend implementations ────────────────────────────────────────────────────

def create_ticket_file(ticket_path: str, payload: dict[str, Any], finding: dict[str, Any]) -> TicketResult:
    """Append a ticket record to a JSONL file."""
    record = {
        "created_at": utc_now_iso(),
        "summary": payload["summary"],
        "description": payload["description"],
        "labels": payload["labels"],
        "ioc": finding["ioc"],
        "risk_score": finding["risk_score"],
        "priority": finding["priority"],
    }
    with open(ticket_path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return TicketResult(backend="file", ok=True, reference=ticket_path)


def create_ticket_webhook(
    webhook_url: str,
    webhook_token: str | None,
    payload: dict[str, Any],
    finding: dict[str, Any],
    timeout: int,
    max_retries: int = 2,
    retry_backoff_seconds: float = 0.5,
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> TicketResult:
    """POST a ticket payload to a generic webhook endpoint."""
    body = {
        "source": "mini-soar",
        "event": "ioc_alert",
        "summary": payload["summary"],
        "description": payload["description"],
        "labels": payload["labels"],
        "ioc": finding["ioc"],
        "ioc_type": finding["ioc_type"],
        "risk_score": finding["risk_score"],
        "priority": finding["priority"],
    }
    headers: dict[str, str] = {"Accept": "application/json"}
    if webhook_token:
        headers["Authorization"] = f"Bearer {webhook_token}"

    status, data, error = http_json_request(
        url=webhook_url, method="POST", headers=headers, payload=body, timeout=timeout,
        connector_name="ticket_webhook", max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds, correlation_id=correlation_id, logger=logger,
    )
    if error:
        return TicketResult(backend="webhook", ok=False, error=error)

    reference = None
    if isinstance(data, dict):
        reference = data.get("id") or data.get("ticket") or data.get("key")
    return TicketResult(backend="webhook", ok=True, reference=str(reference or status))


def create_ticket_jira(
    base_url: str,
    email: str,
    api_token: str,
    project_key: str,
    issue_type: str,
    payload: dict[str, Any],
    timeout: int,
    max_retries: int = 2,
    retry_backoff_seconds: float = 0.5,
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> TicketResult:
    """Create a Jira issue via the REST API v2."""
    jira_endpoint = f"{base_url.rstrip('/')}/rest/api/2/issue"
    auth = base64.b64encode(f"{email}:{api_token}".encode("utf-8")).decode("utf-8")
    headers = {"Authorization": f"Basic {auth}", "Accept": "application/json"}
    body = {
        "fields": {
            "project": {"key": project_key},
            "summary": payload["summary"][:255],
            "description": payload["description"],
            "issuetype": {"name": issue_type},
            "labels": payload["labels"],
        }
    }

    status, data, error = http_json_request(
        url=jira_endpoint, method="POST", headers=headers, payload=body, timeout=timeout,
        connector_name="jira", max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds, correlation_id=correlation_id, logger=logger,
    )
    if error:
        return TicketResult(backend="jira", ok=False, error=error)

    reference = None
    if isinstance(data, dict):
        reference = data.get("key") or data.get("id")
    return TicketResult(backend="jira", ok=status in {200, 201}, reference=str(reference or status))


# ── Orchestrator ───────────────────────────────────────────────────────────────

def maybe_open_ticket(
    config: RuntimeConfig,
    finding: dict[str, Any],
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> TicketResult | None:
    """Open a ticket for a finding if the configured backend and threshold allow it."""
    if config.ticket_backend == "none":
        return None

    payload = build_ticket_payload(finding)

    if config.ticket_backend == "file":
        return create_ticket_file(config.ticket_file, payload, finding)

    if config.ticket_backend == "webhook":
        if not config.webhook_url:
            return TicketResult(backend="webhook", ok=False, error="Missing webhook URL.")
        return create_ticket_webhook(
            webhook_url=config.webhook_url,
            webhook_token=config.webhook_token,
            payload=payload, finding=finding,
            timeout=config.integration_timeout or config.timeout,
            max_retries=config.max_retries,
            retry_backoff_seconds=config.retry_backoff_seconds,
            correlation_id=correlation_id, logger=logger,
        )

    if config.ticket_backend == "jira":
        missing = [
            key for key, value in {
                "JIRA_BASE_URL": config.jira_base_url,
                "JIRA_EMAIL": config.jira_email,
                "JIRA_API_TOKEN": config.jira_api_token,
                "JIRA_PROJECT_KEY": config.jira_project_key,
            }.items() if not value
        ]
        if missing:
            return TicketResult(backend="jira", ok=False, error=f"Missing Jira config: {', '.join(missing)}")
        return create_ticket_jira(
            base_url=config.jira_base_url or "",
            email=config.jira_email or "",
            api_token=config.jira_api_token or "",
            project_key=config.jira_project_key or "",
            issue_type=config.jira_issue_type or "Task",
            payload=payload,
            timeout=config.integration_timeout or config.timeout,
            max_retries=config.max_retries,
            retry_backoff_seconds=config.retry_backoff_seconds,
            correlation_id=correlation_id, logger=logger,
        )

    return TicketResult(backend=config.ticket_backend, ok=False, error="Unsupported backend")
