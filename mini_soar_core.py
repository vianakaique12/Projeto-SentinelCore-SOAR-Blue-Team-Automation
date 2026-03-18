#!/usr/bin/env python3
"""Core engine for Mini SOAR IOC enrichment and response automation."""

from __future__ import annotations

import base64
import csv
import datetime as dt
import hashlib
import hmac
import importlib
import ipaddress
import json
import logging
import os
import random
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

from mini_soar_mitre import build_runbook_steps, map_finding_to_mitre
from mini_soar_observability import (
    CONNECTOR_LATENCY_SECONDS,
    CONNECTOR_REQUESTS_TOTAL,
    IOCS_PROCESSED_TOTAL,
    PIPELINE_DURATION_SECONDS,
    PIPELINE_RUNS_TOTAL,
    get_logger,
    log_event,
)
from mini_soar_storage import BaseStore, NullStore, create_store


DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

INTEGRATION_CHOICES = {"thehive", "splunk", "sentinel"}
TICKET_CHOICES = {"none", "file", "webhook", "jira"}


@dataclass
class TicketResult:
    backend: str
    ok: bool
    reference: str | None = None
    error: str | None = None


@dataclass
class IntegrationResult:
    target: str
    ok: bool
    reference: str | None = None
    error: str | None = None


@dataclass
class RuntimeConfig:
    vt_api_key: str | None = None
    abuse_api_key: str | None = None
    abuse_max_age: int = 90
    timeout: int = 20
    vt_timeout: int | None = None
    abuse_timeout: int | None = None
    integration_timeout: int | None = None
    sleep: float = 0.0
    max_retries: int = 2
    retry_backoff_seconds: float = 0.5

    ticket_backend: str = "file"
    ticket_file: str = "tickets.jsonl"
    ticket_threshold: int = 70
    webhook_url: str | None = None
    webhook_token: str | None = None
    jira_base_url: str | None = None
    jira_email: str | None = None
    jira_api_token: str | None = None
    jira_project_key: str | None = None
    jira_issue_type: str = "Task"

    integration_targets: tuple[str, ...] = ()
    integration_threshold: int = 60
    thehive_url: str | None = None
    thehive_api_key: str | None = None
    thehive_alert_type: str = "external"
    thehive_tlp: int = 2
    thehive_pap: int = 2

    splunk_hec_url: str | None = None
    splunk_hec_token: str | None = None
    splunk_sourcetype: str = "mini_soar:ioc"

    sentinel_workspace_id: str | None = None
    sentinel_shared_key: str | None = None
    sentinel_log_type: str = "MiniSoarIOC"
    sentinel_endpoint: str | None = None

    enable_idempotency: bool = True
    idempotency_window_seconds: int = 3600
    database_url: str = "sqlite:///mini_soar.db"
    persist_findings: bool = True

    log_level: str = "INFO"
    json_logs: bool = True


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def utc_now_rfc1123() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


def build_config_from_env() -> RuntimeConfig:
    targets_raw = os.getenv("MINI_SOAR_INTEGRATION_TARGETS", "")
    parsed_targets = tuple(
        sorted(
            {
                item.strip().lower()
                for item in targets_raw.split(",")
                if item.strip().lower() in INTEGRATION_CHOICES
            }
        )
    )

    return RuntimeConfig(
        vt_api_key=os.getenv("VT_API_KEY"),
        abuse_api_key=os.getenv("ABUSEIPDB_API_KEY"),
        abuse_max_age=int(os.getenv("ABUSE_MAX_AGE", "90")),
        timeout=int(os.getenv("MINI_SOAR_TIMEOUT", "20")),
        vt_timeout=int(os.getenv("MINI_SOAR_VT_TIMEOUT", "20")),
        abuse_timeout=int(os.getenv("MINI_SOAR_ABUSE_TIMEOUT", "20")),
        integration_timeout=int(os.getenv("MINI_SOAR_INTEGRATION_TIMEOUT", "20")),
        sleep=float(os.getenv("MINI_SOAR_SLEEP", "0")),
        max_retries=int(os.getenv("MINI_SOAR_MAX_RETRIES", "2")),
        retry_backoff_seconds=float(os.getenv("MINI_SOAR_RETRY_BACKOFF_SECONDS", "0.5")),
        ticket_backend=os.getenv("MINI_SOAR_TICKET_BACKEND", "file"),
        ticket_file=os.getenv("MINI_SOAR_TICKET_FILE", "tickets.jsonl"),
        ticket_threshold=int(os.getenv("MINI_SOAR_TICKET_THRESHOLD", "70")),
        webhook_url=os.getenv("TICKET_WEBHOOK_URL"),
        webhook_token=os.getenv("TICKET_WEBHOOK_TOKEN"),
        jira_base_url=os.getenv("JIRA_BASE_URL"),
        jira_email=os.getenv("JIRA_EMAIL"),
        jira_api_token=os.getenv("JIRA_API_TOKEN"),
        jira_project_key=os.getenv("JIRA_PROJECT_KEY"),
        jira_issue_type=os.getenv("JIRA_ISSUE_TYPE", "Task"),
        integration_targets=parsed_targets,
        integration_threshold=int(os.getenv("MINI_SOAR_INTEGRATION_THRESHOLD", "60")),
        thehive_url=os.getenv("THEHIVE_URL"),
        thehive_api_key=os.getenv("THEHIVE_API_KEY"),
        thehive_alert_type=os.getenv("THEHIVE_ALERT_TYPE", "external"),
        thehive_tlp=int(os.getenv("THEHIVE_TLP", "2")),
        thehive_pap=int(os.getenv("THEHIVE_PAP", "2")),
        splunk_hec_url=os.getenv("SPLUNK_HEC_URL"),
        splunk_hec_token=os.getenv("SPLUNK_HEC_TOKEN"),
        splunk_sourcetype=os.getenv("SPLUNK_SOURCETYPE", "mini_soar:ioc"),
        sentinel_workspace_id=os.getenv("SENTINEL_WORKSPACE_ID"),
        sentinel_shared_key=os.getenv("SENTINEL_SHARED_KEY"),
        sentinel_log_type=os.getenv("SENTINEL_LOG_TYPE", "MiniSoarIOC"),
        sentinel_endpoint=os.getenv("SENTINEL_ENDPOINT"),
        enable_idempotency=os.getenv("MINI_SOAR_ENABLE_IDEMPOTENCY", "true").lower() == "true",
        idempotency_window_seconds=int(os.getenv("MINI_SOAR_IDEMPOTENCY_WINDOW_SECONDS", "3600")),
        database_url=os.getenv("MINI_SOAR_DATABASE_URL", "sqlite:///mini_soar.db"),
        persist_findings=os.getenv("MINI_SOAR_PERSIST_FINDINGS", "true").lower() == "true",
        log_level=os.getenv("MINI_SOAR_LOG_LEVEL", "INFO"),
        json_logs=os.getenv("MINI_SOAR_JSON_LOGS", "true").lower() == "true",
    )


def read_iocs(input_file: str | None, inline_iocs: list[str]) -> list[str]:
    iocs: list[str] = []

    for value in inline_iocs:
        if value.strip():
            iocs.append(value.strip())

    if input_file:
        with open(input_file, "r", encoding="utf-8") as handle:
            for line in handle:
                cleaned = line.strip()
                if not cleaned or cleaned.startswith("#"):
                    continue
                iocs.append(cleaned)

    deduped: list[str] = []
    seen: set[str] = set()
    for ioc in iocs:
        key = ioc.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(ioc)

    return deduped


def detect_ioc_type(value: str) -> str:
    value = value.strip()

    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        pass

    parsed = urllib.parse.urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return "url"

    if re.fullmatch(r"[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}", value):
        return "hash"

    if DOMAIN_REGEX.fullmatch(value):
        return "domain"

    return "unknown"


def vt_url_id(raw_url: str) -> str:
    return base64.urlsafe_b64encode(raw_url.encode("utf-8")).decode("utf-8").rstrip("=")


def _parse_retry_after_seconds(headers: Any) -> float | None:
    if not headers:
        return None
    value = headers.get("Retry-After")
    if not value:
        return None
    try:
        return max(float(value), 0.0)
    except ValueError:
        return None


def _compute_backoff_sleep(attempt: int, base: float, retry_after: float | None = None) -> float:
    if retry_after is not None:
        return retry_after
    jitter = random.uniform(0.0, 0.2)
    return (base * (2**attempt)) + jitter


def http_raw_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int = 20,
    connector_name: str = "generic",
    max_retries: int = 2,
    retry_backoff_seconds: float = 0.5,
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> tuple[int, bytes | None, str | None]:
    retries = max(0, max_retries)

    for attempt in range(retries + 1):
        started = time.perf_counter()
        request = urllib.request.Request(url=url, method=method, headers=headers or {}, data=body)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                raw = response.read()
                elapsed = time.perf_counter() - started
                CONNECTOR_LATENCY_SECONDS.labels(connector=connector_name).observe(elapsed)
                CONNECTOR_REQUESTS_TOTAL.labels(connector=connector_name, status=str(response.status)).inc()
                if logger:
                    log_event(
                        logger,
                        logging.INFO,
                        "connector_request",
                        correlation_id=correlation_id,
                        connector=connector_name,
                        status_code=response.status,
                        duration_ms=round(elapsed * 1000, 2),
                    )
                return response.status, raw, None
        except urllib.error.HTTPError as exc:
            elapsed = time.perf_counter() - started
            status_code = exc.code
            raw_error = exc.read()
            message = raw_error.decode("utf-8", errors="replace")
            CONNECTOR_LATENCY_SECONDS.labels(connector=connector_name).observe(elapsed)
            CONNECTOR_REQUESTS_TOTAL.labels(connector=connector_name, status=str(status_code)).inc()

            retryable = status_code in {429, 500, 502, 503, 504}
            if retryable and attempt < retries:
                retry_after = _parse_retry_after_seconds(getattr(exc, "headers", None))
                sleep_seconds = _compute_backoff_sleep(attempt, retry_backoff_seconds, retry_after=retry_after)
                if logger:
                    log_event(
                        logger,
                        logging.WARNING,
                        "connector_retry",
                        correlation_id=correlation_id,
                        connector=connector_name,
                        status_code=status_code,
                        duration_ms=round(elapsed * 1000, 2),
                        error=f"retry in {round(sleep_seconds, 3)}s",
                    )
                time.sleep(sleep_seconds)
                continue

            if logger:
                log_event(
                    logger,
                    logging.ERROR,
                    "connector_error",
                    correlation_id=correlation_id,
                    connector=connector_name,
                    status_code=status_code,
                    duration_ms=round(elapsed * 1000, 2),
                    error=message[:500],
                )
            return status_code, None, f"HTTP {status_code}: {message}"
        except urllib.error.URLError as exc:
            elapsed = time.perf_counter() - started
            CONNECTOR_LATENCY_SECONDS.labels(connector=connector_name).observe(elapsed)
            CONNECTOR_REQUESTS_TOTAL.labels(connector=connector_name, status="network_error").inc()

            retryable = attempt < retries
            if retryable:
                sleep_seconds = _compute_backoff_sleep(attempt, retry_backoff_seconds)
                if logger:
                    log_event(
                        logger,
                        logging.WARNING,
                        "connector_retry",
                        correlation_id=correlation_id,
                        connector=connector_name,
                        status_code=0,
                        duration_ms=round(elapsed * 1000, 2),
                        error=f"{exc.reason}; retry in {round(sleep_seconds, 3)}s",
                    )
                time.sleep(sleep_seconds)
                continue

            if logger:
                log_event(
                    logger,
                    logging.ERROR,
                    "connector_error",
                    correlation_id=correlation_id,
                    connector=connector_name,
                    status_code=0,
                    duration_ms=round(elapsed * 1000, 2),
                    error=str(exc.reason),
                )
            return 0, None, f"Network error: {exc.reason}"

    return 0, None, "Request failed after retries."


def http_json_request(
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    payload: dict[str, Any] | list[Any] | None = None,
    timeout: int = 20,
    connector_name: str = "generic",
    max_retries: int = 2,
    retry_backoff_seconds: float = 0.5,
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> tuple[int, dict[str, Any] | list[Any] | None, str | None]:
    body: bytes | None = None
    req_headers = (headers or {}).copy()

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    status, raw, error = http_raw_request(
        url=url,
        method=method,
        headers=req_headers,
        body=body,
        timeout=timeout,
        connector_name=connector_name,
        max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds,
        correlation_id=correlation_id,
        logger=logger,
    )
    if error:
        return status, None, error

    if raw is None:
        return status, None, None

    text = raw.decode("utf-8", errors="replace")
    if not text.strip():
        return status, {}, None

    try:
        return status, json.loads(text), None
    except json.JSONDecodeError as exc:
        return status, None, f"Invalid JSON response: {exc}"

def virustotal_lookup(
    ioc: str,
    ioc_type: str,
    api_key: str,
    timeout: int,
    max_retries: int = 2,
    retry_backoff_seconds: float = 0.5,
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    endpoint_map = {
        "ip": f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ioc)}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(ioc)}",
        "hash": f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(ioc)}",
        "url": f"https://www.virustotal.com/api/v3/urls/{vt_url_id(ioc)}",
    }
    if ioc_type not in endpoint_map:
        return None, f"VirusTotal does not support IOC type '{ioc_type}'."

    status, data, error = http_json_request(
        url=endpoint_map[ioc_type],
        headers={"x-apikey": api_key, "Accept": "application/json"},
        timeout=timeout,
        connector_name="virustotal",
        max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds,
        correlation_id=correlation_id,
        logger=logger,
    )
    if error:
        return None, error

    attributes = data.get("data", {}).get("attributes", {}) if isinstance(data, dict) else {}
    analysis_stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation")
    last_analysis_date = attributes.get("last_analysis_date")

    return {
        "status": status,
        "analysis_stats": analysis_stats,
        "reputation": reputation,
        "last_analysis_date": last_analysis_date,
        "permalink": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(ioc)}",
    }, None


def abuseipdb_lookup(
    ip: str,
    api_key: str,
    max_age_days: int,
    timeout: int,
    max_retries: int = 2,
    retry_backoff_seconds: float = 0.5,
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> tuple[dict[str, Any] | None, str | None]:
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    status, data, error = http_json_request(
        url=url,
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=timeout,
        connector_name="abuseipdb",
        max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds,
        correlation_id=correlation_id,
        logger=logger,
    )
    if error:
        return None, error

    details = data.get("data", {}) if isinstance(data, dict) else {}
    return {
        "status": status,
        "abuse_confidence_score": details.get("abuseConfidenceScore", 0),
        "total_reports": details.get("totalReports", 0),
        "country_code": details.get("countryCode"),
        "usage_type": details.get("usageType"),
        "isp": details.get("isp"),
        "domain": details.get("domain"),
    }, None


def score_finding(vt: dict[str, Any] | None, abuse: dict[str, Any] | None) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []

    if vt:
        stats = vt.get("analysis_stats", {})
        malicious = int(stats.get("malicious", 0))
        suspicious = int(stats.get("suspicious", 0))
        reputation = vt.get("reputation")

        if malicious >= 10:
            score += 70
            reasons.append(f"VirusTotal malicious engines: {malicious} (high)")
        elif malicious >= 3:
            score += 50
            reasons.append(f"VirusTotal malicious engines: {malicious} (medium)")
        elif malicious >= 1:
            score += 30
            reasons.append(f"VirusTotal malicious engines: {malicious} (low)")

        if suspicious >= 5:
            score += 15
            reasons.append(f"VirusTotal suspicious engines: {suspicious}")
        elif suspicious >= 1:
            score += 5
            reasons.append(f"VirusTotal suspicious engines: {suspicious}")

        if isinstance(reputation, int) and reputation < 0:
            rep_points = min(abs(reputation), 20)
            score += rep_points
            reasons.append(f"Negative reputation in VirusTotal: {reputation}")

    if abuse:
        abuse_conf = int(abuse.get("abuse_confidence_score", 0))
        total_reports = int(abuse.get("total_reports", 0))

        if abuse_conf >= 90:
            score += 35
            reasons.append(f"AbuseIPDB confidence score: {abuse_conf} (very high)")
        elif abuse_conf >= 60:
            score += 25
            reasons.append(f"AbuseIPDB confidence score: {abuse_conf} (high)")
        elif abuse_conf >= 30:
            score += 10
            reasons.append(f"AbuseIPDB confidence score: {abuse_conf} (medium)")

        if total_reports >= 50:
            score += 15
            reasons.append(f"AbuseIPDB reports: {total_reports}")
        elif total_reports >= 10:
            score += 7
            reasons.append(f"AbuseIPDB reports: {total_reports}")

    return min(score, 100), reasons


def priority_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def finding_to_text(finding: dict[str, Any]) -> str:
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

    lines.extend(
        [
            "",
            "VirusTotal:",
            json.dumps(finding.get("virustotal"), indent=2, ensure_ascii=False),
            "",
            "AbuseIPDB:",
            json.dumps(finding.get("abuseipdb"), indent=2, ensure_ascii=False),
            "",
            "Automation source: mini_soar",
        ]
    )
    return "\n".join(lines)


def build_ticket_payload(finding: dict[str, Any]) -> dict[str, Any]:
    return {
        "summary": (
            f"[MiniSOAR][{finding['priority'].upper()}] IOC {finding['ioc']} "
            f"({finding['ioc_type']}) score={finding['risk_score']}"
        ),
        "description": finding_to_text(finding),
        "labels": ["mini-soar", "soc", finding["priority"], finding["ioc_type"]],
    }


def create_ticket_file(ticket_path: str, payload: dict[str, Any], finding: dict[str, Any]) -> TicketResult:
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

    headers = {"Accept": "application/json"}
    if webhook_token:
        headers["Authorization"] = f"Bearer {webhook_token}"

    status, data, error = http_json_request(
        url=webhook_url,
        method="POST",
        headers=headers,
        payload=body,
        timeout=timeout,
        connector_name="ticket_webhook",
        max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds,
        correlation_id=correlation_id,
        logger=logger,
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
        url=jira_endpoint,
        method="POST",
        headers=headers,
        payload=body,
        timeout=timeout,
        connector_name="jira",
        max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds,
        correlation_id=correlation_id,
        logger=logger,
    )
    if error:
        return TicketResult(backend="jira", ok=False, error=error)

    reference = None
    if isinstance(data, dict):
        reference = data.get("key") or data.get("id")
    return TicketResult(backend="jira", ok=status in {200, 201}, reference=str(reference or status))


def maybe_open_ticket(
    config: RuntimeConfig,
    finding: dict[str, Any],
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> TicketResult | None:
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
            payload=payload,
            finding=finding,
            timeout=config.integration_timeout or config.timeout,
            max_retries=config.max_retries,
            retry_backoff_seconds=config.retry_backoff_seconds,
            correlation_id=correlation_id,
            logger=logger,
        )

    if config.ticket_backend == "jira":
        missing = [
            key
            for key, value in {
                "JIRA_BASE_URL": config.jira_base_url,
                "JIRA_EMAIL": config.jira_email,
                "JIRA_API_TOKEN": config.jira_api_token,
                "JIRA_PROJECT_KEY": config.jira_project_key,
            }.items()
            if not value
        ]
        if missing:
            return TicketResult(
                backend="jira",
                ok=False,
                error=f"Missing Jira config: {', '.join(missing)}",
            )

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
            correlation_id=correlation_id,
            logger=logger,
        )

    return TicketResult(backend=config.ticket_backend, ok=False, error="Unsupported backend")


def _severity_from_priority(priority: str) -> int:
    return {"low": 1, "medium": 2, "high": 3, "critical": 4}.get(priority, 2)


def _observable_type_from_ioc(ioc_type: str) -> str:
    return {"ip": "ip", "domain": "domain", "url": "url", "hash": "hash"}.get(ioc_type, "other")


def _normalized_thehive_alert_endpoint(base_url: str) -> str:
    trimmed = base_url.rstrip("/")
    if trimmed.endswith("/api/v1/alert"):
        return trimmed
    return f"{trimmed}/api/v1/alert"


def forward_to_thehive(
    config: RuntimeConfig,
    finding: dict[str, Any],
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> IntegrationResult:
    if not config.thehive_url or not config.thehive_api_key:
        return IntegrationResult(
            target="thehive",
            ok=False,
            error="Missing THEHIVE_URL or THEHIVE_API_KEY.",
        )

    endpoint = _normalized_thehive_alert_endpoint(config.thehive_url)
    source_ref = f"mini-soar-{int(time.time() * 1000)}-{abs(hash(finding['ioc'])) % 100000}"
    payload = build_ticket_payload(finding)

    body = {
        "type": config.thehive_alert_type,
        "source": "mini_soar",
        "sourceRef": source_ref,
        "title": payload["summary"][:512],
        "description": payload["description"],
        "severity": _severity_from_priority(finding["priority"]),
        "tlp": int(config.thehive_tlp),
        "pap": int(config.thehive_pap),
        "tags": payload["labels"],
        "observables": [
            {
                "dataType": _observable_type_from_ioc(finding["ioc_type"]),
                "data": finding["ioc"],
                "tlp": int(config.thehive_tlp),
                "tags": payload["labels"],
            }
        ],
    }

    headers = {
        "Authorization": f"Bearer {config.thehive_api_key}",
        "X-Api-Key": config.thehive_api_key,
        "Accept": "application/json",
    }
    status, data, error = http_json_request(
        url=endpoint,
        method="POST",
        headers=headers,
        payload=body,
        timeout=config.integration_timeout or config.timeout,
        connector_name="thehive",
        max_retries=config.max_retries,
        retry_backoff_seconds=config.retry_backoff_seconds,
        correlation_id=correlation_id,
        logger=logger,
    )
    if error:
        return IntegrationResult(target="thehive", ok=False, error=error)

    reference = source_ref
    if isinstance(data, dict):
        reference = str(data.get("id") or data.get("_id") or data.get("caseId") or source_ref)
    return IntegrationResult(target="thehive", ok=status in {200, 201}, reference=reference)


def _normalized_splunk_event_endpoint(base_url: str) -> str:
    trimmed = base_url.rstrip("/")
    if trimmed.endswith("/services/collector/event"):
        return trimmed
    return f"{trimmed}/services/collector/event"


def forward_to_splunk(
    config: RuntimeConfig,
    finding: dict[str, Any],
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> IntegrationResult:
    if not config.splunk_hec_url or not config.splunk_hec_token:
        return IntegrationResult(
            target="splunk",
            ok=False,
            error="Missing SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN.",
        )

    endpoint = _normalized_splunk_event_endpoint(config.splunk_hec_url)
    event = {
        "generated_at": finding["generated_at"],
        "ioc": finding["ioc"],
        "ioc_type": finding["ioc_type"],
        "risk_score": finding["risk_score"],
        "priority": finding["priority"],
        "reasons": finding["reasons"],
        "virustotal": finding["virustotal"],
        "abuseipdb": finding["abuseipdb"],
    }
    body = {
        "time": int(time.time()),
        "host": "mini-soar",
        "source": "mini_soar",
        "sourcetype": config.splunk_sourcetype,
        "event": event,
    }
    headers = {
        "Authorization": f"Splunk {config.splunk_hec_token}",
        "Accept": "application/json",
    }
    status, data, error = http_json_request(
        url=endpoint,
        method="POST",
        headers=headers,
        payload=body,
        timeout=config.integration_timeout or config.timeout,
        connector_name="splunk",
        max_retries=config.max_retries,
        retry_backoff_seconds=config.retry_backoff_seconds,
        correlation_id=correlation_id,
        logger=logger,
    )
    if error:
        return IntegrationResult(target="splunk", ok=False, error=error)

    ok = status == 200
    reference = str(status)
    if isinstance(data, dict):
        ok = ok and int(data.get("code", 1)) == 0
        reference = str(data.get("text") or status)
    return IntegrationResult(target="splunk", ok=ok, reference=reference)

def _build_sentinel_signature(
    workspace_id: str,
    shared_key: str,
    date_rfc1123: str,
    content_length: int,
    method: str,
    content_type: str,
    resource: str,
) -> str:
    x_headers = f"x-ms-date:{date_rfc1123}"
    string_to_hash = f"{method}\n{content_length}\n{content_type}\n{x_headers}\n{resource}"
    decoded_key = base64.b64decode(shared_key)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    return f"SharedKey {workspace_id}:{encoded_hash}"


def _normalized_sentinel_endpoint(config: RuntimeConfig) -> str:
    if config.sentinel_endpoint:
        return config.sentinel_endpoint
    return (
        f"https://{config.sentinel_workspace_id}.ods.opinsights.azure.com/"
        "api/logs?api-version=2016-04-01"
    )


def forward_to_sentinel(
    config: RuntimeConfig,
    finding: dict[str, Any],
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> IntegrationResult:
    if not config.sentinel_workspace_id or not config.sentinel_shared_key:
        return IntegrationResult(
            target="sentinel",
            ok=False,
            error="Missing SENTINEL_WORKSPACE_ID or SENTINEL_SHARED_KEY.",
        )

    endpoint = _normalized_sentinel_endpoint(config)
    resource = "/api/logs"
    content_type = "application/json"
    date_rfc1123 = utc_now_rfc1123()

    log_record = {
        "generated_at": finding["generated_at"],
        "ioc": finding["ioc"],
        "ioc_type": finding["ioc_type"],
        "risk_score": finding["risk_score"],
        "priority": finding["priority"],
        "reasons": finding["reasons"],
        "virustotal": finding["virustotal"],
        "abuseipdb": finding["abuseipdb"],
        "source": "mini-soar",
    }
    body = json.dumps([log_record], ensure_ascii=False).encode("utf-8")

    signature = _build_sentinel_signature(
        workspace_id=config.sentinel_workspace_id,
        shared_key=config.sentinel_shared_key,
        date_rfc1123=date_rfc1123,
        content_length=len(body),
        method="POST",
        content_type=content_type,
        resource=resource,
    )

    headers = {
        "Content-Type": content_type,
        "Authorization": signature,
        "Log-Type": config.sentinel_log_type,
        "x-ms-date": date_rfc1123,
        "time-generated-field": "generated_at",
    }
    status, _, error = http_raw_request(
        url=endpoint,
        method="POST",
        headers=headers,
        body=body,
        timeout=config.integration_timeout or config.timeout,
        connector_name="sentinel",
        max_retries=config.max_retries,
        retry_backoff_seconds=config.retry_backoff_seconds,
        correlation_id=correlation_id,
        logger=logger,
    )
    if error:
        return IntegrationResult(target="sentinel", ok=False, error=error)
    return IntegrationResult(target="sentinel", ok=status in {200, 202}, reference=str(status))


IntegrationHandler = Any
INTEGRATION_PLUGIN_REGISTRY: dict[str, IntegrationHandler] = {}
_LOADED_PLUGIN_MODULES: set[str] = set()


def register_integration_plugin(name: str, handler: IntegrationHandler) -> None:
    INTEGRATION_PLUGIN_REGISTRY[name] = handler


def load_plugins_from_env(logger: logging.Logger | None = None) -> None:
    raw_modules = os.getenv("MINI_SOAR_PLUGIN_MODULES", "")
    if not raw_modules.strip():
        return

    for module_name in [item.strip() for item in raw_modules.split(",") if item.strip()]:
        if module_name in _LOADED_PLUGIN_MODULES:
            continue
        try:
            importlib.import_module(module_name)
            _LOADED_PLUGIN_MODULES.add(module_name)
            if logger:
                log_event(logger, logging.INFO, "plugin_loaded", connector=module_name)
        except Exception as exc:
            if logger:
                log_event(logger, logging.ERROR, "plugin_load_failed", connector=module_name, error=str(exc))


def forward_to_integrations(
    config: RuntimeConfig,
    finding: dict[str, Any],
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> list[IntegrationResult]:
    results: list[IntegrationResult] = []
    for target in config.integration_targets:
        handler = INTEGRATION_PLUGIN_REGISTRY.get(target)
        if not handler:
            results.append(IntegrationResult(target=target, ok=False, error="Unsupported integration target."))
            continue
        try:
            result = handler(config, finding, correlation_id=correlation_id, logger=logger)
            results.append(result)
        except Exception as exc:  # Defensive boundary for plugin failures.
            results.append(IntegrationResult(target=target, ok=False, error=str(exc)))
    return results


register_integration_plugin("thehive", forward_to_thehive)
register_integration_plugin("splunk", forward_to_splunk)
register_integration_plugin("sentinel", forward_to_sentinel)


def process_ioc(
    ioc: str,
    config: RuntimeConfig,
    store: BaseStore | None = None,
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    local_store = store or NullStore()
    local_logger = logger or get_logger("mini_soar.core")
    ioc_type = detect_ioc_type(ioc)
    generated_at = utc_now_iso()
    errors: list[str] = []

    if config.enable_idempotency and local_store.seen_recent_ioc(ioc, config.idempotency_window_seconds):
        finding = {
            "ioc": ioc,
            "ioc_type": ioc_type,
            "generated_at": generated_at,
            "correlation_id": correlation_id,
            "risk_score": 0,
            "priority": "low",
            "reasons": [f"Skipped duplicate IOC in idempotency window ({config.idempotency_window_seconds}s)."],
            "virustotal": None,
            "abuseipdb": None,
            "errors": [],
            "ticket": None,
            "integrations": [],
            "skipped": True,
            "mitre_attack": map_finding_to_mitre({"ioc_type": ioc_type, "priority": "low"}),
            "runbook_steps": build_runbook_steps({"ioc": ioc, "ioc_type": ioc_type, "priority": "low"}),
        }
        local_store.mark_ioc_seen(ioc, ioc_type)
        if config.persist_findings:
            local_store.save_finding(correlation_id or "no-correlation-id", finding)
        IOCS_PROCESSED_TOTAL.labels(ioc_type=ioc_type, priority="low").inc()
        log_event(
            local_logger,
            logging.INFO,
            "ioc_skipped_idempotency",
            correlation_id=correlation_id,
            ioc=ioc,
            ioc_type=ioc_type,
        )
        return finding

    vt_data: dict[str, Any] | None = None
    abuse_data: dict[str, Any] | None = None

    if config.vt_api_key:
        vt_data, vt_error = virustotal_lookup(
            ioc,
            ioc_type,
            config.vt_api_key,
            timeout=config.vt_timeout or config.timeout,
            max_retries=config.max_retries,
            retry_backoff_seconds=config.retry_backoff_seconds,
            correlation_id=correlation_id,
            logger=local_logger,
        )
        if vt_error:
            errors.append(f"VirusTotal: {vt_error}")

    if config.abuse_api_key and ioc_type == "ip":
        abuse_data, abuse_error = abuseipdb_lookup(
            ioc,
            config.abuse_api_key,
            max_age_days=config.abuse_max_age,
            timeout=config.abuse_timeout or config.timeout,
            max_retries=config.max_retries,
            retry_backoff_seconds=config.retry_backoff_seconds,
            correlation_id=correlation_id,
            logger=local_logger,
        )
        if abuse_error:
            errors.append(f"AbuseIPDB: {abuse_error}")

    risk_score, reasons = score_finding(vt_data, abuse_data)
    priority = priority_from_score(risk_score)

    finding: dict[str, Any] = {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "generated_at": generated_at,
        "correlation_id": correlation_id,
        "risk_score": risk_score,
        "priority": priority,
        "reasons": reasons,
        "virustotal": vt_data,
        "abuseipdb": abuse_data,
        "errors": errors,
        "ticket": None,
        "integrations": [],
        "skipped": False,
    }

    if risk_score >= config.ticket_threshold:
        ticket_result = maybe_open_ticket(
            config=config,
            finding=finding,
            correlation_id=correlation_id,
            logger=local_logger,
        )
        if ticket_result:
            finding["ticket"] = asdict(ticket_result)

    if config.integration_targets and risk_score >= config.integration_threshold:
        integration_results = forward_to_integrations(
            config=config,
            finding=finding,
            correlation_id=correlation_id,
            logger=local_logger,
        )
        finding["integrations"] = [asdict(result) for result in integration_results]

    finding["mitre_attack"] = map_finding_to_mitre(finding)
    finding["runbook_steps"] = build_runbook_steps(finding)

    local_store.mark_ioc_seen(ioc, ioc_type)
    if config.persist_findings:
        local_store.save_finding(correlation_id or "no-correlation-id", finding)

    IOCS_PROCESSED_TOTAL.labels(ioc_type=ioc_type, priority=priority).inc()
    log_event(
        local_logger,
        logging.INFO,
        "ioc_processed",
        correlation_id=correlation_id,
        ioc=ioc,
        ioc_type=ioc_type,
        risk_score=risk_score,
        priority=priority,
        error="; ".join(errors)[:500] if errors else None,
    )
    return finding


def run_pipeline(
    iocs: list[str],
    config: RuntimeConfig,
    progress: bool = False,
    correlation_id: str | None = None,
    store: BaseStore | None = None,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    local_logger = logger or get_logger("mini_soar.core")
    load_plugins_from_env(local_logger)
    started = time.perf_counter()
    pipeline_status = "ok"
    try:
        try:
            local_store = store or create_store(config.database_url)
        except Exception as exc:
            local_store = NullStore()
            log_event(
                local_logger,
                logging.ERROR,
                "store_init_failed",
                correlation_id=correlation_id,
                error=str(exc),
            )

        findings: list[dict[str, Any]] = []
        opened_tickets = 0

        if config.ticket_backend not in TICKET_CHOICES:
            raise ValueError(f"Unsupported ticket backend: {config.ticket_backend}")

        valid_targets = set(INTEGRATION_CHOICES).union(set(INTEGRATION_PLUGIN_REGISTRY.keys()))
        invalid_targets = [target for target in config.integration_targets if target not in valid_targets]
        if invalid_targets:
            raise ValueError(f"Unsupported integration targets: {', '.join(sorted(set(invalid_targets)))}")

        for index, ioc in enumerate(iocs, start=1):
            finding = process_ioc(
                ioc=ioc,
                config=config,
                store=local_store,
                correlation_id=correlation_id,
                logger=local_logger,
            )
            findings.append(finding)

            ticket_ok = bool(finding["ticket"] and finding["ticket"].get("ok"))
            if ticket_ok:
                opened_tickets += 1

            if progress:
                integrations_sent = len(finding["integrations"])
                print(
                    f"[{index}/{len(iocs)}] {finding['ioc']} ({finding['ioc_type']}) -> "
                    f"score={finding['risk_score']}, priority={finding['priority']}, "
                    f"ticket={'yes' if finding['ticket'] else 'no'}, integrations={integrations_sent}"
                )

            if config.sleep > 0 and index < len(iocs):
                time.sleep(config.sleep)

        integration_attempts = sum(len(f["integrations"]) for f in findings)
        integration_success = sum(
            1 for f in findings for integration in f["integrations"] if integration.get("ok", False)
        )
        integration_failed = integration_attempts - integration_success

        report = {
            "generated_at": utc_now_iso(),
            "correlation_id": correlation_id,
            "summary": {
                "total_iocs": len(iocs),
                "with_errors": sum(1 for f in findings if f["errors"]),
                "high_or_critical": sum(1 for f in findings if f["priority"] in {"high", "critical"}),
                "skipped_by_idempotency": sum(1 for f in findings if f.get("skipped")),
                "tickets_opened": opened_tickets,
                "ticket_backend": config.ticket_backend,
                "ticket_threshold": config.ticket_threshold,
                "integration_targets": list(config.integration_targets),
                "integration_threshold": config.integration_threshold,
                "integration_attempts": integration_attempts,
                "integration_success": integration_success,
                "integration_failed": integration_failed,
                "avg_risk_score": round(
                    (sum(f["risk_score"] for f in findings) / len(findings)) if findings else 0.0,
                    2,
                ),
            },
            "findings": findings,
        }
        return report
    except Exception:
        pipeline_status = "error"
        raise
    finally:
        elapsed = time.perf_counter() - started
        PIPELINE_RUNS_TOTAL.labels(status=pipeline_status).inc()
        PIPELINE_DURATION_SECONDS.observe(elapsed)
        log_event(
            local_logger,
            logging.INFO,
            "pipeline_completed",
            correlation_id=correlation_id,
            duration_ms=round(elapsed * 1000, 2),
            error=None if pipeline_status == "ok" else "pipeline_error",
        )


def write_report_json(report: dict[str, Any], output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)


def write_metrics_csv(report: dict[str, Any], csv_path: str) -> None:
    rows: list[dict[str, Any]] = []
    for finding in report.get("findings", []):
        vt_stats = (finding.get("virustotal") or {}).get("analysis_stats", {})
        abuse = finding.get("abuseipdb") or {}
        ticket = finding.get("ticket") or {}
        integrations = finding.get("integrations") or []
        integration_ok = sum(1 for item in integrations if item.get("ok"))
        integration_fail = sum(1 for item in integrations if not item.get("ok"))

        rows.append(
            {
                "correlation_id": finding.get("correlation_id"),
                "generated_at": finding.get("generated_at"),
                "ioc": finding.get("ioc"),
                "ioc_type": finding.get("ioc_type"),
                "risk_score": finding.get("risk_score"),
                "priority": finding.get("priority"),
                "skipped": finding.get("skipped"),
                "error_count": len(finding.get("errors", [])),
                "ticket_backend": ticket.get("backend"),
                "ticket_ok": ticket.get("ok"),
                "ticket_reference": ticket.get("reference"),
                "vt_malicious": vt_stats.get("malicious"),
                "vt_suspicious": vt_stats.get("suspicious"),
                "vt_harmless": vt_stats.get("harmless"),
                "vt_undetected": vt_stats.get("undetected"),
                "abuse_confidence_score": abuse.get("abuse_confidence_score"),
                "abuse_total_reports": abuse.get("total_reports"),
                "integrations_sent": len(integrations),
                "integrations_ok": integration_ok,
                "integrations_fail": integration_fail,
            }
        )

    fieldnames = [
        "correlation_id",
        "generated_at",
        "ioc",
        "ioc_type",
        "risk_score",
        "priority",
        "skipped",
        "error_count",
        "ticket_backend",
        "ticket_ok",
        "ticket_reference",
        "vt_malicious",
        "vt_suspicious",
        "vt_harmless",
        "vt_undetected",
        "abuse_confidence_score",
        "abuse_total_reports",
        "integrations_sent",
        "integrations_ok",
        "integrations_fail",
    ]

    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def runtime_config_to_dict(config: RuntimeConfig) -> dict[str, Any]:
    return asdict(config)


def runtime_config_from_dict(payload: dict[str, Any]) -> RuntimeConfig:
    return RuntimeConfig(**payload)
