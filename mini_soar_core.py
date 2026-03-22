#!/usr/bin/env python3
"""Core engine for SentinelCore SOAR — pipeline orchestration and configuration.

Coordinates IOC detection, enrichment, scoring, ticketing, and integrations.
Heavy lifting is delegated to the focused sub-modules:
  - mini_soar_enrichment   : HTTP helpers + VirusTotal / AbuseIPDB lookups + demo mocks
  - mini_soar_ticketing    : ticket creation (file / webhook / Jira)
  - mini_soar_integrations : SIEM/SOAR connectors (TheHive, Splunk, Sentinel) + plugin registry
"""

from __future__ import annotations

import csv
import ipaddress
import json
import logging
import os
import re
import time
import urllib.parse
from dataclasses import asdict, dataclass
from typing import Any

from mini_soar_enrichment import (
    abuseipdb_lookup,
    abuseipdb_mock,
    greynoise_lookup,
    greynoise_mock,
    otx_lookup,
    otx_mock,
    shodan_lookup,
    shodan_mock,
    utc_now_iso,
    virustotal_lookup,
    virustotal_mock,
)
from mini_soar_scoring import load_scoring_config, score_finding
from mini_soar_integrations import (
    INTEGRATION_PLUGIN_REGISTRY,
    IntegrationResult,
    forward_to_integrations,
    load_plugins_from_env,
    register_integration_plugin,
)
from mini_soar_mitre import build_runbook_steps, map_finding_to_mitre
from mini_soar_observability import (
    IOCS_PROCESSED_TOTAL,
    PIPELINE_DURATION_SECONDS,
    PIPELINE_RUNS_TOTAL,
    get_logger,
    log_event,
)
from mini_soar_storage import BaseStore, NullStore, create_store
from mini_soar_ticketing import TicketResult, maybe_open_ticket


# ── Constants ──────────────────────────────────────────────────────────────────

DOMAIN_REGEX = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

INTEGRATION_CHOICES = {"thehive", "splunk", "sentinel"}
TICKET_CHOICES = {"none", "file", "webhook", "jira"}


# ── Re-exports for backward compatibility ──────────────────────────────────────
# Code that previously imported these from mini_soar_core continues to work.

__all__ = [
    "RuntimeConfig",
    "build_config_from_env",
    "detect_ioc_type",
    "read_iocs",
    "score_finding",
    "priority_from_score",
    "process_ioc",
    "run_pipeline",
    "write_report_json",
    "write_metrics_csv",
    "runtime_config_to_dict",
    "runtime_config_from_dict",
    # re-exported from sub-modules
    "TicketResult",
    "IntegrationResult",
    "register_integration_plugin",
    "utc_now_iso",
    "load_scoring_config",
    "DOMAIN_REGEX",
    "INTEGRATION_CHOICES",
    "TICKET_CHOICES",
]


# ── Configuration ──────────────────────────────────────────────────────────────

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
    demo_mode: bool = False
    scoring_config_path: str | None = None

    # ── Additional threat intelligence sources ─────────────────────────────────
    greynoise_api_key: str | None = None
    greynoise_timeout: int = 20
    shodan_api_key: str | None = None
    shodan_timeout: int = 20
    otx_api_key: str | None = None
    otx_timeout: int = 20


def build_config_from_env() -> RuntimeConfig:
    """Build a RuntimeConfig from environment variables."""
    targets_raw = os.getenv("MINI_SOAR_INTEGRATION_TARGETS", "")
    parsed_targets = tuple(sorted({
        item.strip().lower()
        for item in targets_raw.split(",")
        if item.strip().lower() in INTEGRATION_CHOICES
    }))

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
        demo_mode=os.getenv("MINI_SOAR_DEMO_MODE", "false").lower() == "true",
        scoring_config_path=os.getenv("MINI_SOAR_SCORING_CONFIG"),
        greynoise_api_key=os.getenv("GREYNOISE_API_KEY"),
        greynoise_timeout=int(os.getenv("MINI_SOAR_GREYNOISE_TIMEOUT", "20")),
        shodan_api_key=os.getenv("SHODAN_API_KEY"),
        shodan_timeout=int(os.getenv("MINI_SOAR_SHODAN_TIMEOUT", "20")),
        otx_api_key=os.getenv("OTX_API_KEY"),
        otx_timeout=int(os.getenv("MINI_SOAR_OTX_TIMEOUT", "20")),
    )


def runtime_config_to_dict(config: RuntimeConfig) -> dict[str, Any]:
    return asdict(config)


def runtime_config_from_dict(payload: dict[str, Any]) -> RuntimeConfig:
    return RuntimeConfig(**payload)


# ── IOC helpers ────────────────────────────────────────────────────────────────

def read_iocs(input_file: str | None, inline_iocs: list[str]) -> list[str]:
    """Read and deduplicate IOCs from an inline list and/or a file."""
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
    """Detect the type of an IOC string: ip, url, hash, domain, or unknown."""
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


# score_finding is imported from mini_soar_scoring; re-exported via __all__


def priority_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


# ── Pipeline ───────────────────────────────────────────────────────────────────

def process_ioc(
    ioc: str,
    config: RuntimeConfig,
    store: BaseStore | None = None,
    correlation_id: str | None = None,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Enrich a single IOC and produce a finding dict."""
    local_store = store or NullStore()
    local_logger = logger or get_logger("mini_soar.core")
    ioc_type = detect_ioc_type(ioc)
    generated_at = utc_now_iso()
    errors: list[str] = []

    if config.enable_idempotency and local_store.seen_recent_ioc(
        ioc, config.idempotency_window_seconds, ioc_type
    ):
        cached = local_store.get_cached_finding(ioc, ioc_type)
        if cached is not None:
            # Return the real enriched result; update request-scoped fields only.
            finding = dict(cached)
            finding["skipped"] = True
            finding["cached"] = True
            finding["correlation_id"] = correlation_id
            finding["generated_at"] = generated_at
        else:
            # Defensive fallback: IOC was seen but no stored finding available
            # (e.g. persist_findings was disabled on the first run).
            finding = {
                "ioc": ioc,
                "ioc_type": ioc_type,
                "generated_at": generated_at,
                "correlation_id": correlation_id,
                "risk_score": 0,
                "priority": "low",
                "reasons": [
                    f"Skipped duplicate IOC in idempotency window"
                    f" ({config.idempotency_window_seconds}s); no cached finding available."
                ],
                "virustotal": None,
                "abuseipdb": None,
                "greynoise": None,
                "shodan": None,
                "otx": None,
                "sources_queried": [],
                "errors": [],
                "ticket": None,
                "integrations": [],
                "skipped": True,
                "cached": False,
                "mitre_attack": map_finding_to_mitre({"ioc_type": ioc_type, "priority": "low"}),
                "runbook_steps": build_runbook_steps(
                    {"ioc": ioc, "ioc_type": ioc_type, "priority": "low"}
                ),
            }
        local_store.mark_ioc_seen(ioc, ioc_type)
        # Do not re-persist — the original finding is already in storage.
        IOCS_PROCESSED_TOTAL.labels(
            ioc_type=ioc_type, priority=finding.get("priority", "low")
        ).inc()
        log_event(
            local_logger, logging.INFO, "ioc_skipped_idempotency",
            correlation_id=correlation_id, ioc=ioc, ioc_type=ioc_type,
            cached=cached is not None,
        )
        return finding

    vt_data:        dict[str, Any] | None = None
    abuse_data:     dict[str, Any] | None = None
    greynoise_data: dict[str, Any] | None = None
    shodan_data:    dict[str, Any] | None = None
    otx_data:       dict[str, Any] | None = None

    if config.demo_mode:
        vt_data, vt_error = virustotal_mock(ioc, ioc_type)
        if vt_error:
            errors.append(f"VirusTotal (demo): {vt_error}")
        if ioc_type == "ip":
            abuse_data, abuse_error = abuseipdb_mock(ioc)
            if abuse_error:
                errors.append(f"AbuseIPDB (demo): {abuse_error}")
            greynoise_data, gn_error = greynoise_mock(ioc)
            if gn_error:
                errors.append(f"GreyNoise (demo): {gn_error}")
            shodan_data, sh_error = shodan_mock(ioc)
            if sh_error:
                errors.append(f"Shodan (demo): {sh_error}")
        otx_data, otx_error = otx_mock(ioc, ioc_type)
        if otx_error:
            errors.append(f"OTX (demo): {otx_error}")
    else:
        if config.vt_api_key:
            vt_data, vt_error = virustotal_lookup(
                ioc, ioc_type, config.vt_api_key,
                timeout=config.vt_timeout or config.timeout,
                max_retries=config.max_retries,
                retry_backoff_seconds=config.retry_backoff_seconds,
                correlation_id=correlation_id, logger=local_logger,
            )
            if vt_error:
                errors.append(f"VirusTotal: {vt_error}")

        if config.abuse_api_key and ioc_type == "ip":
            abuse_data, abuse_error = abuseipdb_lookup(
                ioc, config.abuse_api_key,
                max_age_days=config.abuse_max_age,
                timeout=config.abuse_timeout or config.timeout,
                max_retries=config.max_retries,
                retry_backoff_seconds=config.retry_backoff_seconds,
                correlation_id=correlation_id, logger=local_logger,
            )
            if abuse_error:
                errors.append(f"AbuseIPDB: {abuse_error}")

        if config.greynoise_api_key and ioc_type == "ip":
            greynoise_data, gn_error = greynoise_lookup(
                ioc, config.greynoise_api_key,
                timeout=config.greynoise_timeout,
                max_retries=config.max_retries,
                retry_backoff_seconds=config.retry_backoff_seconds,
                correlation_id=correlation_id, logger=local_logger,
            )
            if gn_error:
                errors.append(f"GreyNoise: {gn_error}")

        if config.shodan_api_key and ioc_type == "ip":
            shodan_data, sh_error = shodan_lookup(
                ioc, config.shodan_api_key,
                timeout=config.shodan_timeout,
                max_retries=config.max_retries,
                retry_backoff_seconds=config.retry_backoff_seconds,
                correlation_id=correlation_id, logger=local_logger,
            )
            if sh_error:
                errors.append(f"Shodan: {sh_error}")

        if config.otx_api_key:
            otx_data, otx_error = otx_lookup(
                ioc, ioc_type, config.otx_api_key,
                timeout=config.otx_timeout,
                max_retries=config.max_retries,
                retry_backoff_seconds=config.retry_backoff_seconds,
                correlation_id=correlation_id, logger=local_logger,
            )
            if otx_error:
                errors.append(f"OTX: {otx_error}")

    scoring_cfg = load_scoring_config(config.scoring_config_path)
    risk_score, reasons = score_finding(
        vt_data, abuse_data, scoring_cfg,
        greynoise=greynoise_data, shodan=shodan_data, otx=otx_data,
    )
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
        "greynoise": greynoise_data,
        "shodan": shodan_data,
        "otx": otx_data,
        "sources_queried": [
            src for src, data in [
                ("virustotal", vt_data),
                ("abuseipdb",  abuse_data),
                ("greynoise",  greynoise_data),
                ("shodan",     shodan_data),
                ("otx",        otx_data),
            ] if data is not None
        ],
        "errors": errors,
        "ticket": None,
        "integrations": [],
        "skipped": False,
    }

    if risk_score >= config.ticket_threshold:
        ticket_result = maybe_open_ticket(
            config=config, finding=finding,
            correlation_id=correlation_id, logger=local_logger,
        )
        if ticket_result:
            finding["ticket"] = asdict(ticket_result)

    if config.integration_targets and risk_score >= config.integration_threshold:
        integration_results = forward_to_integrations(
            config=config, finding=finding,
            correlation_id=correlation_id, logger=local_logger,
        )
        finding["integrations"] = [asdict(result) for result in integration_results]

    finding["mitre_attack"] = map_finding_to_mitre(finding)
    finding["runbook_steps"] = build_runbook_steps(finding)

    local_store.mark_ioc_seen(ioc, ioc_type)
    if config.persist_findings:
        local_store.save_finding(correlation_id or "no-correlation-id", finding)

    IOCS_PROCESSED_TOTAL.labels(ioc_type=ioc_type, priority=priority).inc()
    log_event(local_logger, logging.INFO, "ioc_processed",
              correlation_id=correlation_id, ioc=ioc, ioc_type=ioc_type,
              risk_score=risk_score, priority=priority,
              error="; ".join(errors)[:500] if errors else None)
    return finding


def run_pipeline(
    iocs: list[str],
    config: RuntimeConfig,
    progress: bool = False,
    correlation_id: str | None = None,
    store: BaseStore | None = None,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Run the full IOC enrichment pipeline and return a report dict."""
    local_logger = logger or get_logger("mini_soar.core")
    load_plugins_from_env(local_logger)
    started = time.perf_counter()
    pipeline_status = "ok"
    try:
        try:
            local_store = store or create_store(config.database_url)
        except Exception as exc:
            local_store = NullStore()
            log_event(local_logger, logging.ERROR, "store_init_failed",
                      correlation_id=correlation_id, error=str(exc))

        findings: list[dict[str, Any]] = []
        opened_tickets = 0

        if config.ticket_backend not in TICKET_CHOICES:
            raise ValueError(f"Unsupported ticket backend: {config.ticket_backend}")

        valid_targets = set(INTEGRATION_CHOICES).union(set(INTEGRATION_PLUGIN_REGISTRY.keys()))
        invalid_targets = [t for t in config.integration_targets if t not in valid_targets]
        if invalid_targets:
            raise ValueError(f"Unsupported integration targets: {', '.join(sorted(set(invalid_targets)))}")

        for index, ioc in enumerate(iocs, start=1):
            finding = process_ioc(
                ioc=ioc, config=config, store=local_store,
                correlation_id=correlation_id, logger=local_logger,
            )
            findings.append(finding)

            if finding["ticket"] and finding["ticket"].get("ok"):
                opened_tickets += 1

            if progress:
                print(
                    f"[{index}/{len(iocs)}] {finding['ioc']} ({finding['ioc_type']}) -> "
                    f"score={finding['risk_score']}, priority={finding['priority']}, "
                    f"ticket={'yes' if finding['ticket'] else 'no'}, "
                    f"integrations={len(finding['integrations'])}"
                )

            if config.sleep > 0 and index < len(iocs):
                time.sleep(config.sleep)

        integration_attempts = sum(len(f["integrations"]) for f in findings)
        integration_success = sum(
            1 for f in findings for i in f["integrations"] if i.get("ok", False)
        )

        report = {
            "generated_at": utc_now_iso(),
            "correlation_id": correlation_id,
            "demo_mode": config.demo_mode,
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
                "integration_failed": integration_attempts - integration_success,
                "avg_risk_score": round(
                    (sum(f["risk_score"] for f in findings) / len(findings)) if findings else 0.0, 2
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
        log_event(local_logger, logging.INFO, "pipeline_completed",
                  correlation_id=correlation_id, duration_ms=round(elapsed * 1000, 2),
                  error=None if pipeline_status == "ok" else "pipeline_error")


# ── Output ─────────────────────────────────────────────────────────────────────

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
        rows.append({
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
            "integrations_ok": sum(1 for i in integrations if i.get("ok")),
            "integrations_fail": sum(1 for i in integrations if not i.get("ok")),
        })

    fieldnames = [
        "correlation_id", "generated_at", "ioc", "ioc_type", "risk_score", "priority",
        "skipped", "error_count", "ticket_backend", "ticket_ok", "ticket_reference",
        "vt_malicious", "vt_suspicious", "vt_harmless", "vt_undetected",
        "abuse_confidence_score", "abuse_total_reports",
        "integrations_sent", "integrations_ok", "integrations_fail",
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)
