#!/usr/bin/env python3
"""External SIEM/SOAR integration connectors for SentinelCore SOAR.

Supports forwarding enriched findings to:
- TheHive (alert creation via v1 API)
- Splunk (HTTP Event Collector)
- Microsoft Sentinel (Log Analytics Data Collector API)

Also manages the integration plugin registry for custom connectors.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import importlib
import json
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from mini_soar_enrichment import http_json_request, http_raw_request, utc_now_rfc1123
from mini_soar_observability import log_event
from mini_soar_ticketing import build_ticket_payload

if TYPE_CHECKING:
    from mini_soar_core import RuntimeConfig


@dataclass
class IntegrationResult:
    target: str
    ok: bool
    reference: str | None = None
    error: str | None = None


# ── Plugin registry ────────────────────────────────────────────────────────────

IntegrationHandler = Any
INTEGRATION_PLUGIN_REGISTRY: dict[str, IntegrationHandler] = {}
_LOADED_PLUGIN_MODULES: set[str] = set()


def register_integration_plugin(name: str, handler: IntegrationHandler) -> None:
    """Register a named integration handler in the global registry."""
    INTEGRATION_PLUGIN_REGISTRY[name] = handler


def load_plugins_from_env(logger: logging.Logger | None = None) -> None:
    """Load external plugin modules listed in MINI_SOAR_PLUGIN_MODULES env var."""
    import os
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
    """Dispatch a finding to all configured integration targets."""
    results: list[IntegrationResult] = []
    for target in config.integration_targets:
        handler = INTEGRATION_PLUGIN_REGISTRY.get(target)
        if not handler:
            results.append(IntegrationResult(target=target, ok=False, error="Unsupported integration target."))
            continue
        try:
            result = handler(config, finding, correlation_id=correlation_id, logger=logger)
            results.append(result)
        except Exception as exc:
            results.append(IntegrationResult(target=target, ok=False, error=str(exc)))
    return results


# ── TheHive ────────────────────────────────────────────────────────────────────

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
    """Create a TheHive alert for the given finding."""
    if not config.thehive_url or not config.thehive_api_key:
        return IntegrationResult(target="thehive", ok=False, error="Missing THEHIVE_URL or THEHIVE_API_KEY.")

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
        "observables": [{
            "dataType": _observable_type_from_ioc(finding["ioc_type"]),
            "data": finding["ioc"],
            "tlp": int(config.thehive_tlp),
            "tags": payload["labels"],
        }],
    }
    headers = {
        "Authorization": f"Bearer {config.thehive_api_key}",
        "X-Api-Key": config.thehive_api_key,
        "Accept": "application/json",
    }
    status, data, error = http_json_request(
        url=endpoint, method="POST", headers=headers, payload=body,
        timeout=config.integration_timeout or config.timeout,
        connector_name="thehive", max_retries=config.max_retries,
        retry_backoff_seconds=config.retry_backoff_seconds,
        correlation_id=correlation_id, logger=logger,
    )
    if error:
        return IntegrationResult(target="thehive", ok=False, error=error)

    reference = source_ref
    if isinstance(data, dict):
        reference = str(data.get("id") or data.get("_id") or data.get("caseId") or source_ref)
    return IntegrationResult(target="thehive", ok=status in {200, 201}, reference=reference)


# ── Splunk ─────────────────────────────────────────────────────────────────────

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
    """Send a finding to Splunk via the HTTP Event Collector (HEC)."""
    if not config.splunk_hec_url or not config.splunk_hec_token:
        return IntegrationResult(target="splunk", ok=False, error="Missing SPLUNK_HEC_URL or SPLUNK_HEC_TOKEN.")

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
    headers = {"Authorization": f"Splunk {config.splunk_hec_token}", "Accept": "application/json"}
    status, data, error = http_json_request(
        url=endpoint, method="POST", headers=headers, payload=body,
        timeout=config.integration_timeout or config.timeout,
        connector_name="splunk", max_retries=config.max_retries,
        retry_backoff_seconds=config.retry_backoff_seconds,
        correlation_id=correlation_id, logger=logger,
    )
    if error:
        return IntegrationResult(target="splunk", ok=False, error=error)

    ok = status == 200
    reference = str(status)
    if isinstance(data, dict):
        ok = ok and int(data.get("code", 1)) == 0
        reference = str(data.get("text") or status)
    return IntegrationResult(target="splunk", ok=ok, reference=reference)


# ── Microsoft Sentinel ─────────────────────────────────────────────────────────

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
    """Send a finding to Microsoft Sentinel via the Log Analytics Data Collector API."""
    if not config.sentinel_workspace_id or not config.sentinel_shared_key:
        return IntegrationResult(
            target="sentinel", ok=False,
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
        url=endpoint, method="POST", headers=headers, body=body,
        timeout=config.integration_timeout or config.timeout,
        connector_name="sentinel", max_retries=config.max_retries,
        retry_backoff_seconds=config.retry_backoff_seconds,
        correlation_id=correlation_id, logger=logger,
    )
    if error:
        return IntegrationResult(target="sentinel", ok=False, error=error)
    return IntegrationResult(target="sentinel", ok=status in {200, 202}, reference=str(status))


# ── Built-in registrations ─────────────────────────────────────────────────────

register_integration_plugin("thehive", forward_to_thehive)
register_integration_plugin("splunk", forward_to_splunk)
register_integration_plugin("sentinel", forward_to_sentinel)
