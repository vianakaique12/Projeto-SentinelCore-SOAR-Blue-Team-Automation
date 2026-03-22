#!/usr/bin/env python3
"""Threat intelligence enrichment layer for SentinelCore SOAR.

Handles HTTP requests with retry/backoff and IOC lookups against:
- VirusTotal API v3
- AbuseIPDB API v2

Also provides deterministic mock functions for demo mode (MINI_SOAR_DEMO_MODE=true).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from mini_soar_observability import (
    CONNECTOR_LATENCY_SECONDS,
    CONNECTOR_REQUESTS_TOTAL,
    log_event,
)


# ── UTC helpers ────────────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def utc_now_rfc1123() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%a, %d %b %Y %H:%M:%S GMT")


# ── URL helpers ────────────────────────────────────────────────────────────────

def vt_url_id(raw_url: str) -> str:
    """Encode a URL into the base64 identifier required by the VirusTotal v3 API."""
    return base64.urlsafe_b64encode(raw_url.encode("utf-8")).decode("utf-8").rstrip("=")


# ── HTTP helpers ───────────────────────────────────────────────────────────────

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
    """HTTP request with exponential backoff retry on transient errors."""
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
                        logger, logging.INFO, "connector_request",
                        correlation_id=correlation_id, connector=connector_name,
                        status_code=response.status, duration_ms=round(elapsed * 1000, 2),
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
                        logger, logging.WARNING, "connector_retry",
                        correlation_id=correlation_id, connector=connector_name,
                        status_code=status_code, duration_ms=round(elapsed * 1000, 2),
                        error=f"retry in {round(sleep_seconds, 3)}s",
                    )
                time.sleep(sleep_seconds)
                continue

            if logger:
                log_event(
                    logger, logging.ERROR, "connector_error",
                    correlation_id=correlation_id, connector=connector_name,
                    status_code=status_code, duration_ms=round(elapsed * 1000, 2),
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
                        logger, logging.WARNING, "connector_retry",
                        correlation_id=correlation_id, connector=connector_name,
                        status_code=0, duration_ms=round(elapsed * 1000, 2),
                        error=f"{exc.reason}; retry in {round(sleep_seconds, 3)}s",
                    )
                time.sleep(sleep_seconds)
                continue

            if logger:
                log_event(
                    logger, logging.ERROR, "connector_error",
                    correlation_id=correlation_id, connector=connector_name,
                    status_code=0, duration_ms=round(elapsed * 1000, 2),
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
    """HTTP JSON request wrapper over http_raw_request."""
    body: bytes | None = None
    req_headers = (headers or {}).copy()

    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        req_headers["Content-Type"] = "application/json"

    status, raw, error = http_raw_request(
        url=url, method=method, headers=req_headers, body=body, timeout=timeout,
        connector_name=connector_name, max_retries=max_retries,
        retry_backoff_seconds=retry_backoff_seconds, correlation_id=correlation_id, logger=logger,
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


# ── VirusTotal ─────────────────────────────────────────────────────────────────

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
    """Query the VirusTotal v3 API for a given IOC."""
    endpoint_map = {
        "ip":     f"https://www.virustotal.com/api/v3/ip_addresses/{urllib.parse.quote(ioc)}",
        "domain": f"https://www.virustotal.com/api/v3/domains/{urllib.parse.quote(ioc)}",
        "hash":   f"https://www.virustotal.com/api/v3/files/{urllib.parse.quote(ioc)}",
        "url":    f"https://www.virustotal.com/api/v3/urls/{vt_url_id(ioc)}",
    }
    if ioc_type not in endpoint_map:
        return None, f"VirusTotal does not support IOC type '{ioc_type}'."

    status, data, error = http_json_request(
        url=endpoint_map[ioc_type],
        headers={"x-apikey": api_key, "Accept": "application/json"},
        timeout=timeout, connector_name="virustotal",
        max_retries=max_retries, retry_backoff_seconds=retry_backoff_seconds,
        correlation_id=correlation_id, logger=logger,
    )
    if error:
        return None, error

    attributes = data.get("data", {}).get("attributes", {}) if isinstance(data, dict) else {}
    return {
        "status": status,
        "analysis_stats": attributes.get("last_analysis_stats", {}),
        "reputation": attributes.get("reputation"),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "permalink": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(ioc)}",
    }, None


# ── AbuseIPDB ──────────────────────────────────────────────────────────────────

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
    """Query the AbuseIPDB v2 API for IP reputation data."""
    query = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days, "verbose": ""})
    url = f"https://api.abuseipdb.com/api/v2/check?{query}"
    status, data, error = http_json_request(
        url=url,
        headers={"Key": api_key, "Accept": "application/json"},
        timeout=timeout, connector_name="abuseipdb",
        max_retries=max_retries, retry_backoff_seconds=retry_backoff_seconds,
        correlation_id=correlation_id, logger=logger,
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


# ── Demo / Mock ────────────────────────────────────────────────────────────────

def _demo_seed(ioc: str) -> int:
    """Derive a deterministic integer seed from an IOC string."""
    return int(hashlib.md5(ioc.encode("utf-8")).hexdigest(), 16)


def virustotal_mock(ioc: str, ioc_type: str) -> tuple[dict[str, Any] | None, str | None]:
    """Deterministic VirusTotal mock. Same IOC always produces the same result."""
    if ioc_type not in {"ip", "domain", "url", "hash"}:
        return None, f"VirusTotal does not support IOC type '{ioc_type}'."

    seed = _demo_seed(ioc)
    rng = random.Random(seed)
    tier = seed % 4  # 0=low, 1=medium, 2=high, 3=critical

    if tier == 0:
        malicious, suspicious, harmless = rng.randint(0, 1), rng.randint(0, 2), rng.randint(55, 70)
    elif tier == 1:
        malicious, suspicious, harmless = rng.randint(2, 4), rng.randint(1, 4), rng.randint(35, 55)
    elif tier == 2:
        malicious, suspicious, harmless = rng.randint(5, 9), rng.randint(2, 6), rng.randint(10, 30)
    else:
        malicious, suspicious, harmless = rng.randint(10, 20), rng.randint(3, 8), rng.randint(0, 10)

    undetected = max(0, 72 - harmless - malicious - suspicious)
    reputation = -(malicious * 3) if malicious > 0 else rng.randint(0, 10)

    return {
        "status": 200,
        "analysis_stats": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
        },
        "reputation": reputation,
        "last_analysis_date": int(time.time()) - rng.randint(0, 86400 * 30),
        "permalink": f"https://www.virustotal.com/gui/search/{urllib.parse.quote(ioc)}",
    }, None


def abuseipdb_mock(ioc: str) -> tuple[dict[str, Any] | None, str | None]:
    """Deterministic AbuseIPDB mock. Same IOC always produces the same result."""
    seed = _demo_seed(ioc)
    rng = random.Random(seed)
    tier = seed % 4

    _countries = ["BR", "US", "CN", "RU", "DE", "NL", "UA", "KR", "IN", "FR"]
    _isps = ["Amazon AWS", "Google Cloud", "DigitalOcean", "OVH SAS", "Hetzner Online", "Cloudflare"]

    if tier == 0:
        abuse_score, total_reports = rng.randint(0, 15), rng.randint(0, 5)
    elif tier == 1:
        abuse_score, total_reports = rng.randint(20, 50), rng.randint(6, 20)
    elif tier == 2:
        abuse_score, total_reports = rng.randint(55, 80), rng.randint(21, 60)
    else:
        abuse_score, total_reports = rng.randint(85, 100), rng.randint(61, 250)

    return {
        "status": 200,
        "abuse_confidence_score": abuse_score,
        "total_reports": total_reports,
        "country_code": rng.choice(_countries),
        "usage_type": rng.choice(["Data Center/Web Hosting/Transit", "ISP", "Fixed Line ISP"]),
        "isp": rng.choice(_isps),
        "domain": f"demo-isp-{seed % 999}.net",
    }, None
