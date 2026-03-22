#!/usr/bin/env python3
"""IOC Feed Ingestion — CSV and STIX 2.1 external feed support.

Supports:
- CSVFeedIngester  : fetches a remote CSV and extracts IOCs from a configurable column.
- STIXFeedIngester : fetches a STIX 2.1 JSON bundle and parses indicator patterns.
- ingest_feeds()   : orchestrator that runs all configured feeds and passes new IOCs
                     through the SentinelCore pipeline.
- Feed status registry: in-memory store of per-URL last-poll metadata.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import re
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from mini_soar_core import RuntimeConfig, build_config_from_env, run_pipeline
from mini_soar_enrichment import http_raw_request
from mini_soar_observability import get_logger, log_event
from mini_soar_storage import create_store


# ── Constants ──────────────────────────────────────────────────────────────────

# Regex to extract value from a STIX pattern atom: [<obj>:<prop> = '<value>']
_STIX_PATTERN_RE = re.compile(
    r"\[([a-zA-Z0-9_-]+:[a-zA-Z0-9_.]+)\s*=\s*'([^']+)'\]",
    re.IGNORECASE,
)

# Map STIX object types to SentinelCore IOC types
_STIX_TYPE_MAP: dict[str, str] = {
    "ipv4-addr": "ip",
    "ipv6-addr": "ip",
    "domain-name": "domain",
    "url": "url",
    "file": "hash",
    "email-addr": "domain",  # treat email domains as domain IOC — best effort
}

# Candidate column names tried when the user-specified column is absent
_CSV_COLUMN_CANDIDATES = [
    "ioc", "indicator", "value", "observable", "ip", "domain", "url", "hash",
    "ip_address", "ipv4", "ipv6", "hostname",
]

logger = get_logger("mini_soar.feeds")


# ── Feed Status Registry ────────────────────────────────────────────────────────

@dataclass
class FeedStatus:
    url: str
    format: str = "auto"
    last_polled_at: str | None = None
    last_ioc_count: int = 0
    last_new_ioc_count: int = 0
    total_ingested: int = 0
    last_error: str | None = None
    poll_count: int = 0


_feed_registry: dict[str, FeedStatus] = {}
_registry_lock = threading.Lock()


def get_feed_statuses() -> list[dict[str, Any]]:
    """Return a snapshot of all known feed statuses."""
    with _registry_lock:
        return [
            {
                "url": s.url,
                "format": s.format,
                "last_polled_at": s.last_polled_at,
                "last_ioc_count": s.last_ioc_count,
                "last_new_ioc_count": s.last_new_ioc_count,
                "total_ingested": s.total_ingested,
                "last_error": s.last_error,
                "poll_count": s.poll_count,
            }
            for s in _feed_registry.values()
        ]


def _upsert_status(url: str, fmt: str) -> FeedStatus:
    """Get or create a FeedStatus entry (lock already held by caller)."""
    if url not in _feed_registry:
        _feed_registry[url] = FeedStatus(url=url, format=fmt)
    return _feed_registry[url]


def _utc_now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(tz=timezone.utc).isoformat()


# ── CSV Ingester ────────────────────────────────────────────────────────────────

class CSVFeedIngester:
    """Downloads a remote CSV file and extracts IOC values from a named column."""

    def __init__(
        self,
        url: str,
        ioc_column: str = "ioc",
        timeout: int = 30,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.5,
        comment_char: str = "#",
    ) -> None:
        self.url = url
        self.ioc_column = ioc_column
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds
        self.comment_char = comment_char

    def fetch_iocs(self) -> tuple[list[str], str | None]:
        """Fetch and parse the CSV. Returns (ioc_list, error_or_None)."""
        status_code, raw, error = http_raw_request(
            url=self.url,
            timeout=self.timeout,
            connector_name="csv_feed",
            max_retries=self.max_retries,
            retry_backoff_seconds=self.retry_backoff_seconds,
            logger=logger,
        )
        if error or raw is None:
            return [], error or f"HTTP {status_code}: no data"

        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            return [], f"Decode error: {exc}"

        return self._parse_csv(text)

    def _parse_csv(self, text: str) -> tuple[list[str], str | None]:
        # Strip comment lines
        lines = [ln for ln in text.splitlines() if not ln.strip().startswith(self.comment_char)]
        cleaned = "\n".join(lines)
        if not cleaned.strip():
            return [], "Feed returned empty content"

        try:
            reader = csv.DictReader(io.StringIO(cleaned))
            headers = reader.fieldnames or []
        except Exception as exc:
            return [], f"CSV parse error: {exc}"

        col = self._resolve_column(headers)
        if col is None:
            # No header row — treat each non-empty line as a bare IOC value
            bare = [ln.strip() for ln in lines if ln.strip() and not ln.strip().startswith(self.comment_char)]
            return list(dict.fromkeys(bare)), None  # deduplicate, preserve order

        iocs: list[str] = []
        for row in reader:
            val = (row.get(col) or "").strip()
            if val:
                iocs.append(val)

        return list(dict.fromkeys(iocs)), None  # deduplicate

    def _resolve_column(self, headers: list[str]) -> str | None:
        """Find the best column matching ioc_column preference or fallback candidates."""
        if not headers:
            return None
        # Exact match first
        if self.ioc_column in headers:
            return self.ioc_column
        # Case-insensitive
        lower_map = {h.lower(): h for h in headers}
        if self.ioc_column.lower() in lower_map:
            return lower_map[self.ioc_column.lower()]
        # Try candidates
        for candidate in _CSV_COLUMN_CANDIDATES:
            if candidate in lower_map:
                return lower_map[candidate]
        return None


# ── STIX Ingester ───────────────────────────────────────────────────────────────

class STIXFeedIngester:
    """Downloads a STIX 2.1 JSON bundle and extracts IOC values from indicator objects."""

    def __init__(
        self,
        url: str,
        timeout: int = 30,
        max_retries: int = 2,
        retry_backoff_seconds: float = 0.5,
    ) -> None:
        self.url = url
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff_seconds = retry_backoff_seconds

    def fetch_iocs(self) -> tuple[list[str], str | None]:
        """Fetch STIX bundle and return (ioc_list, error_or_None)."""
        status_code, raw, error = http_raw_request(
            url=self.url,
            timeout=self.timeout,
            connector_name="stix_feed",
            max_retries=self.max_retries,
            retry_backoff_seconds=self.retry_backoff_seconds,
            logger=logger,
        )
        if error or raw is None:
            return [], error or f"HTTP {status_code}: no data"

        try:
            bundle = json.loads(raw.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            return [], f"JSON parse error: {exc}"

        return self._parse_bundle(bundle)

    def _parse_bundle(self, bundle: Any) -> tuple[list[str], str | None]:
        if not isinstance(bundle, dict):
            return [], "STIX bundle is not a JSON object"

        objects = bundle.get("objects") or []
        if not isinstance(objects, list):
            return [], "STIX bundle 'objects' is not a list"

        iocs: list[str] = []
        for obj in objects:
            if not isinstance(obj, dict):
                continue
            if obj.get("type") != "indicator":
                continue
            pattern = obj.get("pattern", "")
            extracted = self._extract_ioc_from_pattern(pattern)
            if extracted:
                iocs.append(extracted)

        return list(dict.fromkeys(iocs)), None  # deduplicate

    @staticmethod
    def _extract_ioc_from_pattern(pattern: str) -> str | None:
        """Extract IOC value from a STIX pattern string."""
        match = _STIX_PATTERN_RE.search(pattern)
        if not match:
            return None
        obj_prop, value = match.group(1), match.group(2).strip()
        if not value:
            return None
        # For file hashes return just the hash value
        obj_type = obj_prop.split(":")[0].lower()
        if obj_type == "file":
            # value is the hash hex string
            return value
        return value


# ── Format Detection ────────────────────────────────────────────────────────────

def _detect_format(url: str, raw: bytes) -> str:
    """Heuristically determine feed format from content."""
    try:
        text = raw.decode("utf-8", errors="replace").strip()
    except Exception:
        return "csv"

    if text.startswith("{") or text.startswith("["):
        try:
            obj = json.loads(text)
            if isinstance(obj, dict) and obj.get("type") in {"bundle", "indicator"}:
                return "stix"
        except json.JSONDecodeError:
            pass

    return "csv"


# ── Orchestrator ────────────────────────────────────────────────────────────────

def ingest_feeds(
    urls: list[str],
    fmt: str = "auto",
    ioc_column: str = "ioc",
    config: Any = None,
    timeout: int = 30,
    max_retries: int = 2,
    retry_backoff_seconds: float = 0.5,
) -> dict[str, Any]:
    """Ingest IOCs from all given feed URLs and run them through the pipeline.

    Args:
        urls:                  List of feed URLs to poll.
        fmt:                   Feed format: "csv", "stix", or "auto".
        ioc_column:            CSV column name to use as the IOC value.
        config:                RuntimeConfig for pipeline execution.
        timeout:               HTTP timeout for feed downloads.
        max_retries:           Retry count for transient HTTP errors.
        retry_backoff_seconds: Base backoff between retries.

    Returns:
        Summary dict with per-feed stats and overall totals.
    """
    if config is None:
        config = build_config_from_env()

    store = create_store(config.database_url)

    total_new = 0
    total_iocs = 0
    feed_results: list[dict[str, Any]] = []

    for url in urls:
        polled_at = _utc_now_iso()
        iocs: list[str] = []
        error: str | None = None
        effective_fmt = fmt

        log_event(logger, logging.INFO, "feed_poll_start", url=url, format=fmt)

        if fmt == "auto":
            # Peek at the content to decide
            _, raw, fetch_err = http_raw_request(
                url=url,
                timeout=timeout,
                connector_name="feed_auto",
                max_retries=max_retries,
                retry_backoff_seconds=retry_backoff_seconds,
                logger=logger,
            )
            if fetch_err or raw is None:
                error = fetch_err or "no data"
                effective_fmt = "csv"
            else:
                effective_fmt = _detect_format(url, raw)
                # Parse inline to avoid a second download
                if effective_fmt == "stix":
                    ingester = STIXFeedIngester(url=url, timeout=timeout)
                    try:
                        bundle = json.loads(raw.decode("utf-8", errors="replace"))
                        iocs, error = ingester._parse_bundle(bundle)
                    except Exception as exc:
                        error = f"STIX parse error: {exc}"
                else:
                    text = raw.decode("utf-8", errors="replace")
                    ingester_csv = CSVFeedIngester(
                        url=url, ioc_column=ioc_column, timeout=timeout,
                        max_retries=max_retries, retry_backoff_seconds=retry_backoff_seconds,
                    )
                    iocs, error = ingester_csv._parse_csv(text)

        elif fmt == "stix":
            ingester_stix = STIXFeedIngester(
                url=url, timeout=timeout,
                max_retries=max_retries, retry_backoff_seconds=retry_backoff_seconds,
            )
            iocs, error = ingester_stix.fetch_iocs()

        else:  # csv
            ingester_csv = CSVFeedIngester(
                url=url, ioc_column=ioc_column, timeout=timeout,
                max_retries=max_retries, retry_backoff_seconds=retry_backoff_seconds,
            )
            iocs, error = ingester_csv.fetch_iocs()

        ioc_count = len(iocs)
        new_ioc_count = 0

        if iocs and not error:
            # Filter via idempotency to avoid reprocessing already-seen IOCs
            if config.enable_idempotency:
                new_iocs = [
                    ioc for ioc in iocs
                    if not store.seen_recent_ioc(ioc, window_seconds=config.idempotency_window_seconds)
                ]
            else:
                new_iocs = iocs

            new_ioc_count = len(new_iocs)
            total_new += new_ioc_count
            total_iocs += ioc_count

            if new_iocs:
                log_event(logger, logging.INFO, "feed_pipeline_start",
                          url=url, new_iocs=new_ioc_count)
                try:
                    run_pipeline(new_iocs, config=config, store=store)
                except Exception as exc:
                    error = f"Pipeline error: {exc}"
                    log_event(logger, logging.ERROR, "feed_pipeline_error", url=url, error=str(exc))
            else:
                log_event(logger, logging.INFO, "feed_no_new_iocs", url=url, ioc_count=ioc_count)
        else:
            total_iocs += ioc_count

        # Update registry
        with _registry_lock:
            status = _upsert_status(url, effective_fmt)
            status.last_polled_at = polled_at
            status.last_ioc_count = ioc_count
            status.last_new_ioc_count = new_ioc_count
            status.total_ingested += new_ioc_count
            status.last_error = error
            status.poll_count += 1

        feed_results.append({
            "url": url,
            "format": effective_fmt,
            "polled_at": polled_at,
            "ioc_count": ioc_count,
            "new_ioc_count": new_ioc_count,
            "error": error,
        })

        log_event(logger, logging.INFO, "feed_poll_done",
                  url=url, ioc_count=ioc_count, new_ioc_count=new_ioc_count,
                  error=error)

    return {
        "feeds_polled": len(urls),
        "total_iocs_found": total_iocs,
        "total_new_iocs": total_new,
        "results": feed_results,
    }


# ── Env helpers ─────────────────────────────────────────────────────────────────

def feed_urls_from_env() -> list[str]:
    """Parse MINI_SOAR_FEED_URLS into a list of non-empty URLs."""
    raw = os.getenv("MINI_SOAR_FEED_URLS", "")
    return [u.strip() for u in raw.split(",") if u.strip()]


