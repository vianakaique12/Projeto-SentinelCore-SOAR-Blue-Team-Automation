#!/usr/bin/env python3
"""Logging and metrics helpers for Mini SOAR."""

from __future__ import annotations

import json
import logging
import time
import uuid
from typing import Any

try:
    from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
except ModuleNotFoundError:  # Optional runtime dependency for metrics.
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4"

    class _NoopMetric:
        def labels(self, **_: Any) -> "_NoopMetric":
            return self

        def inc(self, amount: float = 1.0) -> None:
            return None

        def observe(self, value: float) -> None:
            return None

    def Counter(*_: Any, **__: Any) -> _NoopMetric:  # type: ignore[misc]
        return _NoopMetric()

    def Histogram(*_: Any, **__: Any) -> _NoopMetric:  # type: ignore[misc]
        return _NoopMetric()

    def generate_latest() -> bytes:
        return b"# prometheus_client not installed\n"


PIPELINE_RUNS_TOTAL = Counter(
    "mini_soar_pipeline_runs_total",
    "Total number of pipeline runs",
    ["status"],
)
IOCS_PROCESSED_TOTAL = Counter(
    "mini_soar_iocs_processed_total",
    "Total number of IOCs processed",
    ["ioc_type", "priority"],
)
CONNECTOR_REQUESTS_TOTAL = Counter(
    "mini_soar_connector_requests_total",
    "Connector requests",
    ["connector", "status"],
)
CONNECTOR_LATENCY_SECONDS = Histogram(
    "mini_soar_connector_latency_seconds",
    "Connector request latency in seconds",
    ["connector"],
)
PIPELINE_DURATION_SECONDS = Histogram(
    "mini_soar_pipeline_duration_seconds",
    "Pipeline duration in seconds",
)
API_REQUESTS_TOTAL = Counter(
    "mini_soar_api_requests_total",
    "API requests total",
    ["endpoint", "status"],
)
RATE_LIMIT_HITS_TOTAL = Counter(
    "mini_soar_rate_limit_hits_total",
    "Total rate limit blocks",
    ["scope"],
)


class JsonLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created)),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for field in [
            "event",
            "correlation_id",
            "ioc",
            "ioc_type",
            "risk_score",
            "priority",
            "connector",
            "endpoint",
            "subject",
            "status_code",
            "duration_ms",
            "error",
        ]:
            value = getattr(record, field, None)
            if value is not None:
                payload[field] = value
        return json.dumps(payload, ensure_ascii=False)


def configure_logging(level: str = "INFO", json_logs: bool = True) -> None:
    root = logging.getLogger()
    root.handlers.clear()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))

    handler = logging.StreamHandler()
    if json_logs:
        handler.setFormatter(JsonLogFormatter())
    else:
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    root.addHandler(handler)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def new_correlation_id() -> str:
    return uuid.uuid4().hex


def log_event(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    logger.log(level, event, extra={"event": event, **fields})


def prometheus_payload() -> tuple[bytes, str]:
    return generate_latest(), CONTENT_TYPE_LATEST
