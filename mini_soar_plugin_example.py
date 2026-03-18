#!/usr/bin/env python3
"""Example external integration plugin for Mini SOAR."""

from __future__ import annotations

import json
from typing import Any

from mini_soar_core import IntegrationResult, RuntimeConfig, register_integration_plugin, utc_now_iso


def _example_sink(
    config: RuntimeConfig,
    finding: dict[str, Any],
    correlation_id: str | None = None,
    logger: Any | None = None,
) -> IntegrationResult:
    path = "plugin_example_events.jsonl"
    record = {
        "created_at": utc_now_iso(),
        "correlation_id": correlation_id,
        "ioc": finding.get("ioc"),
        "ioc_type": finding.get("ioc_type"),
        "priority": finding.get("priority"),
        "risk_score": finding.get("risk_score"),
        "source": "example_plugin",
    }
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")
    return IntegrationResult(target="example_sink", ok=True, reference=path)


register_integration_plugin("example_sink", _example_sink)

