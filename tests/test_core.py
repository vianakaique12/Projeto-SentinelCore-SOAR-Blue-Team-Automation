from __future__ import annotations

import os

from mini_soar_core import RuntimeConfig, run_pipeline


def test_pipeline_adds_mitre_and_runbook(tmp_path):
    db_path = tmp_path / "mini_soar_test.db"
    config = RuntimeConfig(
        ticket_backend="none",
        database_url=f"sqlite:///{db_path}",
        persist_findings=True,
    )

    report = run_pipeline(["8.8.8.8"], config=config, progress=False, correlation_id="test-correlation")
    assert report["summary"]["total_iocs"] == 1
    finding = report["findings"][0]
    assert finding["ioc_type"] == "ip"
    assert isinstance(finding["mitre_attack"], list) and len(finding["mitre_attack"]) >= 1
    assert isinstance(finding["runbook_steps"], list) and len(finding["runbook_steps"]) >= 1


def test_pipeline_idempotency_skip(tmp_path):
    db_path = tmp_path / "mini_soar_idempotency.db"
    config = RuntimeConfig(
        ticket_backend="none",
        database_url=f"sqlite:///{db_path}",
        enable_idempotency=True,
        idempotency_window_seconds=3600,
        persist_findings=True,
    )

    first = run_pipeline(["example.com"], config=config, progress=False)
    second = run_pipeline(["example.com"], config=config, progress=False)
    assert first["findings"][0]["skipped"] is False
    assert second["findings"][0]["skipped"] is True
    assert second["summary"]["skipped_by_idempotency"] == 1


def test_external_plugin_loading(tmp_path, monkeypatch):
    db_path = tmp_path / "mini_soar_plugin.db"
    monkeypatch.setenv("MINI_SOAR_PLUGIN_MODULES", "mini_soar_plugin_example")
    try:
        config = RuntimeConfig(
            ticket_backend="none",
            database_url=f"sqlite:///{db_path}",
            persist_findings=False,
            enable_idempotency=False,
            integration_targets=("example_sink",),
            integration_threshold=0,
        )
        report = run_pipeline(["1.1.1.1"], config=config, progress=False)
    finally:
        monkeypatch.delenv("MINI_SOAR_PLUGIN_MODULES", raising=False)

    finding = report["findings"][0]
    assert finding["integrations"], "Expected plugin integration result."
    assert finding["integrations"][0]["target"] == "example_sink"
    assert finding["integrations"][0]["ok"] is True

    if os.path.exists("plugin_example_events.jsonl"):
        os.remove("plugin_example_events.jsonl")

