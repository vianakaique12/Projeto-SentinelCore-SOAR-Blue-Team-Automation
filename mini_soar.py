#!/usr/bin/env python3
"""CLI entrypoint for Mini SOAR IOC enrichment and response automation."""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import replace

from mini_soar_core import (
    INTEGRATION_CHOICES,
    TICKET_CHOICES,
    RuntimeConfig,
    build_config_from_env,
    read_iocs,
    run_pipeline,
    write_metrics_csv,
    write_report_json,
)
from mini_soar_observability import configure_logging, new_correlation_id


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Mini SOAR: IOC enrichment (VirusTotal + AbuseIPDB), ticketing and SIEM integrations"
    )
    parser.add_argument("--ioc", action="append", default=[], help="IOC value (can repeat)")
    parser.add_argument("--input", help="Path to IOC list file (one IOC per line)")
    parser.add_argument("--output", default="report.json", help="Output JSON report path")
    parser.add_argument("--metrics-csv", help="Optional CSV export path for findings metrics")
    parser.add_argument("--interactive", action="store_true", help="Run in interactive didactic mode")

    parser.add_argument("--vt-api-key", help="VirusTotal API key")
    parser.add_argument("--abuse-api-key", help="AbuseIPDB API key")
    parser.add_argument("--abuse-max-age", type=int, help="AbuseIPDB maxAgeInDays")
    parser.add_argument("--max-retries", type=int, help="Max retries for connector requests")
    parser.add_argument("--retry-backoff-seconds", type=float, help="Base backoff seconds between retries")

    parser.add_argument("--ticket-backend", choices=sorted(TICKET_CHOICES), help="Ticket backend")
    parser.add_argument("--ticket-file", help="Path for file backend")
    parser.add_argument("--ticket-threshold", type=int, help="Open ticket if score >= threshold")

    parser.add_argument("--webhook-url", help="Webhook URL for ticket backend 'webhook'")
    parser.add_argument("--webhook-token", help="Bearer token for webhook")

    parser.add_argument("--jira-base-url", help="Jira base URL, e.g. https://company.atlassian.net")
    parser.add_argument("--jira-email", help="Jira user email")
    parser.add_argument("--jira-api-token", help="Jira API token")
    parser.add_argument("--jira-project-key", help="Jira project key")
    parser.add_argument("--jira-issue-type", help="Jira issue type (default: Task)")

    parser.add_argument(
        "--integration-target",
        action="append",
        default=[],
        help="Forward findings to integration plugin target (can repeat)",
    )
    parser.add_argument("--integration-threshold", type=int, help="Forward if score >= threshold")

    parser.add_argument("--thehive-url", help="TheHive base URL")
    parser.add_argument("--thehive-api-key", help="TheHive API key")
    parser.add_argument("--thehive-alert-type", help="TheHive alert type (default: external)")
    parser.add_argument("--thehive-tlp", type=int, help="TheHive TLP")
    parser.add_argument("--thehive-pap", type=int, help="TheHive PAP")

    parser.add_argument("--splunk-hec-url", help="Splunk HEC base URL")
    parser.add_argument("--splunk-hec-token", help="Splunk HEC token")
    parser.add_argument("--splunk-sourcetype", help="Splunk sourcetype")

    parser.add_argument("--sentinel-workspace-id", help="Microsoft Sentinel workspace id")
    parser.add_argument("--sentinel-shared-key", help="Microsoft Sentinel shared key")
    parser.add_argument("--sentinel-log-type", help="Microsoft Sentinel Log-Type")
    parser.add_argument("--sentinel-endpoint", help="Custom Sentinel endpoint override")

    parser.add_argument("--timeout", type=int, help="HTTP timeout in seconds")
    parser.add_argument("--vt-timeout", type=int, help="VirusTotal timeout in seconds")
    parser.add_argument("--abuse-timeout", type=int, help="AbuseIPDB timeout in seconds")
    parser.add_argument("--integration-timeout", type=int, help="Integration/ticket timeout in seconds")
    parser.add_argument("--sleep", type=float, help="Sleep between IOCs (seconds)")
    parser.add_argument("--database-url", help="Storage URL (sqlite:///mini_soar.db)")
    parser.add_argument("--idempotency-window-seconds", type=int, help="Idempotency window in seconds")
    parser.add_argument("--disable-idempotency", action="store_true", help="Disable IOC idempotency filter")
    parser.add_argument("--disable-persistence", action="store_true", help="Disable persistence store")
    parser.add_argument("--log-level", help="Log level (DEBUG, INFO, WARNING, ERROR)")
    parser.add_argument("--plain-logs", action="store_true", help="Use plain-text logs instead of JSON logs")
    return parser.parse_args()


def choose(value: object, fallback: object) -> object:
    return fallback if value is None else value


def prompt_text(message: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{message}{suffix}: ").strip()
    if not value and default is not None:
        return default
    return value


def prompt_int(message: str, default: int) -> int:
    while True:
        raw = prompt_text(message, str(default))
        try:
            value = int(raw)
        except ValueError:
            print("[WARN] Please enter a valid integer.")
            continue
        if value < 0:
            print("[WARN] Please enter a non-negative integer.")
            continue
        return value


def prompt_menu_choice(message: str, options: list[str], default: str) -> str:
    option_map = {str(index): value for index, value in enumerate(options, start=1)}
    default_index = "1"
    for key, value in option_map.items():
        if value == default:
            default_index = key
            break

    print(f"\n{message}")
    for key, value in option_map.items():
        print(f"  {key}) {value}")

    while True:
        raw = prompt_text("Choose an option number", default_index)
        chosen = option_map.get(raw)
        if chosen:
            return chosen
        print(f"[WARN] Invalid option. Choose one of: {', '.join(option_map.keys())}")


def prompt_menu_multi_select(message: str, options: list[str], default_selected: tuple[str, ...]) -> tuple[str, ...]:
    option_map = {str(index): value for index, value in enumerate(options, start=1)}
    default_raw = ",".join(
        key for key, value in option_map.items() if value in set(default_selected)
    ) or "0"

    print(f"\n{message}")
    print("  0) none")
    for key, value in option_map.items():
        print(f"  {key}) {value}")
    print("  Example: 1,3")

    while True:
        raw = prompt_text("Choose option number(s) comma-separated", default_raw).strip()
        if raw in {"", "0", "none"}:
            return ()

        parts = [item.strip() for item in raw.split(",") if item.strip()]
        invalid = [item for item in parts if item not in option_map]
        if invalid:
            print(f"[WARN] Invalid option number(s): {', '.join(invalid)}")
            continue

        selected = tuple(sorted({option_map[item] for item in parts}))
        return selected


def print_ioc_examples() -> None:
    print("\n[Interactive] IOC examples:")
    print("  - IP: 8.8.8.8")
    print("  - Domain: example.com")
    print("  - URL: http://example.com/login")
    print("  - Hash (MD5/SHA1/SHA256): d41d8cd98f00b204e9800998ecf8427e")


def prompt_iocs(default_iocs: list[str]) -> list[str]:
    print_ioc_examples()
    print("\n[Interactive] Add IOC(s). Press Enter on empty line to finish.")
    iocs: list[str] = []
    index = 1
    while True:
        value = input(f"IOC #{index}: ").strip()
        if not value:
            break
        iocs.append(value)
        index += 1

    if iocs:
        return read_iocs(None, iocs)
    if default_iocs:
        print("[Interactive] No IOC typed. Using IOC(s) from --ioc/--input.")
        return default_iocs
    return []


def run_interactive_mode(
    args: argparse.Namespace, config: RuntimeConfig, default_iocs: list[str]
) -> tuple[list[str], RuntimeConfig, str, str | None]:
    print("[Interactive] Mini SOAR didactic mode")
    print("[Interactive] This mode is for manual learning/demo; CLI/API automation remains unchanged.")

    iocs = prompt_iocs(default_iocs)
    if not iocs:
        return [], config, args.output, args.metrics_csv

    ticket_backend = prompt_menu_choice(
        "Ticket backend",
        sorted(TICKET_CHOICES),
        config.ticket_backend,
    )
    ticket_threshold = prompt_int("Ticket threshold (open ticket if score >=)", config.ticket_threshold)
    integration_targets = prompt_menu_multi_select(
        "Integration targets",
        sorted(INTEGRATION_CHOICES),
        config.integration_targets,
    )
    integration_threshold = prompt_int("Integration threshold (forward if score >=)", config.integration_threshold)

    output = prompt_text("JSON output report path", args.output)
    metrics_default = args.metrics_csv or ""
    metrics_csv_raw = prompt_text("CSV metrics output path (empty to disable)", metrics_default)
    metrics_csv = metrics_csv_raw or None

    updated_config = replace(
        config,
        ticket_backend=ticket_backend,
        ticket_threshold=ticket_threshold,
        integration_targets=integration_targets,
        integration_threshold=integration_threshold,
    )
    return iocs, updated_config, output, metrics_csv


def build_runtime_config(args: argparse.Namespace) -> RuntimeConfig:
    env_cfg = build_config_from_env()

    integration_targets = tuple(args.integration_target) if args.integration_target else env_cfg.integration_targets

    return RuntimeConfig(
        vt_api_key=choose(args.vt_api_key, env_cfg.vt_api_key),
        abuse_api_key=choose(args.abuse_api_key, env_cfg.abuse_api_key),
        abuse_max_age=int(choose(args.abuse_max_age, env_cfg.abuse_max_age)),
        timeout=int(choose(args.timeout, env_cfg.timeout)),
        vt_timeout=int(choose(args.vt_timeout, env_cfg.vt_timeout or env_cfg.timeout)),
        abuse_timeout=int(choose(args.abuse_timeout, env_cfg.abuse_timeout or env_cfg.timeout)),
        integration_timeout=int(choose(args.integration_timeout, env_cfg.integration_timeout or env_cfg.timeout)),
        sleep=float(choose(args.sleep, env_cfg.sleep)),
        max_retries=int(choose(args.max_retries, env_cfg.max_retries)),
        retry_backoff_seconds=float(choose(args.retry_backoff_seconds, env_cfg.retry_backoff_seconds)),
        ticket_backend=str(choose(args.ticket_backend, env_cfg.ticket_backend)),
        ticket_file=str(choose(args.ticket_file, env_cfg.ticket_file)),
        ticket_threshold=int(choose(args.ticket_threshold, env_cfg.ticket_threshold)),
        webhook_url=choose(args.webhook_url, env_cfg.webhook_url),
        webhook_token=choose(args.webhook_token, env_cfg.webhook_token),
        jira_base_url=choose(args.jira_base_url, env_cfg.jira_base_url),
        jira_email=choose(args.jira_email, env_cfg.jira_email),
        jira_api_token=choose(args.jira_api_token, env_cfg.jira_api_token),
        jira_project_key=choose(args.jira_project_key, env_cfg.jira_project_key),
        jira_issue_type=str(choose(args.jira_issue_type, env_cfg.jira_issue_type)),
        integration_targets=tuple(integration_targets),
        integration_threshold=int(choose(args.integration_threshold, env_cfg.integration_threshold)),
        thehive_url=choose(args.thehive_url, env_cfg.thehive_url),
        thehive_api_key=choose(args.thehive_api_key, env_cfg.thehive_api_key),
        thehive_alert_type=str(choose(args.thehive_alert_type, env_cfg.thehive_alert_type)),
        thehive_tlp=int(choose(args.thehive_tlp, env_cfg.thehive_tlp)),
        thehive_pap=int(choose(args.thehive_pap, env_cfg.thehive_pap)),
        splunk_hec_url=choose(args.splunk_hec_url, env_cfg.splunk_hec_url),
        splunk_hec_token=choose(args.splunk_hec_token, env_cfg.splunk_hec_token),
        splunk_sourcetype=str(choose(args.splunk_sourcetype, env_cfg.splunk_sourcetype)),
        sentinel_workspace_id=choose(args.sentinel_workspace_id, env_cfg.sentinel_workspace_id),
        sentinel_shared_key=choose(args.sentinel_shared_key, env_cfg.sentinel_shared_key),
        sentinel_log_type=str(choose(args.sentinel_log_type, env_cfg.sentinel_log_type)),
        sentinel_endpoint=choose(args.sentinel_endpoint, env_cfg.sentinel_endpoint),
        enable_idempotency=False if args.disable_idempotency else env_cfg.enable_idempotency,
        idempotency_window_seconds=int(
            choose(args.idempotency_window_seconds, env_cfg.idempotency_window_seconds)
        ),
        database_url=str(choose(args.database_url, env_cfg.database_url)),
        persist_findings=False if args.disable_persistence else env_cfg.persist_findings,
        log_level=str(choose(args.log_level, env_cfg.log_level)),
        json_logs=False if args.plain_logs else env_cfg.json_logs,
    )


def main() -> int:
    args = parse_args()
    config = build_runtime_config(args)
    configure_logging(level=config.log_level, json_logs=config.json_logs)
    iocs = read_iocs(args.input, args.ioc)
    output_path = args.output
    metrics_csv_path = args.metrics_csv

    if args.interactive:
        iocs, config, output_path, metrics_csv_path = run_interactive_mode(args, config, iocs)

    if not iocs:
        print("[ERROR] No IOCs provided. Use --ioc and/or --input.", file=sys.stderr)
        return 2

    if not config.vt_api_key and not config.abuse_api_key:
        print("[WARN] No API keys provided. Enrichment providers will not return data.", file=sys.stderr)

    correlation_id = os.getenv("MINI_SOAR_CORRELATION_ID", new_correlation_id())
    report = run_pipeline(iocs=iocs, config=config, progress=True, correlation_id=correlation_id)
    write_report_json(report, output_path)

    if metrics_csv_path:
        write_metrics_csv(report, metrics_csv_path)
        print(f"[OK] Metrics CSV written to: {metrics_csv_path}")

    print(f"\n[OK] Report written to: {output_path}")
    print(
        "[OK] Summary: "
        f"iocs={report['summary']['total_iocs']}, "
        f"tickets={report['summary']['tickets_opened']}, "
        f"integrations={report['summary']['integration_success']}/"
        f"{report['summary']['integration_attempts']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
