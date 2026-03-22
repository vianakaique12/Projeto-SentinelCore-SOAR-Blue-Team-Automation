#!/usr/bin/env python3
"""FastAPI service wrapper for Mini SOAR."""

from __future__ import annotations

import csv
import io
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, Response, StreamingResponse
from pydantic import BaseModel, Field, field_validator, model_validator

from mini_soar_core import RuntimeConfig, build_config_from_env, read_iocs, run_pipeline
from mini_soar_feeds import feed_urls_from_env, get_feed_statuses, ingest_feeds
from mini_soar_health import run_health_checks
from mini_soar_storage import create_store
from mini_soar_observability import (
    API_REQUESTS_TOTAL,
    RATE_LIMIT_HITS_TOTAL,
    configure_logging,
    get_logger,
    log_event,
    new_correlation_id,
    prometheus_payload,
)
from mini_soar_queue import enqueue_iocs_job, get_job_status
from mini_soar_rate_limit import get_rate_limiter

try:
    import jwt
except ModuleNotFoundError:  # Optional dependency
    jwt = None  # type: ignore[assignment]


configure_logging(
    level=os.getenv("MINI_SOAR_LOG_LEVEL", "INFO"),
    json_logs=os.getenv("MINI_SOAR_JSON_LOGS", "true").lower() == "true",
)
logger = get_logger("mini_soar.api")


class AnalyzeRequest(BaseModel):
    ioc: str | None = Field(default=None, description="Single IOC", max_length=4096)
    iocs: list[str] = Field(default_factory=list, description="List of IOCs", max_length=200)
    ticket_backend: Literal["none", "file", "webhook", "jira"] | None = None
    ticket_threshold: int | None = Field(default=None, ge=0, le=100)
    integration_targets: list[Literal["thehive", "splunk", "sentinel"]] = Field(default_factory=list, max_length=10)
    integration_threshold: int | None = Field(default=None, ge=0, le=100)
    timeout: int | None = Field(default=None, ge=1, le=120)
    max_retries: int | None = Field(default=None, ge=0, le=10)

    @field_validator("ioc")
    @classmethod
    def validate_ioc(cls, value: str | None) -> str | None:
        if value is None:
            return value
        cleaned = value.strip()
        if not cleaned:
            raise ValueError("IOC cannot be blank.")
        return cleaned

    @field_validator("iocs")
    @classmethod
    def validate_iocs(cls, value: list[str]) -> list[str]:
        cleaned = [item.strip() for item in value if item and item.strip()]
        if len(cleaned) > 200:
            raise ValueError("Maximum 200 IOCs per request.")
        return cleaned

    @model_validator(mode="after")
    def validate_has_ioc(self) -> "AnalyzeRequest":
        if not self.ioc and not self.iocs:
            raise ValueError("Provide at least one IOC in 'ioc' or 'iocs'.")
        return self


class AnalyzeAsyncRequest(AnalyzeRequest):
    pass


class AnalyzeResponse(BaseModel):
    generated_at: str
    correlation_id: str | None = None
    summary: dict
    findings: list[dict]


class AsyncAcceptedResponse(BaseModel):
    job_id: str
    status: str
    correlation_id: str


class FindingsResponse(BaseModel):
    total: int
    limit: int
    offset: int
    findings: list[dict]


class FeedIngestRequest(BaseModel):
    urls: list[str] = Field(
        default_factory=list,
        description="Feed URLs to ingest. If empty, uses MINI_SOAR_FEED_URLS env var.",
        max_length=50,
    )
    format: Literal["csv", "stix", "auto"] = Field(
        default="auto",
        description="Feed format: csv | stix | auto (default: auto).",
    )
    ioc_column: str = Field(
        default="ioc",
        description="CSV column name containing the IOC value (csv format only).",
        max_length=128,
    )

    @field_validator("urls")
    @classmethod
    def validate_urls(cls, value: list[str]) -> list[str]:
        cleaned = [u.strip() for u in value if u.strip()]
        return cleaned


def choose(value: object, fallback: object) -> object:
    return fallback if value is None else value


def _rate_limit_settings() -> tuple[int, int]:
    limit  = int(os.getenv("MINI_SOAR_API_RATE_LIMIT", "60"))
    window = int(os.getenv("MINI_SOAR_API_RATE_WINDOW_SECONDS", "60"))
    return limit, window


# Instantiated once at startup; backend is selected by env vars.
_rate_limiter = get_rate_limiter()


def enforce_rate_limit(request: Request) -> None:
    limit, window = _rate_limit_settings()
    client_id = request.client.host if request.client else "unknown"
    if not _rate_limiter.is_allowed(client_id, limit, window):
        RATE_LIMIT_HITS_TOTAL.labels(scope="api").inc()
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded. Max {limit} requests per {window}s.",
        )


def _allowed_api_keys() -> set[str]:
    raw = os.getenv("MINI_SOAR_API_KEYS", "")
    return {item.strip() for item in raw.split(",") if item.strip()}


def _jwt_secret() -> str | None:
    secret = os.getenv("MINI_SOAR_JWT_SECRET")
    return secret.strip() if secret else None


def _require_auth() -> bool:
    return os.getenv("MINI_SOAR_REQUIRE_AUTH", "false").lower() == "true"


def _validate_jwt(token: str) -> dict[str, Any]:
    secret = _jwt_secret()
    if not secret:
        raise HTTPException(status_code=401, detail="JWT auth not configured.")
    if jwt is None:
        raise HTTPException(status_code=500, detail="PyJWT not installed on server.")
    try:
        payload = jwt.decode(token, secret, algorithms=["HS256"])  # type: ignore[union-attr]
        if not isinstance(payload, dict):
            raise HTTPException(status_code=401, detail="Invalid JWT payload.")
        return payload
    except Exception as exc:  # noqa: BLE001 - keep concise auth error boundary
        raise HTTPException(status_code=401, detail=f"Invalid JWT: {exc}") from exc


def authorize_request(
    request: Request,
    x_api_key: str | None = Header(default=None),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    require_auth = _require_auth()
    allowed_keys = _allowed_api_keys()
    has_any_auth_config = bool(allowed_keys or _jwt_secret())

    if not require_auth and not has_any_auth_config:
        return {"subject": "anonymous", "auth_mode": "none"}

    if x_api_key and x_api_key in allowed_keys:
        return {"subject": "api_key_user", "auth_mode": "api_key"}

    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        claims = _validate_jwt(token)
        return {"subject": str(claims.get("sub", "jwt_user")), "auth_mode": "jwt"}

    raise HTTPException(status_code=401, detail="Unauthorized. Provide valid API key or JWT.")


def build_runtime_config_from_request(request: AnalyzeRequest) -> RuntimeConfig:
    env_cfg = build_config_from_env()
    integration_targets = tuple(request.integration_targets) if request.integration_targets else env_cfg.integration_targets
    return RuntimeConfig(
        vt_api_key=env_cfg.vt_api_key,
        abuse_api_key=env_cfg.abuse_api_key,
        abuse_max_age=env_cfg.abuse_max_age,
        timeout=int(choose(request.timeout, env_cfg.timeout)),
        sleep=0.0,
        max_retries=int(choose(request.max_retries, env_cfg.max_retries)),
        retry_backoff_seconds=env_cfg.retry_backoff_seconds,
        ticket_backend=str(choose(request.ticket_backend, env_cfg.ticket_backend)),
        ticket_file=env_cfg.ticket_file,
        ticket_threshold=int(choose(request.ticket_threshold, env_cfg.ticket_threshold)),
        webhook_url=env_cfg.webhook_url,
        webhook_token=env_cfg.webhook_token,
        jira_base_url=env_cfg.jira_base_url,
        jira_email=env_cfg.jira_email,
        jira_api_token=env_cfg.jira_api_token,
        jira_project_key=env_cfg.jira_project_key,
        jira_issue_type=env_cfg.jira_issue_type,
        integration_targets=integration_targets,
        integration_threshold=int(choose(request.integration_threshold, env_cfg.integration_threshold)),
        thehive_url=env_cfg.thehive_url,
        thehive_api_key=env_cfg.thehive_api_key,
        thehive_alert_type=env_cfg.thehive_alert_type,
        thehive_tlp=env_cfg.thehive_tlp,
        thehive_pap=env_cfg.thehive_pap,
        splunk_hec_url=env_cfg.splunk_hec_url,
        splunk_hec_token=env_cfg.splunk_hec_token,
        splunk_sourcetype=env_cfg.splunk_sourcetype,
        sentinel_workspace_id=env_cfg.sentinel_workspace_id,
        sentinel_shared_key=env_cfg.sentinel_shared_key,
        sentinel_log_type=env_cfg.sentinel_log_type,
        sentinel_endpoint=env_cfg.sentinel_endpoint,
        enable_idempotency=env_cfg.enable_idempotency,
        idempotency_window_seconds=env_cfg.idempotency_window_seconds,
        database_url=env_cfg.database_url,
        persist_findings=env_cfg.persist_findings,
        log_level=env_cfg.log_level,
        json_logs=env_cfg.json_logs,
        greynoise_api_key=env_cfg.greynoise_api_key,
        greynoise_timeout=env_cfg.greynoise_timeout,
        shodan_api_key=env_cfg.shodan_api_key,
        shodan_timeout=env_cfg.shodan_timeout,
        otx_api_key=env_cfg.otx_api_key,
        otx_timeout=env_cfg.otx_timeout,
    )


_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>SentinelCore SOAR · Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
:root{
  --bg:#0d1117;--surface:#161b22;--surface2:#1c2128;--border:#30363d;
  --accent:#58a6ff;--accent2:#3fb950;--warn:#d29922;--danger:#f85149;
  --text:#e6edf3;--muted:#8b949e;
  --clr-low:#3fb950;--clr-medium:#d29922;--clr-high:#f85149;--clr-critical:#ff6b6b;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh}
a{color:var(--accent);text-decoration:none}

/* ── Header ── */
header{
  background:var(--surface);border-bottom:1px solid var(--border);
  padding:14px 28px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;
}
.logo{font-size:20px;font-weight:700;color:var(--accent);letter-spacing:1px}
.logo span{color:var(--text);font-weight:300}
.header-right{margin-left:auto;display:flex;align-items:center;gap:16px;flex-wrap:wrap}
.health-pill{
  display:flex;align-items:center;gap:7px;
  background:var(--surface2);border:1px solid var(--border);
  border-radius:20px;padding:5px 14px;font-size:12px;
}
.dot{width:8px;height:8px;border-radius:50%;background:var(--muted)}
.dot.healthy{background:var(--accent2);box-shadow:0 0 5px var(--accent2)}
.dot.degraded{background:var(--warn);box-shadow:0 0 5px var(--warn)}
.dot.unhealthy{background:var(--danger);box-shadow:0 0 5px var(--danger)}
.demo-badge{
  background:#2d2208;border:1px solid #5c4408;color:var(--warn);
  border-radius:20px;padding:4px 12px;font-size:11px;font-weight:700;letter-spacing:.5px;
}
.export-btn{
  background:var(--surface2);border:1px solid var(--border);color:var(--text);
  border-radius:8px;padding:6px 14px;font-size:12px;cursor:pointer;
  display:flex;align-items:center;gap:6px;transition:border-color .2s;
}
.export-btn:hover{border-color:var(--accent)}

/* ── Layout ── */
main{max-width:1200px;margin:0 auto;padding:28px 24px}

/* ── Auth bar ── */
.auth-bar{
  background:var(--surface2);border:1px solid var(--border);border-radius:10px;
  padding:12px 16px;margin-bottom:20px;display:flex;align-items:center;
  gap:10px;flex-wrap:wrap;font-size:13px;
}
.auth-bar label{color:var(--muted);white-space:nowrap}
.auth-bar input{
  flex:1;min-width:180px;background:var(--bg);border:1px solid var(--border);
  border-radius:6px;color:var(--text);font-size:13px;padding:6px 10px;outline:none;
}
.auth-bar input:focus{border-color:var(--accent)}
.auth-bar input::placeholder{color:var(--muted)}
.btn-sm{
  background:var(--accent);color:#0d1117;border:none;border-radius:6px;
  padding:6px 14px;font-size:12px;font-weight:700;cursor:pointer;white-space:nowrap;
}
.btn-sm:hover{opacity:.85}

/* ── Summary cards ── */
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:14px;margin-bottom:28px}
.card{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;
  padding:18px 20px;transition:border-color .2s;
}
.card:hover{border-color:var(--accent)}
.card .lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.card .val{font-size:30px;font-weight:700;margin-top:6px;line-height:1}
.card .sub{font-size:11px;color:var(--muted);margin-top:4px}

/* ── Section header ── */
.section-hdr{
  display:flex;align-items:center;gap:12px;margin-bottom:16px;flex-wrap:wrap;
}
.section-hdr h2{font-size:13px;color:var(--muted);text-transform:uppercase;letter-spacing:1px}
.section-hdr .spacer{flex:1}

/* ── Charts ── */
.charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(280px,1fr));gap:18px;margin-bottom:28px}
.chart-card{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:20px;
}
.chart-card h3{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-bottom:14px}
.chart-wrap{position:relative;height:220px}

/* ── Filters ── */
.filters{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
select{
  background:var(--surface2);border:1px solid var(--border);border-radius:6px;
  color:var(--text);font-size:13px;padding:7px 10px;outline:none;cursor:pointer;
}
select:focus{border-color:var(--accent)}

/* ── Table ── */
.table-wrap{
  background:var(--surface);border:1px solid var(--border);border-radius:10px;overflow:hidden;
}
table{width:100%;border-collapse:collapse}
thead th{
  background:var(--surface2);font-size:11px;font-weight:600;
  color:var(--muted);text-transform:uppercase;letter-spacing:.8px;
  padding:12px 16px;text-align:left;border-bottom:1px solid var(--border);
}
tbody tr{cursor:pointer;transition:background .15s;border-bottom:1px solid var(--border)}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:var(--surface2)}
tbody td{padding:11px 16px;font-size:13px;vertical-align:middle}
.ioc-cell{font-family:monospace;font-size:13px;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}

/* ── Badges ── */
.badge{display:inline-block;padding:2px 9px;border-radius:12px;font-size:11px;font-weight:700;text-transform:uppercase}
.b-low    {background:#0d2018;color:var(--clr-low);   border:1px solid #1a4a2a}
.b-medium {background:#2d2208;color:var(--clr-medium);border:1px solid #5c4408}
.b-high   {background:#2d0f0e;color:var(--clr-high);  border:1px solid #6b1a18}
.b-critical{background:#2d0505;color:var(--clr-critical);border:1px solid #7a0a0a}
.b-type   {background:#1c2d3d;color:var(--accent);    border:1px solid #1f4f7f}

/* ── Score bar ── */
.sbar{display:inline-flex;align-items:center;gap:6px;min-width:90px}
.sbar-bg{flex:1;height:5px;background:var(--border);border-radius:3px;overflow:hidden;width:52px}
.sbar-fill{height:100%;border-radius:3px}
.sbar-num{font-size:12px;font-weight:700;width:26px;text-align:right}

/* ── Pagination ── */
.pagination{display:flex;align-items:center;gap:10px;padding:14px 16px;border-top:1px solid var(--border);justify-content:flex-end}
.pg-btn{
  background:var(--surface2);border:1px solid var(--border);color:var(--text);
  border-radius:6px;padding:5px 12px;font-size:12px;cursor:pointer;
}
.pg-btn:disabled{opacity:.35;cursor:not-allowed}
.pg-btn:not(:disabled):hover{border-color:var(--accent)}
.pg-info{font-size:12px;color:var(--muted)}

/* ── Modal ── */
.modal-overlay{
  display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:1000;
  align-items:center;justify-content:center;padding:16px;
}
.modal-overlay.open{display:flex}
.modal{
  background:var(--surface);border:1px solid var(--border);border-radius:14px;
  width:100%;max-width:680px;max-height:90vh;overflow-y:auto;
}
.modal-hdr{
  padding:18px 24px;border-bottom:1px solid var(--border);
  display:flex;align-items:flex-start;gap:12px;
}
.modal-hdr .ioc-big{font-family:monospace;font-size:16px;font-weight:700;flex:1;word-break:break-all}
.close-btn{
  background:none;border:none;color:var(--muted);font-size:20px;cursor:pointer;line-height:1;
  padding:0 4px;
}
.close-btn:hover{color:var(--text)}
.modal-body{padding:20px 24px}
.mrow{margin-bottom:16px}
.mrow .mlbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px}
.reason-item{
  background:var(--surface2);border-left:3px solid var(--warn);
  border-radius:4px;padding:6px 10px;font-size:13px;margin-bottom:5px;
}
.mitre-tag{
  display:inline-block;background:#1a1f2e;border:1px solid #2d3a5c;color:#79b8ff;
  font-size:11px;padding:3px 9px;border-radius:5px;margin:2px;font-family:monospace;
}
.source-tag{
  display:inline-block;background:var(--surface2);border:1px solid var(--border);
  color:var(--accent2);font-size:11px;padding:3px 9px;border-radius:5px;margin:2px;
}
.kv-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}
.kv{background:var(--surface2);border-radius:6px;padding:8px 12px;font-size:12px}
.kv .k{color:var(--muted);margin-bottom:2px}
.kv .v{font-weight:600;word-break:break-all}

/* ── Empty / Loading ── */
.empty{text-align:center;padding:48px 20px;color:var(--muted);font-size:14px}
.empty .ico{font-size:40px;margin-bottom:12px}
.loading{text-align:center;padding:40px;color:var(--muted)}
.spin{
  display:inline-block;width:24px;height:24px;border:2px solid var(--border);
  border-top-color:var(--accent);border-radius:50%;animation:rot .7s linear infinite;
  margin-bottom:8px;
}
@keyframes rot{to{transform:rotate(360deg)}}
.err-box{
  background:#2d0f0e;border:1px solid #6b1a18;color:var(--danger);
  border-radius:8px;padding:12px 16px;font-size:13px;margin-bottom:16px;
}

footer{
  text-align:center;padding:28px;color:var(--muted);font-size:12px;
  border-top:1px solid var(--border);margin-top:40px;
}
@media(max-width:600px){
  .charts-grid{grid-template-columns:1fr}
  main{padding:16px}
  thead th:nth-child(4),tbody td:nth-child(4),
  thead th:nth-child(5),tbody td:nth-child(5){display:none}
}
</style>
</head>
<body>
<header>
  <div class="logo">&#9889; SentinelCore <span>SOAR</span></div>
  <div style="font-size:13px;color:var(--muted)">Dashboard</div>
  <div class="header-right">
    <span id="demoBadge" class="demo-badge" style="display:none">DEMO MODE</span>
    <div class="health-pill">
      <div class="dot" id="hDot"></div>
      <span id="hLabel" style="color:var(--muted)">Carregando...</span>
    </div>
    <button class="export-btn" onclick="exportCsv()">&#8595; Export CSV</button>
  </div>
</header>

<main>
  <div class="auth-bar">
    <label>API Key (se necessário):</label>
    <input type="password" id="apiKeyInput" placeholder="Deixe vazio se auth não configurada" oninput="onApiKeyChange()"/>
    <button class="btn-sm" onclick="loadAll()">Carregar</button>
    <span style="color:var(--muted);font-size:12px" id="authHint"></span>
  </div>

  <div id="errBox" class="err-box" style="display:none"></div>

  <!-- Summary cards -->
  <div class="cards" id="cardsSection">
    <div class="card"><div class="lbl">Total Findings</div><div class="val" id="cTotal" style="color:var(--accent)">—</div></div>
    <div class="card"><div class="lbl">Score Médio</div><div class="val" id="cAvg" style="color:var(--text)">—</div></div>
    <div class="card"><div class="lbl">Critical</div><div class="val" id="cCrit" style="color:var(--clr-critical)">—</div></div>
    <div class="card"><div class="lbl">High</div><div class="val" id="cHigh" style="color:var(--clr-high)">—</div></div>
    <div class="card"><div class="lbl">Medium</div><div class="val" id="cMed" style="color:var(--clr-medium)">—</div></div>
    <div class="card"><div class="lbl">Low</div><div class="val" id="cLow" style="color:var(--clr-low)">—</div></div>
  </div>

  <!-- Charts -->
  <div class="section-hdr"><h2>Visualizações</h2></div>
  <div class="charts-grid">
    <div class="chart-card">
      <h3>Distribuição por Prioridade</h3>
      <div class="chart-wrap"><canvas id="donutChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>Top 10 IOCs por Score</h3>
      <div class="chart-wrap"><canvas id="barChart"></canvas></div>
    </div>
    <div class="chart-card">
      <h3>Findings — Últimos 7 Dias</h3>
      <div class="chart-wrap"><canvas id="lineChart"></canvas></div>
    </div>
  </div>

  <!-- Findings table -->
  <div class="section-hdr">
    <h2>Findings Recentes</h2>
    <div class="spacer"></div>
    <div class="filters">
      <select id="fPriority" onchange="applyFilters()">
        <option value="">Todas prioridades</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <select id="fType" onchange="applyFilters()">
        <option value="">Todos os tipos</option>
        <option value="ip">IP</option>
        <option value="domain">Domain</option>
        <option value="url">URL</option>
        <option value="hash">Hash</option>
      </select>
    </div>
  </div>

  <div id="tableSection">
    <div class="loading"><div class="spin"></div><br>Carregando findings...</div>
  </div>
</main>

<!-- Detail modal -->
<div class="modal-overlay" id="modal" onclick="closeModal(event)">
  <div class="modal" id="modalBox">
    <div class="modal-hdr">
      <div>
        <div class="ioc-big" id="mIoc"></div>
        <div style="margin-top:6px;display:flex;gap:8px;flex-wrap:wrap" id="mBadges"></div>
      </div>
      <button class="close-btn" onclick="closeModal(null)">&#10005;</button>
    </div>
    <div class="modal-body" id="mBody"></div>
  </div>
</div>

<footer>
  SentinelCore SOAR &nbsp;·&nbsp;
  <a href="/">&#9889; Analyzer</a> &nbsp;·&nbsp;
  <a href="/docs">API Docs</a> &nbsp;·&nbsp;
  <a href="/health">Health</a>
</footer>

<script>
// ── State ──────────────────────────────────────────────────────────────────
const PAGE_SIZE = 25;
let allFindings = [];   // fetched for stats + charts (up to 1000)
let tableTotal  = 0;
let tablePage   = 0;
let tableFilter = {priority:'', ioc_type:''};
let charts      = {};
let apiKey      = '';

// ── Init ──────────────────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  const qs = new URLSearchParams(location.search);
  if (qs.get('api_key')) {
    apiKey = qs.get('api_key');
    document.getElementById('apiKeyInput').value = apiKey;
  }
  loadAll();
  setInterval(checkHealth, 15000);
});

function onApiKeyChange() {
  apiKey = document.getElementById('apiKeyInput').value.trim();
}

// ── Headers ───────────────────────────────────────────────────────────────
function headers() {
  const h = {'Content-Type':'application/json'};
  if (apiKey) h['X-API-Key'] = apiKey;
  return h;
}

// ── Health ────────────────────────────────────────────────────────────────
async function checkHealth() {
  try {
    const r = await fetch('/health');
    const d = await r.json();
    const dot   = document.getElementById('hDot');
    const label = document.getElementById('hLabel');
    const demo  = document.getElementById('demoBadge');
    const status = d.status || 'unhealthy';
    dot.className = 'dot ' + status;
    label.textContent = status.charAt(0).toUpperCase() + status.slice(1);
    label.style.color = status === 'healthy' ? 'var(--accent2)'
                      : status === 'degraded' ? 'var(--warn)'
                      : 'var(--danger)';
    demo.style.display = d.demo_mode ? 'inline-block' : 'none';
  } catch {
    document.getElementById('hDot').className = 'dot unhealthy';
    document.getElementById('hLabel').textContent = 'Offline';
  }
}

// ── Load all (stats + charts + first table page) ──────────────────────────
async function loadAll() {
  apiKey = document.getElementById('apiKeyInput').value.trim();
  hideErr();
  checkHealth();
  await fetchAllForStats();
  renderCards();
  renderCharts();
  tablePage = 0;
  await fetchTablePage();
}

async function fetchAllForStats() {
  try {
    const r = await fetch('/findings?limit=1000&offset=0', {headers: headers()});
    if (r.status === 401) {
      showErr('Autenticação necessária. Informe a API Key acima e clique em Carregar.');
      document.getElementById('authHint').textContent = '401 – chave obrigatória';
      allFindings = [];
      return;
    }
    if (!r.ok) { showErr('Erro ao buscar findings: ' + r.status); allFindings = []; return; }
    hideErr();
    document.getElementById('authHint').textContent = '';
    const d = await r.json();
    allFindings = d.findings || [];
  } catch(e) {
    showErr('Erro de rede: ' + e.message);
    allFindings = [];
  }
}

// ── Table ─────────────────────────────────────────────────────────────────
function applyFilters() {
  tableFilter.priority = document.getElementById('fPriority').value;
  tableFilter.ioc_type = document.getElementById('fType').value;
  tablePage = 0;
  fetchTablePage();
}

async function fetchTablePage() {
  const sec = document.getElementById('tableSection');
  sec.innerHTML = '<div class="loading"><div class="spin"></div><br>Carregando...</div>';
  const params = new URLSearchParams({
    limit: PAGE_SIZE,
    offset: tablePage * PAGE_SIZE,
  });
  if (tableFilter.priority) params.set('priority', tableFilter.priority);
  if (tableFilter.ioc_type) params.set('ioc_type', tableFilter.ioc_type);

  try {
    const r = await fetch('/findings?' + params, {headers: headers()});
    if (!r.ok) { sec.innerHTML = '<div class="empty"><div class="ico">&#9888;</div><p>Erro ' + r.status + '</p></div>'; return; }
    const d = await r.json();
    tableTotal = d.total;
    renderTable(d.findings, d.total, d.offset, d.limit);
  } catch(e) {
    sec.innerHTML = '<div class="empty"><div class="ico">&#9888;</div><p>' + e.message + '</p></div>';
  }
}

function renderTable(rows, total, offset, limit) {
  const sec = document.getElementById('tableSection');
  if (!rows.length) {
    sec.innerHTML = '<div class="empty"><div class="ico">&#128737;</div><p>Nenhum finding encontrado com os filtros aplicados.</p></div>';
    return;
  }
  const trs = rows.map((f, i) => {
    const sc = f.risk_score || 0;
    const color = scoreColor(sc);
    const mitre = (f.mitre_attack || []).slice(0,3).map(m => m.technique_id).join(', ');
    return `<tr onclick="openModal(${i + offset})">
      <td><span class="ioc-cell" title="${esc(f.ioc)}">${esc(f.ioc)}</span></td>
      <td><span class="badge b-type">${esc(f.ioc_type)}</span></td>
      <td><span class="sbar">
        <span class="sbar-bg"><span class="sbar-fill" style="width:${sc}%;background:${color}"></span></span>
        <span class="sbar-num" style="color:${color}">${sc}</span>
      </span></td>
      <td><span class="badge b-${f.priority}">${f.priority}</span></td>
      <td style="color:var(--muted)">${fmtDate(f.generated_at)}</td>
      <td style="font-size:11px;color:var(--muted)">${mitre || '—'}</td>
    </tr>`;
  }).join('');

  const totalPages = Math.ceil(total / limit) || 1;
  const curPage = Math.floor(offset / limit) + 1;

  sec.innerHTML = `
  <div class="table-wrap">
    <table>
      <thead><tr>
        <th>IOC</th><th>Tipo</th><th>Score</th><th>Prioridade</th><th>Data</th><th>MITRE</th>
      </tr></thead>
      <tbody>${trs}</tbody>
    </table>
    <div class="pagination">
      <span class="pg-info">${total} finding${total !== 1 ? 's' : ''} &nbsp;·&nbsp; Página ${curPage} / ${totalPages}</span>
      <button class="pg-btn" onclick="prevPage()" ${tablePage === 0 ? 'disabled' : ''}>&#8592; Anterior</button>
      <button class="pg-btn" onclick="nextPage()" ${curPage >= totalPages ? 'disabled' : ''}>Próximo &#8594;</button>
    </div>
  </div>`;
}

function prevPage() { if (tablePage > 0) { tablePage--; fetchTablePage(); } }
function nextPage() { tablePage++; fetchTablePage(); }

// ── Modal ─────────────────────────────────────────────────────────────────
function openModal(globalIdx) {
  // Try to find in allFindings first, else fetch page-level row
  const f = allFindings[globalIdx] || null;
  if (!f) return;
  populateModal(f);
}

function populateModal(f) {
  document.getElementById('mIoc').textContent = f.ioc;
  document.getElementById('mBadges').innerHTML =
    `<span class="badge b-type">${esc(f.ioc_type)}</span>
     <span class="badge b-${f.priority}">${f.priority}</span>
     <span class="badge" style="background:var(--surface2);color:${scoreColor(f.risk_score)};border:1px solid var(--border)">Score ${f.risk_score}</span>`;

  const reasons = (f.reasons || []).map(r => `<div class="reason-item">${esc(r)}</div>`).join('') || '<span style="color:var(--muted)">—</span>';
  const mitre   = (f.mitre_attack || []).map(m => `<span class="mitre-tag">${esc(m.technique_id)} · ${esc(m.name||'')}</span>`).join('') || '—';
  const sources = (f.sources_queried || []).map(s => `<span class="source-tag">${esc(s)}</span>`).join('') || '<span style="color:var(--muted)">nenhuma</span>';
  const runbook = (f.runbook_steps || []).map((s,i) => `<div style="display:flex;gap:8px;font-size:13px;margin-bottom:6px"><span style="min-width:20px;height:20px;background:var(--surface2);border:1px solid var(--border);border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:10px;color:var(--accent);font-weight:700;flex-shrink:0">${i+1}</span>${esc(s)}</div>`).join('') || '—';

  const vt  = f.virustotal || {};
  const abu = f.abuseipdb || {};
  const gn  = f.greynoise || {};
  const sh  = f.shodan || {};
  const otx = f.otx || {};

  const kvs = [
    ['Gerado em',  fmtDate(f.generated_at)],
    ['Correlation ID', f.correlation_id || '—'],
    ['VT Malicious',   vt.analysis_stats ? vt.analysis_stats.malicious : '—'],
    ['VT Suspicious',  vt.analysis_stats ? vt.analysis_stats.suspicious : '—'],
    ['Abuse Score',    abu.abuse_confidence_score !== undefined ? abu.abuse_confidence_score + '%' : '—'],
    ['Abuse Reports',  abu.total_reports !== undefined ? abu.total_reports : '—'],
    ['GreyNoise',      gn.classification || '—'],
    ['Shodan Ports',   sh.ports ? sh.ports.join(', ') || '—' : '—'],
    ['Shodan CVEs',    sh.vulns && sh.vulns.length ? sh.vulns.slice(0,3).join(', ') : '—'],
    ['OTX Pulses',     otx.pulse_count !== undefined ? otx.pulse_count : '—'],
  ].map(([k,v]) => `<div class="kv"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('');

  document.getElementById('mBody').innerHTML = `
    <div class="mrow"><div class="mlbl">Razões do Score</div>${reasons}</div>
    <div class="mrow"><div class="mlbl">Fontes Consultadas</div><div>${sources}</div></div>
    <div class="mrow"><div class="mlbl">Detalhes de Enriquecimento</div><div class="kv-grid">${kvs}</div></div>
    <div class="mrow"><div class="mlbl">MITRE ATT&CK</div><div>${mitre}</div></div>
    <div class="mrow"><div class="mlbl">Runbook</div>${runbook}</div>`;

  document.getElementById('modal').classList.add('open');
}

function closeModal(evt) {
  if (evt === null || evt.target === document.getElementById('modal')) {
    document.getElementById('modal').classList.remove('open');
  }
}
document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(null); });

// ── Summary cards ─────────────────────────────────────────────────────────
function renderCards() {
  const total = allFindings.length;
  const scores = allFindings.map(f => f.risk_score || 0);
  const avg = total ? Math.round(scores.reduce((a,b)=>a+b,0) / total) : 0;
  const cnt = {critical:0, high:0, medium:0, low:0};
  allFindings.forEach(f => { if (cnt[f.priority] !== undefined) cnt[f.priority]++; });
  set('cTotal', total);
  set('cAvg', avg);
  set('cCrit', cnt.critical);
  set('cHigh', cnt.high);
  set('cMed',  cnt.medium);
  set('cLow',  cnt.low);
}

// ── Charts ────────────────────────────────────────────────────────────────
function renderCharts() {
  const cnt = {critical:0, high:0, medium:0, low:0};
  allFindings.forEach(f => { if (cnt[f.priority] !== undefined) cnt[f.priority]++; });

  // Donut
  destroyChart('donutChart');
  charts.donut = new Chart(document.getElementById('donutChart'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low'],
      datasets: [{
        data: [cnt.critical, cnt.high, cnt.medium, cnt.low],
        backgroundColor: ['#ff6b6b','#f85149','#d29922','#3fb950'],
        borderColor: '#161b22',
        borderWidth: 3,
        hoverOffset: 6,
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{
        legend:{position:'right', labels:{color:'#8b949e',font:{size:11}}},
        tooltip:{callbacks:{label: ctx => ` ${ctx.label}: ${ctx.parsed}`}}
      }
    }
  });

  // Bar – top 10 by score
  const top10 = [...allFindings].sort((a,b)=>(b.risk_score||0)-(a.risk_score||0)).slice(0,10);
  destroyChart('barChart');
  charts.bar = new Chart(document.getElementById('barChart'), {
    type: 'bar',
    data: {
      labels: top10.map(f => truncate(f.ioc, 20)),
      datasets: [{
        label: 'Score',
        data: top10.map(f => f.risk_score || 0),
        backgroundColor: top10.map(f => priorityBg(f.priority)),
        borderRadius: 5,
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false, indexAxis:'y',
      plugins:{legend:{display:false}, tooltip:{callbacks:{title: (items)=>[top10[items[0].dataIndex].ioc]}}},
      scales:{
        x:{ticks:{color:'#8b949e',font:{size:10}}, grid:{color:'#30363d'}, max:100},
        y:{ticks:{color:'#8b949e',font:{size:10}}, grid:{display:false}}
      }
    }
  });

  // Line – last 7 days
  const days = last7Days();
  const byDay = {};
  days.forEach(d => byDay[d] = 0);
  allFindings.forEach(f => {
    const d = (f.generated_at || '').slice(0,10);
    if (byDay[d] !== undefined) byDay[d]++;
  });
  destroyChart('lineChart');
  charts.line = new Chart(document.getElementById('lineChart'), {
    type: 'line',
    data: {
      labels: days.map(d => d.slice(5)),
      datasets: [{
        label: 'Findings',
        data: days.map(d => byDay[d]),
        borderColor: '#58a6ff',
        backgroundColor: 'rgba(88,166,255,.12)',
        fill: true,
        tension: 0.4,
        pointRadius: 4,
        pointBackgroundColor: '#58a6ff',
      }]
    },
    options: {
      responsive:true, maintainAspectRatio:false,
      plugins:{legend:{display:false}},
      scales:{
        x:{ticks:{color:'#8b949e',font:{size:11}}, grid:{color:'#30363d'}},
        y:{ticks:{color:'#8b949e',font:{size:11}}, grid:{color:'#30363d'}, beginAtZero:true, precision:0}
      }
    }
  });
}

function destroyChart(id) {
  if (charts[id]) { charts[id].destroy(); delete charts[id]; }
}

// ── Export CSV ────────────────────────────────────────────────────────────
function exportCsv() {
  const params = new URLSearchParams();
  if (tableFilter.priority) params.set('priority', tableFilter.priority);
  if (tableFilter.ioc_type) params.set('ioc_type', tableFilter.ioc_type);
  if (apiKey) params.set('api_key', apiKey);
  window.location.href = '/report.csv?' + params;
}

// ── Helpers ───────────────────────────────────────────────────────────────
function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function set(id, val) { document.getElementById(id).textContent = val; }
function showErr(msg) {
  const b = document.getElementById('errBox');
  b.textContent = msg; b.style.display = 'block';
}
function hideErr() { document.getElementById('errBox').style.display = 'none'; }
function scoreColor(s) {
  if (s >= 80) return 'var(--clr-critical)';
  if (s >= 60) return 'var(--clr-high)';
  if (s >= 40) return 'var(--clr-medium)';
  return 'var(--clr-low)';
}
function priorityBg(p) {
  if (p === 'critical') return '#ff6b6b';
  if (p === 'high')     return '#f85149';
  if (p === 'medium')   return '#d29922';
  return '#3fb950';
}
function truncate(s, n) { return s.length > n ? s.slice(0,n)+'…' : s; }
function fmtDate(s) {
  if (!s) return '—';
  try { return new Date(s).toLocaleString('pt-BR', {dateStyle:'short', timeStyle:'short'}); }
  catch { return s.slice(0,16).replace('T',' '); }
}
function last7Days() {
  const days = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date(); d.setDate(d.getDate() - i);
    days.push(d.toISOString().slice(0,10));
  }
  return days;
}
</script>
</body>
</html>"""


app = FastAPI(title="Mini SOAR API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/", include_in_schema=False)
def root_dashboard() -> FileResponse:
    return FileResponse("dashboard.html")


@app.get("/dashboard", include_in_schema=False)
def dashboard_page(api_key: str | None = Query(default=None)) -> HTMLResponse:  # noqa: ARG001
    return HTMLResponse(content=_DASHBOARD_HTML)


@app.middleware("http")
async def api_metrics_middleware(request: Request, call_next):
    started = time.perf_counter()
    endpoint = request.url.path
    status_code = "500"
    try:
        response = await call_next(request)
        status_code = str(response.status_code)
        API_REQUESTS_TOTAL.labels(endpoint=endpoint, status=status_code).inc()
        return response
    except HTTPException as exc:
        status_code = str(exc.status_code)
        API_REQUESTS_TOTAL.labels(endpoint=endpoint, status=status_code).inc()
        raise
    finally:
        elapsed_ms = round((time.perf_counter() - started) * 1000, 2)
        log_event(
            logger,
            logging.INFO,
            "api_request",
            connector="api",
            endpoint=endpoint,
            duration_ms=elapsed_ms,
            status_code=int(status_code) if status_code.isdigit() else status_code,
        )


@app.get("/health")
def health() -> JSONResponse:
    env_cfg = build_config_from_env()
    limit, window = _rate_limit_settings()
    payload, http_code = run_health_checks(
        database_url=env_cfg.database_url,
        redis_url=os.getenv("MINI_SOAR_REDIS_URL"),
        vt_api_key=env_cfg.vt_api_key,
        abuse_api_key=env_cfg.abuse_api_key,
        rate_limit_backend=_rate_limiter.backend_name,
        rate_limit_limit=limit,
        rate_limit_window=window,
        demo_mode=env_cfg.demo_mode,
        api_version=app.version,
    )
    payload["dashboard_url"] = "/dashboard"
    return JSONResponse(content=payload, status_code=http_code)


@app.get("/metrics")
def metrics(_: dict[str, Any] = Depends(authorize_request)) -> Response:
    payload, content_type = prometheus_payload()
    return Response(content=payload, media_type=content_type)


def _request_to_iocs(request: AnalyzeRequest) -> list[str]:
    candidates: list[str] = []
    if request.ioc:
        candidates.append(request.ioc)
    candidates.extend(request.iocs)
    return read_iocs(None, candidates)


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(
    request: AnalyzeRequest,
    http_request: Request,
    identity: dict[str, Any] = Depends(authorize_request),
) -> AnalyzeResponse:
    enforce_rate_limit(http_request)
    correlation_id = http_request.headers.get("X-Correlation-ID", new_correlation_id())
    iocs = _request_to_iocs(request)

    config = build_runtime_config_from_request(request)
    if not config.vt_api_key and not config.abuse_api_key:
        raise HTTPException(
            status_code=400,
            detail="Set VT_API_KEY and/or ABUSEIPDB_API_KEY in environment before calling /analyze.",
        )

    log_event(
        logger,
        logging.INFO,
        "analyze_requested",
        correlation_id=correlation_id,
        subject=str(identity.get("subject")),
    )
    report = run_pipeline(iocs=iocs, config=config, progress=False, correlation_id=correlation_id, logger=logger)
    return AnalyzeResponse(
        generated_at=report["generated_at"],
        correlation_id=report.get("correlation_id"),
        summary=report["summary"],
        findings=report["findings"],
    )


@app.post("/analyze/async", response_model=AsyncAcceptedResponse, status_code=202)
def analyze_async(
    request: AnalyzeAsyncRequest,
    http_request: Request,
    _: dict[str, Any] = Depends(authorize_request),
) -> AsyncAcceptedResponse:
    enforce_rate_limit(http_request)
    correlation_id = http_request.headers.get("X-Correlation-ID", new_correlation_id())
    iocs = _request_to_iocs(request)
    config = build_runtime_config_from_request(request)

    overrides = {
        "ticket_backend": config.ticket_backend,
        "ticket_threshold": config.ticket_threshold,
        "integration_targets": config.integration_targets,
        "integration_threshold": config.integration_threshold,
        "timeout": config.timeout,
        "max_retries": config.max_retries,
    }

    try:
        job_id = enqueue_iocs_job(iocs=iocs, config_overrides=overrides, correlation_id=correlation_id)
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Queue unavailable: {exc}") from exc

    return AsyncAcceptedResponse(job_id=job_id, status="queued", correlation_id=correlation_id)


@app.get("/jobs/{job_id}")
def job_status(job_id: str, _: dict[str, Any] = Depends(authorize_request)) -> JSONResponse:
    try:
        payload = get_job_status(job_id)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=f"Job not found or queue unavailable: {exc}") from exc
    return JSONResponse(payload)


@app.get("/findings", response_model=FindingsResponse)
def list_findings(
    priority: str | None = Query(default=None, description="Filter by priority: low, medium, high, critical"),
    ioc_type: str | None = Query(default=None, description="Filter by IOC type: ip, domain, url, hash"),
    min_score: int | None = Query(default=None, ge=0, description="Minimum risk score (inclusive)"),
    max_score: int | None = Query(default=None, le=100, description="Maximum risk score (inclusive)"),
    ioc: str | None = Query(default=None, description="Partial match on IOC value"),
    since: str | None = Query(default=None, description="ISO datetime — findings created at or after this time"),
    until: str | None = Query(default=None, description="ISO datetime — findings created at or before this time"),
    limit: int = Query(default=50, ge=1, le=200, description="Number of results to return (max 200)"),
    offset: int = Query(default=0, ge=0, description="Number of results to skip"),
    _: dict[str, Any] = Depends(authorize_request),
) -> FindingsResponse:
    env_cfg = build_config_from_env()
    store = create_store(env_cfg.database_url)
    filters: dict[str, Any] = {
        "priority":  priority,
        "ioc_type":  ioc_type,
        "min_score": min_score,
        "max_score": max_score,
        "ioc":       ioc,
        "since":     since,
        "until":     until,
    }
    findings, total = store.query_findings(filters, limit=limit, offset=offset)
    return FindingsResponse(total=total, limit=limit, offset=offset, findings=findings)


# ── CSV export ─────────────────────────────────────────────────────────────────

_CSV_COLUMNS = [
    "generated_at", "ioc", "ioc_type", "risk_score", "priority",
    "reasons", "vt_malicious", "vt_suspicious",
    "abuse_confidence", "abuse_reports", "mitre_techniques",
]


def _finding_to_csv_row(finding: dict[str, Any]) -> dict[str, Any]:
    vt_stats = (finding.get("virustotal") or {}).get("analysis_stats", {})
    abuse    = finding.get("abuseipdb") or {}
    mitre    = finding.get("mitre_attack") or []
    return {
        "generated_at":     finding.get("generated_at", ""),
        "ioc":              finding.get("ioc", ""),
        "ioc_type":         finding.get("ioc_type", ""),
        "risk_score":       finding.get("risk_score", ""),
        "priority":         finding.get("priority", ""),
        "reasons":          " | ".join(finding.get("reasons") or []),
        "vt_malicious":     vt_stats.get("malicious", ""),
        "vt_suspicious":    vt_stats.get("suspicious", ""),
        "abuse_confidence": abuse.get("abuse_confidence_score", ""),
        "abuse_reports":    abuse.get("total_reports", ""),
        "mitre_techniques": " | ".join(
            t.get("technique_id", "") for t in mitre if isinstance(t, dict)
        ),
    }


def _generate_csv(findings: list[dict[str, Any]]):
    """Yield the CSV header then one row per finding."""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    yield buf.getvalue()
    for finding in findings:
        buf.seek(0)
        buf.truncate(0)
        writer.writerow(_finding_to_csv_row(finding))
        yield buf.getvalue()


@app.get("/report.csv")
def export_csv(
    priority:  str | None = Query(default=None, description="Filter by priority"),
    ioc_type:  str | None = Query(default=None, description="Filter by IOC type"),
    min_score: int | None = Query(default=None, ge=0,   description="Minimum risk score"),
    max_score: int | None = Query(default=None, le=100, description="Maximum risk score"),
    ioc:       str | None = Query(default=None, description="Partial match on IOC value"),
    since:     str | None = Query(default=None, description="ISO datetime lower bound"),
    until:     str | None = Query(default=None, description="ISO datetime upper bound"),
    _: dict[str, Any] = Depends(authorize_request),
) -> StreamingResponse:
    env_cfg = build_config_from_env()
    store = create_store(env_cfg.database_url)
    filters: dict[str, Any] = {
        "priority":  priority,
        "ioc_type":  ioc_type,
        "min_score": min_score,
        "max_score": max_score,
        "ioc":       ioc,
        "since":     since,
        "until":     until,
    }
    findings, _ = store.query_findings(filters, limit=10_000, offset=0)
    date_str = datetime.now(tz=timezone.utc).strftime("%Y%m%d")
    filename = f"sentinelcore_report_{date_str}.csv"
    return StreamingResponse(
        _generate_csv(findings),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── Feed ingestion ──────────────────────────────────────────────────────────────

@app.post("/feeds/ingest", status_code=200)
def trigger_feed_ingest(
    body: FeedIngestRequest | None = None,
    _: dict[str, Any] = Depends(authorize_request),
) -> JSONResponse:
    """Manually trigger IOC feed ingestion.

    If ``body.urls`` is empty the endpoint falls back to ``MINI_SOAR_FEED_URLS``.
    Returns per-feed stats and pipeline totals.
    """
    req = body or FeedIngestRequest()
    urls = req.urls or feed_urls_from_env()
    if not urls:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="No feed URLs provided. Pass 'urls' in the request body or set MINI_SOAR_FEED_URLS.",
        )

    env_cfg = build_config_from_env()
    feed_timeout = int(os.getenv("MINI_SOAR_FEED_TIMEOUT", "30"))

    try:
        result = ingest_feeds(
            urls=urls,
            fmt=req.format,
            ioc_column=req.ioc_column,
            config=env_cfg,
            timeout=feed_timeout,
        )
    except Exception as exc:
        logger.exception("feed_ingest_error")
        raise HTTPException(status_code=500, detail=f"Feed ingestion failed: {exc}") from exc

    return JSONResponse(result)


@app.get("/feeds/status")
def feed_status(_: dict[str, Any] = Depends(authorize_request)) -> JSONResponse:
    """Return the status of all previously polled feeds."""
    statuses = get_feed_statuses()
    return JSONResponse({"feeds": statuses, "count": len(statuses)})
