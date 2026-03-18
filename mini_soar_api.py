#!/usr/bin/env python3
"""FastAPI service wrapper for Mini SOAR."""

from __future__ import annotations

import logging
import os
import threading
import time
from collections import defaultdict
from typing import Any, Literal

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field, field_validator, model_validator

from mini_soar_core import RuntimeConfig, build_config_from_env, read_iocs, run_pipeline
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


def choose(value: object, fallback: object) -> object:
    return fallback if value is None else value


def _rate_limit_settings() -> tuple[int, int]:
    limit = int(os.getenv("MINI_SOAR_API_RATE_LIMIT", "60"))
    window = int(os.getenv("MINI_SOAR_API_RATE_WINDOW_SECONDS", "60"))
    return limit, window


_rate_state: dict[str, list[float]] = defaultdict(list)
_rate_lock = threading.Lock()


def _cleanup_rate_bucket(now_ts: float, entries: list[float], window_seconds: int) -> list[float]:
    cutoff = now_ts - window_seconds
    return [value for value in entries if value >= cutoff]


def enforce_rate_limit(request: Request) -> None:
    limit, window = _rate_limit_settings()
    client_id = request.client.host if request.client else "unknown"
    now_ts = time.time()

    with _rate_lock:
        entries = _cleanup_rate_bucket(now_ts, _rate_state[client_id], window)
        if len(entries) >= limit:
            RATE_LIMIT_HITS_TOTAL.labels(scope="api").inc()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Max {limit} requests per {window}s.",
            )
        entries.append(now_ts)
        _rate_state[client_id] = entries


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
    )


app = FastAPI(title="Mini SOAR API", version="2.0.0")


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
def health() -> dict[str, str]:
    return {"status": "ok"}


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
