#!/usr/bin/env python3
"""Async queue helpers for Mini SOAR using RQ + Redis."""

from __future__ import annotations

import os
from typing import Any

from mini_soar_core import (
    RuntimeConfig,
    build_config_from_env,
    run_pipeline,
    runtime_config_from_dict,
    runtime_config_to_dict,
)
from mini_soar_observability import configure_logging, new_correlation_id

try:
    from redis import Redis
    from rq import Queue
    from rq.job import Job
except ModuleNotFoundError:  # Optional dependency.
    Redis = None  # type: ignore[assignment]
    Queue = None  # type: ignore[assignment]
    Job = None  # type: ignore[assignment]


def ensure_queue_dependencies() -> None:
    if Redis is None or Queue is None or Job is None:
        raise RuntimeError("Missing queue dependencies. Install `redis` and `rq`.")


def redis_url_from_env() -> str:
    return os.getenv("MINI_SOAR_REDIS_URL", "redis://127.0.0.1:6379/0")


def get_redis_connection():
    ensure_queue_dependencies()
    return Redis.from_url(redis_url_from_env())  # type: ignore[union-attr]


def get_queue(name: str = "mini_soar"):
    conn = get_redis_connection()
    return Queue(name=name, connection=conn)  # type: ignore[misc]


def _merge_runtime_config(base: RuntimeConfig, override_payload: dict[str, Any] | None) -> RuntimeConfig:
    base_dict = runtime_config_to_dict(base)
    if override_payload:
        base_dict.update(override_payload)
    return runtime_config_from_dict(base_dict)


def process_iocs_job(
    iocs: list[str],
    config_overrides: dict[str, Any] | None = None,
    correlation_id: str | None = None,
) -> dict[str, Any]:
    configure_logging()
    corr_id = correlation_id or new_correlation_id()
    base_cfg = build_config_from_env()
    runtime_cfg = _merge_runtime_config(base_cfg, config_overrides)
    return run_pipeline(iocs=iocs, config=runtime_cfg, progress=False, correlation_id=corr_id)


def enqueue_iocs_job(
    iocs: list[str],
    config_overrides: dict[str, Any] | None = None,
    correlation_id: str | None = None,
    queue_name: str = "mini_soar",
) -> str:
    corr_id = correlation_id or new_correlation_id()
    queue = get_queue(queue_name)
    job = queue.enqueue(
        process_iocs_job,
        iocs,
        config_overrides=config_overrides,
        correlation_id=corr_id,
        job_timeout=600,
        result_ttl=3600,
    )
    return str(job.id)


def get_job_status(job_id: str) -> dict[str, Any]:
    ensure_queue_dependencies()
    conn = get_redis_connection()
    job = Job.fetch(job_id, connection=conn)  # type: ignore[misc]
    response: dict[str, Any] = {
        "job_id": job.id,
        "status": job.get_status(refresh=True),
    }
    if job.is_finished:
        response["result"] = job.result
    if job.is_failed:
        response["error"] = str(job.exc_info)
    return response

