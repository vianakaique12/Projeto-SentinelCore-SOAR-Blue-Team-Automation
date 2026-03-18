#!/usr/bin/env python3
"""RQ worker entrypoint for Mini SOAR async jobs."""

from __future__ import annotations

from mini_soar_queue import ensure_queue_dependencies, get_redis_connection


def main() -> int:
    ensure_queue_dependencies()
    from rq import Connection, Worker

    conn = get_redis_connection()
    with Connection(conn):
        worker = Worker(["mini_soar"])
        worker.work(with_scheduler=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

