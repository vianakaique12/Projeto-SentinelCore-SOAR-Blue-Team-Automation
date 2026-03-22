"""Tests for mini_soar_queue.py and mini_soar_worker.py.

All Redis and RQ interactions are mocked via unittest.mock so no real
Redis server is required.  Each test is fully independent — no shared state.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from mini_soar_core import RuntimeConfig
from mini_soar_queue import (
    _merge_runtime_config,
    ensure_queue_dependencies,
    enqueue_iocs_job,
    get_job_status,
    process_iocs_job,
    redis_url_from_env,
)


# ── Shared helpers ─────────────────────────────────────────────────────────────

def _make_job(
    job_id: str = "job-abc",
    status: str = "queued",
    is_finished: bool = False,
    is_failed: bool = False,
    result=None,
    exc_info=None,
) -> MagicMock:
    """Build a MagicMock that quacks like an RQ Job."""
    job = MagicMock()
    job.id = job_id
    job.get_status.return_value = status
    job.is_finished = is_finished
    job.is_failed = is_failed
    job.result = result
    job.exc_info = exc_info
    return job


def _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job: MagicMock) -> MagicMock:
    """Wire up Redis + Queue mocks and return the queue instance."""
    conn = MagicMock()
    mock_redis_cls.from_url.return_value = conn
    q = MagicMock()
    q.enqueue.return_value = job
    mock_queue_cls.return_value = q
    return q


# ══════════════════════════════════════════════════════════════════════════════
# redis_url_from_env
# ══════════════════════════════════════════════════════════════════════════════

class TestRedisUrlFromEnv:

    def test_returns_default_when_env_not_set(self, monkeypatch):
        """Falls back to localhost when MINI_SOAR_REDIS_URL is not defined."""
        monkeypatch.delenv("MINI_SOAR_REDIS_URL", raising=False)
        assert redis_url_from_env() == "redis://127.0.0.1:6379/0"

    def test_returns_value_from_env(self, monkeypatch):
        """Returns the exact URL stored in MINI_SOAR_REDIS_URL."""
        monkeypatch.setenv("MINI_SOAR_REDIS_URL", "redis://prodhost:6380/1")
        assert redis_url_from_env() == "redis://prodhost:6380/1"


# ══════════════════════════════════════════════════════════════════════════════
# ensure_queue_dependencies
# ══════════════════════════════════════════════════════════════════════════════

class TestEnsureQueueDependencies:

    def test_passes_silently_when_rq_is_importable(self):
        """No exception is raised in a normal environment with redis+rq installed."""
        ensure_queue_dependencies()  # must not raise

    def test_raises_when_all_imports_are_none(self):
        """RuntimeError is raised when the optional rq/redis imports are absent."""
        with (
            patch("mini_soar_queue.Redis", None),
            patch("mini_soar_queue.Queue", None),
            patch("mini_soar_queue.Job", None),
        ):
            with pytest.raises(RuntimeError, match="Missing queue dependencies"):
                ensure_queue_dependencies()

    def test_raises_when_only_redis_is_none(self):
        """RuntimeError is raised even when only Redis is unavailable."""
        with patch("mini_soar_queue.Redis", None):
            with pytest.raises(RuntimeError):
                ensure_queue_dependencies()


# ══════════════════════════════════════════════════════════════════════════════
# _merge_runtime_config
# ══════════════════════════════════════════════════════════════════════════════

class TestMergeRuntimeConfig:

    def test_none_overrides_returns_equivalent_config(self):
        """Passing None leaves every field at its base value."""
        base = RuntimeConfig(timeout=30, max_retries=5)
        merged = _merge_runtime_config(base, None)
        assert merged.timeout == 30
        assert merged.max_retries == 5

    def test_empty_dict_overrides_returns_equivalent_config(self):
        """An empty overrides dict is identical to no overrides."""
        base = RuntimeConfig(timeout=30)
        merged = _merge_runtime_config(base, {})
        assert merged.timeout == 30

    def test_single_override_replaces_field(self):
        """A single key in overrides replaces only that field."""
        base = RuntimeConfig(timeout=20, max_retries=2)
        merged = _merge_runtime_config(base, {"timeout": 60})
        assert merged.timeout == 60
        assert merged.max_retries == 2  # untouched

    def test_multiple_overrides_all_applied(self):
        """Multiple override keys are all applied in one call."""
        base = RuntimeConfig(timeout=20, ticket_threshold=70, max_retries=2)
        merged = _merge_runtime_config(
            base, {"timeout": 45, "ticket_threshold": 50, "max_retries": 4}
        )
        assert merged.timeout == 45
        assert merged.ticket_threshold == 50
        assert merged.max_retries == 4

    def test_override_does_not_mutate_base(self):
        """The original RuntimeConfig object must not be modified."""
        base = RuntimeConfig(timeout=20)
        _merge_runtime_config(base, {"timeout": 99})
        assert base.timeout == 20


# ══════════════════════════════════════════════════════════════════════════════
# enqueue_iocs_job
# ══════════════════════════════════════════════════════════════════════════════

class TestEnqueueIocsJob:

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_returns_job_id_as_string(self, mock_redis_cls, mock_queue_cls):
        """Return value is the string representation of the job ID."""
        job = _make_job(job_id="returned-id")
        _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        result = enqueue_iocs_job(["1.2.3.4"])
        assert result == "returned-id"
        assert isinstance(result, str)

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_passes_iocs_as_positional_arg_to_enqueue(self, mock_redis_cls, mock_queue_cls):
        """IOC list is forwarded as the second positional argument to queue.enqueue()."""
        job = _make_job()
        q = _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        enqueue_iocs_job(["8.8.8.8", "1.1.1.1"])

        positional = q.enqueue.call_args[0]
        # positional[0] = func (process_iocs_job), positional[1] = iocs
        assert positional[1] == ["8.8.8.8", "1.1.1.1"]

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_propagates_provided_correlation_id(self, mock_redis_cls, mock_queue_cls):
        """A supplied correlation_id must be forwarded as a keyword arg to enqueue()."""
        job = _make_job()
        q = _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        enqueue_iocs_job(["1.2.3.4"], correlation_id="trace-xyz")

        kwargs = q.enqueue.call_args[1]
        assert kwargs["correlation_id"] == "trace-xyz"

    @patch("mini_soar_queue.new_correlation_id", return_value="auto-corr-id")
    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_generates_correlation_id_when_none_provided(
        self, mock_redis_cls, mock_queue_cls, _mock_new_corr
    ):
        """When correlation_id is None, a new ID is generated and forwarded."""
        job = _make_job()
        q = _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        enqueue_iocs_job(["1.2.3.4"])

        kwargs = q.enqueue.call_args[1]
        assert kwargs["correlation_id"] == "auto-corr-id"

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_passes_config_overrides_to_job(self, mock_redis_cls, mock_queue_cls):
        """config_overrides dict is forwarded as a keyword arg to enqueue()."""
        job = _make_job()
        q = _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        overrides = {"timeout": 45, "ticket_backend": "none"}
        enqueue_iocs_job(["1.2.3.4"], config_overrides=overrides)

        kwargs = q.enqueue.call_args[1]
        assert kwargs["config_overrides"] == overrides

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_uses_default_queue_name_mini_soar(self, mock_redis_cls, mock_queue_cls):
        """Queue is constructed with name='mini_soar' by default."""
        job = _make_job()
        _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        enqueue_iocs_job(["1.2.3.4"])

        mock_queue_cls.assert_called_once()
        assert mock_queue_cls.call_args[1]["name"] == "mini_soar"

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_uses_custom_queue_name_when_provided(self, mock_redis_cls, mock_queue_cls):
        """A custom queue_name parameter is forwarded to Queue() constructor."""
        job = _make_job()
        _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        enqueue_iocs_job(["1.2.3.4"], queue_name="priority")

        assert mock_queue_cls.call_args[1]["name"] == "priority"

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_enqueue_sets_job_timeout_600(self, mock_redis_cls, mock_queue_cls):
        """job_timeout=600 must always be set on the enqueued job."""
        job = _make_job()
        q = _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        enqueue_iocs_job(["1.2.3.4"])

        assert q.enqueue.call_args[1]["job_timeout"] == 600

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_enqueue_sets_result_ttl_3600(self, mock_redis_cls, mock_queue_cls):
        """result_ttl=3600 must always be set so results survive for one hour."""
        job = _make_job()
        q = _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        enqueue_iocs_job(["1.2.3.4"])

        assert q.enqueue.call_args[1]["result_ttl"] == 3600

    @patch("mini_soar_queue.Redis")
    def test_raises_when_redis_connection_fails(self, mock_redis_cls):
        """A Redis connection error must propagate immediately to the caller."""
        mock_redis_cls.from_url.side_effect = ConnectionError("Redis unreachable")

        with pytest.raises(ConnectionError, match="Redis unreachable"):
            enqueue_iocs_job(["1.2.3.4"])

    @patch("mini_soar_queue.Queue")
    @patch("mini_soar_queue.Redis")
    def test_enqueue_function_arg_is_process_iocs_job(self, mock_redis_cls, mock_queue_cls):
        """The first argument to queue.enqueue() must be process_iocs_job."""
        from mini_soar_queue import process_iocs_job as pij

        job = _make_job()
        q = _patch_redis_and_queue(mock_redis_cls, mock_queue_cls, job)

        enqueue_iocs_job(["1.2.3.4"])

        func_arg = q.enqueue.call_args[0][0]
        assert func_arg is pij


# ══════════════════════════════════════════════════════════════════════════════
# get_job_status
# ══════════════════════════════════════════════════════════════════════════════

class TestGetJobStatus:

    def _wire(self, mock_redis_cls, mock_job_cls, job: MagicMock) -> None:
        mock_redis_cls.from_url.return_value = MagicMock()
        mock_job_cls.fetch.return_value = job

    @patch("mini_soar_queue.Job")
    @patch("mini_soar_queue.Redis")
    def test_queued_job_has_no_result_or_error(self, mock_redis_cls, mock_job_cls):
        """A queued job response contains job_id + status but no result or error keys."""
        job = _make_job(job_id="j1", status="queued")
        self._wire(mock_redis_cls, mock_job_cls, job)

        result = get_job_status("j1")

        assert result["job_id"] == "j1"
        assert result["status"] == "queued"
        assert "result" not in result
        assert "error" not in result

    @patch("mini_soar_queue.Job")
    @patch("mini_soar_queue.Redis")
    def test_started_job_returns_status_without_result(self, mock_redis_cls, mock_job_cls):
        """A running job response contains only status; no result yet."""
        job = _make_job(job_id="j2", status="started")
        self._wire(mock_redis_cls, mock_job_cls, job)

        result = get_job_status("j2")

        assert result["status"] == "started"
        assert "result" not in result
        assert "error" not in result

    @patch("mini_soar_queue.Job")
    @patch("mini_soar_queue.Redis")
    def test_finished_job_includes_pipeline_result(self, mock_redis_cls, mock_job_cls):
        """A finished job response includes the full result payload under 'result'."""
        pipeline_output = {"summary": {"total_iocs": 2}, "findings": [{"ioc": "8.8.8.8"}]}
        job = _make_job(
            job_id="j3", status="finished", is_finished=True, result=pipeline_output
        )
        self._wire(mock_redis_cls, mock_job_cls, job)

        result = get_job_status("j3")

        assert result["status"] == "finished"
        assert result["result"] is pipeline_output
        assert "error" not in result

    @patch("mini_soar_queue.Job")
    @patch("mini_soar_queue.Redis")
    def test_failed_job_includes_error_string(self, mock_redis_cls, mock_job_cls):
        """A failed job response includes the exception traceback under 'error'."""
        job = _make_job(
            job_id="j4",
            status="failed",
            is_failed=True,
            exc_info="Traceback: ValueError: pipeline exploded",
        )
        self._wire(mock_redis_cls, mock_job_cls, job)

        result = get_job_status("j4")

        assert result["status"] == "failed"
        assert "error" in result
        assert "ValueError" in result["error"]
        assert "result" not in result

    @patch("mini_soar_queue.Job")
    @patch("mini_soar_queue.Redis")
    def test_nonexistent_job_propagates_exception(self, mock_redis_cls, mock_job_cls):
        """When Job.fetch raises (job not found), the exception must propagate."""
        mock_redis_cls.from_url.return_value = MagicMock()
        mock_job_cls.fetch.side_effect = Exception("No such job: unknown-id")

        with pytest.raises(Exception, match="No such job"):
            get_job_status("unknown-id")

    @patch("mini_soar_queue.Job")
    @patch("mini_soar_queue.Redis")
    def test_fetches_job_with_exact_id(self, mock_redis_cls, mock_job_cls):
        """Job.fetch() must be called with the exact ID passed to get_job_status()."""
        conn = MagicMock()
        mock_redis_cls.from_url.return_value = conn
        job = _make_job(job_id="exact-id")
        mock_job_cls.fetch.return_value = job

        get_job_status("exact-id")

        mock_job_cls.fetch.assert_called_once_with("exact-id", connection=conn)

    @patch("mini_soar_queue.Job")
    @patch("mini_soar_queue.Redis")
    def test_status_is_refreshed_before_reading(self, mock_redis_cls, mock_job_cls):
        """get_status(refresh=True) must be called so the latest state is returned."""
        job = _make_job(job_id="j6")
        self._wire(mock_redis_cls, mock_job_cls, job)

        get_job_status("j6")

        job.get_status.assert_called_once_with(refresh=True)


# ══════════════════════════════════════════════════════════════════════════════
# process_iocs_job
# ══════════════════════════════════════════════════════════════════════════════

class TestProcessIocsJob:
    """Tests for the actual RQ job function that runs inside the worker."""

    _PATCHES = (
        "mini_soar_queue.configure_logging",
        "mini_soar_queue.build_config_from_env",
        "mini_soar_queue.run_pipeline",
    )

    def _call(self, iocs, config_overrides=None, correlation_id=None,
              base_cfg=None, pipeline_result=None):
        """Helper: call process_iocs_job with all dependencies mocked."""
        base_cfg = base_cfg or RuntimeConfig()
        pipeline_result = pipeline_result if pipeline_result is not None else {}

        with (
            patch("mini_soar_queue.configure_logging"),
            patch("mini_soar_queue.build_config_from_env", return_value=base_cfg),
            patch("mini_soar_queue.run_pipeline", return_value=pipeline_result) as mock_run,
        ):
            result = process_iocs_job(
                iocs, config_overrides=config_overrides, correlation_id=correlation_id
            )
            return result, mock_run

    def test_calls_run_pipeline_with_provided_iocs(self):
        """run_pipeline() must receive the exact IOC list passed to the job."""
        _, mock_run = self._call(["1.2.3.4", "evil.com"])
        assert mock_run.call_args[1]["iocs"] == ["1.2.3.4", "evil.com"]

    def test_propagates_correlation_id_to_run_pipeline(self):
        """A supplied correlation_id must be forwarded to run_pipeline()."""
        _, mock_run = self._call(["1.2.3.4"], correlation_id="trace-123")
        assert mock_run.call_args[1]["correlation_id"] == "trace-123"

    @patch("mini_soar_queue.new_correlation_id", return_value="auto-id")
    def test_generates_correlation_id_when_none(self, _mock_new_corr):
        """When no correlation_id is given, one is auto-generated and forwarded."""
        with (
            patch("mini_soar_queue.configure_logging"),
            patch("mini_soar_queue.build_config_from_env", return_value=RuntimeConfig()),
            patch("mini_soar_queue.run_pipeline", return_value={}) as mock_run,
        ):
            process_iocs_job(["1.2.3.4"])

        assert mock_run.call_args[1]["correlation_id"] == "auto-id"

    def test_applies_config_overrides_to_runtime(self):
        """Overrides must be merged so run_pipeline() receives the updated config."""
        _, mock_run = self._call(
            ["1.2.3.4"],
            base_cfg=RuntimeConfig(timeout=20),
            config_overrides={"timeout": 99},
        )
        assert mock_run.call_args[1]["config"].timeout == 99

    def test_progress_is_always_false(self):
        """progress=False must be set so workers produce no stdout noise."""
        _, mock_run = self._call(["1.2.3.4"])
        assert mock_run.call_args[1]["progress"] is False

    def test_returns_pipeline_result_unchanged(self):
        """The dict returned by run_pipeline() is returned as-is."""
        fake_report = {"generated_at": "2024-01-01T00:00:00Z", "findings": []}
        result, _ = self._call(["1.2.3.4"], pipeline_result=fake_report)
        assert result is fake_report

    def test_pipeline_exception_propagates_for_rq_failure_tracking(self):
        """Exceptions from run_pipeline() must not be swallowed — RQ needs them
        to mark the job as failed and store the traceback."""
        with (
            patch("mini_soar_queue.configure_logging"),
            patch("mini_soar_queue.build_config_from_env", return_value=RuntimeConfig()),
            patch("mini_soar_queue.run_pipeline", side_effect=RuntimeError("boom")),
        ):
            with pytest.raises(RuntimeError, match="boom"):
                process_iocs_job(["1.2.3.4"])

    def test_config_without_overrides_uses_env_defaults(self):
        """When config_overrides is None, the env-derived config is used unchanged."""
        base = RuntimeConfig(timeout=77)
        _, mock_run = self._call(["1.2.3.4"], base_cfg=base, config_overrides=None)
        assert mock_run.call_args[1]["config"].timeout == 77


# ══════════════════════════════════════════════════════════════════════════════
# mini_soar_worker — main()
# ══════════════════════════════════════════════════════════════════════════════

class TestWorkerMain:
    """Tests for the RQ worker entry-point in mini_soar_worker.py."""

    def _make_ctx(self):
        """Return a MagicMock that behaves as a context manager."""
        ctx = MagicMock()
        ctx.__enter__ = MagicMock(return_value=ctx)
        ctx.__exit__ = MagicMock(return_value=False)
        return ctx

    @patch("rq.Worker")
    @patch("rq.Connection")
    @patch("mini_soar_worker.get_redis_connection")
    @patch("mini_soar_worker.ensure_queue_dependencies")
    def test_main_returns_zero_on_clean_exit(
        self, mock_ensure, mock_get_conn, mock_connection, mock_worker_cls
    ):
        """main() must return 0 after the worker finishes without error."""
        mock_get_conn.return_value = MagicMock()
        mock_connection.return_value = self._make_ctx()
        mock_worker_cls.return_value = MagicMock()

        from mini_soar_worker import main
        assert main() == 0

    @patch("rq.Worker")
    @patch("rq.Connection")
    @patch("mini_soar_worker.get_redis_connection")
    @patch("mini_soar_worker.ensure_queue_dependencies")
    def test_main_calls_worker_work_with_scheduler_disabled(
        self, mock_ensure, mock_get_conn, mock_connection, mock_worker_cls
    ):
        """worker.work() must be called with with_scheduler=False."""
        mock_get_conn.return_value = MagicMock()
        mock_connection.return_value = self._make_ctx()
        mock_worker = MagicMock()
        mock_worker_cls.return_value = mock_worker

        from mini_soar_worker import main
        main()

        mock_worker.work.assert_called_once_with(with_scheduler=False)

    @patch("rq.Worker")
    @patch("rq.Connection")
    @patch("mini_soar_worker.get_redis_connection")
    @patch("mini_soar_worker.ensure_queue_dependencies")
    def test_main_creates_worker_listening_on_mini_soar_queue(
        self, mock_ensure, mock_get_conn, mock_connection, mock_worker_cls
    ):
        """Worker must be instantiated with the 'mini_soar' queue name."""
        mock_get_conn.return_value = MagicMock()
        mock_connection.return_value = self._make_ctx()
        mock_worker_cls.return_value = MagicMock()

        from mini_soar_worker import main
        main()

        mock_worker_cls.assert_called_once_with(["mini_soar"])

    @patch("mini_soar_worker.ensure_queue_dependencies")
    def test_main_propagates_missing_dependency_error(self, mock_ensure):
        """If ensure_queue_dependencies raises, main() lets the error propagate."""
        mock_ensure.side_effect = RuntimeError(
            "Missing queue dependencies. Install `redis` and `rq`."
        )

        from mini_soar_worker import main
        with pytest.raises(RuntimeError, match="Missing queue dependencies"):
            main()

    @patch("rq.Worker")
    @patch("rq.Connection")
    @patch("mini_soar_worker.get_redis_connection")
    @patch("mini_soar_worker.ensure_queue_dependencies")
    def test_main_checks_dependencies_before_connecting(
        self, mock_ensure, mock_get_conn, mock_connection, mock_worker_cls
    ):
        """ensure_queue_dependencies() must run before the Redis connection is opened."""
        call_order: list[str] = []

        def record_ensure():
            call_order.append("ensure")

        def record_conn():
            call_order.append("conn")
            return MagicMock()

        mock_ensure.side_effect = record_ensure
        mock_get_conn.side_effect = record_conn
        mock_connection.return_value = self._make_ctx()
        mock_worker_cls.return_value = MagicMock()

        from mini_soar_worker import main
        main()

        assert call_order.index("ensure") < call_order.index("conn")

    @patch("rq.Worker")
    @patch("rq.Connection")
    @patch("mini_soar_worker.get_redis_connection")
    @patch("mini_soar_worker.ensure_queue_dependencies")
    def test_main_passes_redis_conn_to_connection_context_manager(
        self, mock_ensure, mock_get_conn, mock_connection, mock_worker_cls
    ):
        """The Redis connection returned by get_redis_connection() is passed to Connection()."""
        fake_conn = MagicMock(name="redis_conn")
        mock_get_conn.return_value = fake_conn
        mock_connection.return_value = self._make_ctx()
        mock_worker_cls.return_value = MagicMock()

        from mini_soar_worker import main
        main()

        mock_connection.assert_called_once_with(fake_conn)
