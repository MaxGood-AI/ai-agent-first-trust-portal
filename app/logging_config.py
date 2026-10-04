"""Process-wide logging: JSON lines on stdout in production, readable text in
development, and optional shipping to CloudWatch Logs.

``configure_logging()`` is idempotent and is called by the app factory, the
CLI and the gunicorn worker hooks. When ``CLOUDWATCH_LOG_GROUP`` is set (in
the environment or the portal secret), every record of the root logger and
of gunicorn's access and error loggers is also sent to that existing log
group, one stream per process (``<hostname>-<pid>``), in batches from a
background thread. Shipping failures are counted and reported to stderr;
they never block or fail a request. The shipping queue holds at most
``CloudWatchLogsHandler.MAX_QUEUE_EVENTS`` records and
``CloudWatchLogsHandler.MAX_QUEUE_BYTES`` bytes; a record that does not fit
is dropped from shipping (it still reaches stdout), counted in ``dropped``
and reported to stderr at the next flush.
"""

from __future__ import annotations

import json
import logging
import os
import queue
import socket
import sys
import threading
import time
from datetime import datetime, timezone

_configured_pid: int | None = None
_cloudwatch_handler: "CloudWatchLogsHandler | None" = None

# Loggers whose records are never shipped to CloudWatch (they are emitted by
# the shipping code itself and would recurse).
_NO_SHIP_PREFIXES = ("botocore", "boto3", "urllib3", "s3transfer")


class JsonFormatter(logging.Formatter):
    """One JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(timespec="milliseconds"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "pid": record.process,
        }
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False)


class CloudWatchLogsHandler(logging.Handler):
    """Buffered, non-blocking CloudWatch Logs handler.

    Records are queued and flushed by a daemon thread every
    ``flush_interval`` seconds, in batches within the service limits
    (10,000 events / ~1 MB) and in the order they were queued. The queue is
    bounded by ``MAX_QUEUE_EVENTS`` records and ``MAX_QUEUE_BYTES`` bytes
    (each record counted as its UTF-8 size plus ``EVENT_OVERHEAD``); a record
    that does not fit is dropped and counted in ``dropped``. Uses the
    portal's runtime AWS session.
    """

    MAX_BATCH_EVENTS = 10_000
    MAX_BATCH_BYTES = 1_000_000
    MAX_EVENT_BYTES = 250_000
    EVENT_OVERHEAD = 26
    MAX_QUEUE_EVENTS = 50_000
    MAX_QUEUE_BYTES = 16 * 1024 * 1024

    def __init__(self, log_group: str, stream_name: str | None = None,
                 flush_interval: float = 5.0, client=None):
        super().__init__()
        self.log_group = log_group
        self.stream_name = stream_name or f"{socket.gethostname()}-{os.getpid()}"
        self.flush_interval = flush_interval
        self._client = client
        self._queue: queue.Queue = queue.Queue(maxsize=self.MAX_QUEUE_EVENTS)
        self._queued_bytes = 0
        self._bytes_lock = threading.Lock()
        self._carry: tuple[int, str, int] | None = None
        self._flush_lock = threading.Lock()
        self._stream_ready = False
        self._stop = threading.Event()
        self.dropped = 0
        self._dropped_reported = 0
        self.failures = 0
        self._thread = threading.Thread(target=self._run, name="cloudwatch-logs", daemon=True)
        self._thread.start()

    @property
    def queued_bytes(self) -> int:
        """Bytes of the records waiting to be shipped."""
        with self._bytes_lock:
            return self._queued_bytes

    def _get_client(self):
        if self._client is None:
            from app.services.aws_session import get_session
            self._client = get_session().client("logs")
        return self._client

    def emit(self, record: logging.LogRecord) -> None:
        if record.name.startswith(_NO_SHIP_PREFIXES):
            return
        try:
            message = self.format(record)
        except Exception:  # noqa: BLE001
            self.handleError(record)
            return
        encoded = message.encode("utf-8")
        if len(encoded) > self.MAX_EVENT_BYTES:
            encoded = encoded[: self.MAX_EVENT_BYTES]
            message = encoded.decode("utf-8", "ignore")
        size = len(encoded) + self.EVENT_OVERHEAD
        with self._bytes_lock:
            if self._queued_bytes + size > self.MAX_QUEUE_BYTES:
                self.dropped += 1
                return
            try:
                self._queue.put_nowait((int(record.created * 1000), message, size))
            except queue.Full:
                self.dropped += 1
                return
            self._queued_bytes += size

    def _ensure_stream(self) -> None:
        if self._stream_ready:
            return
        client = self._get_client()
        try:
            client.create_log_stream(logGroupName=self.log_group, logStreamName=self.stream_name)
        except client.exceptions.ResourceAlreadyExistsException:
            pass
        self._stream_ready = True

    def _drain(self) -> list[tuple[int, str]]:
        """The next batch, in queue order. A record that would overflow the
        batch is carried over to the next one, ahead of the queue."""
        events: list[tuple[int, str]] = []
        size = 0
        while len(events) < self.MAX_BATCH_EVENTS:
            if self._carry is not None:
                item, self._carry = self._carry, None
            else:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
            ts, message, event_size = item
            if size + event_size > self.MAX_BATCH_BYTES and events:
                self._carry = item
                break
            events.append((ts, message))
            size += event_size
        with self._bytes_lock:
            self._queued_bytes -= size
        events.sort(key=lambda event: event[0])
        return events

    def _report_drops(self) -> None:
        dropped = self.dropped
        if dropped > self._dropped_reported:
            sys.stderr.write(f"cloudwatch-logs: dropped {dropped - self._dropped_reported} event(s): "
                             f"the shipping queue was full\n")
            self._dropped_reported = dropped

    def flush(self) -> None:
        with self._flush_lock:
            self._report_drops()
            while True:
                events = self._drain()
                if not events:
                    return
                try:
                    self._ensure_stream()
                    self._get_client().put_log_events(
                        logGroupName=self.log_group,
                        logStreamName=self.stream_name,
                        logEvents=[{"timestamp": ts, "message": msg} for ts, msg in events],
                    )
                except Exception as exc:  # noqa: BLE001 - shipping must never raise
                    self.failures += 1
                    self._stream_ready = False
                    sys.stderr.write(f"cloudwatch-logs: failed to ship {len(events)} event(s): {exc}\n")
                    return

    def _run(self) -> None:
        while not self._stop.is_set():
            self._stop.wait(self.flush_interval)
            try:
                self.flush()
            except Exception as exc:  # noqa: BLE001 - the shipping thread must outlive any error
                sys.stderr.write(f"cloudwatch-logs: flush failed: {exc!r}\n")

    def close(self) -> None:
        self._stop.set()
        try:
            self.flush()
        finally:
            super().close()


_log_stream_name = "stdout"


def route_logs_to_stderr() -> None:
    """Command-line processes log to stderr, never stdout: stdout carries only the
    command's own output. Takes effect for this process now and at any later
    ``configure_logging``."""
    global _log_stream_name
    _log_stream_name = "stderr"
    root = logging.getLogger()
    for handler in root.handlers:
        if getattr(handler, "_portal_handler", False) and isinstance(handler, logging.StreamHandler) \
                and getattr(handler, "stream", None) is sys.stdout:
            handler.setStream(sys.stderr)


def configure_logging(force: bool = False) -> None:
    """Configure root logging once per process (re-run after fork). The web
    process logs to stdout; command-line processes to stderr
    (:func:`route_logs_to_stderr`)."""
    global _configured_pid, _cloudwatch_handler
    pid = os.getpid()
    if _configured_pid == pid and not force:
        return

    from app.runtime_config import env, portal_env

    level = getattr(logging, (env("LOG_LEVEL", "INFO") or "INFO").upper(), logging.INFO)
    if portal_env() == "production":
        formatter: logging.Formatter = JsonFormatter()
    else:
        formatter = logging.Formatter("%(asctime)s %(levelname)s [%(name)s] %(message)s")

    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        if getattr(handler, "_portal_handler", False):
            root.removeHandler(handler)
    stdout = logging.StreamHandler(sys.stderr if _log_stream_name == "stderr" else sys.stdout)
    stdout.setFormatter(formatter)
    stdout._portal_handler = True  # type: ignore[attr-defined]
    root.addHandler(stdout)

    for noisy in _NO_SHIP_PREFIXES:
        logging.getLogger(noisy).setLevel(max(level, logging.WARNING))

    log_group = env("CLOUDWATCH_LOG_GROUP")
    if log_group:
        if _cloudwatch_handler is not None:
            _cloudwatch_handler._stop.set()  # noqa: SLF001 - handler from the parent process
        _cloudwatch_handler = CloudWatchLogsHandler(log_group)
        _cloudwatch_handler.setFormatter(JsonFormatter())
        _cloudwatch_handler._portal_handler = True  # type: ignore[attr-defined]
        root.addHandler(_cloudwatch_handler)
        # gunicorn's loggers do not propagate to root; ship them too.
        for name in ("gunicorn.access", "gunicorn.error"):
            logging.getLogger(name).addHandler(_cloudwatch_handler)

    _configured_pid = pid


def shutdown_logging() -> None:
    """Flush the CloudWatch handler (worker exit)."""
    if _cloudwatch_handler is not None:
        _cloudwatch_handler.close()


def wait_for_flush(timeout: float = 5.0) -> None:  # pragma: no cover - used by CLI exit paths
    deadline = time.monotonic() + timeout
    while _cloudwatch_handler is not None and _cloudwatch_handler.queued_bytes:
        if time.monotonic() > deadline:
            return
        time.sleep(0.1)
