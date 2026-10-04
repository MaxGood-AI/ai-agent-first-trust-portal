"""Authentication rate limiting backed by the ``auth_rate_limit`` table.

Every attempt (login, client login, setup) consumes one unit of the client's
budget for the bucket in the current fixed window through a single atomic
upsert (``INSERT ... ON CONFLICT DO UPDATE ... RETURNING attempts``), so
concurrent attempts from many processes or nodes can never exceed the limit.
A successful authentication clears the client's counters for the bucket.
The client is its IP address as seen after ``ProxyFix``. Windows older than
a day are pruned by the scheduler's maintenance task.

Configuration: ``AUTH_RATE_LIMIT_ATTEMPTS`` attempts per
``AUTH_RATE_LIMIT_WINDOW_SECONDS`` (defaults 10 per 900 s).
"""

from datetime import datetime, timedelta, timezone

from flask import current_app, request
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from app.models import db
from app.models.auth_rate_limit import AuthRateLimitWindow

BUCKETS = ("login", "client_login", "setup")


def client_key() -> str:
    return (request.remote_addr or "unknown")[:128]


def _limit() -> int:
    return int(current_app.config.get("AUTH_RATE_LIMIT_ATTEMPTS", 10))


def _window_start(now: datetime | None = None) -> datetime:
    seconds = int(current_app.config.get("AUTH_RATE_LIMIT_WINDOW_SECONDS", 900))
    now = now or datetime.now(timezone.utc)
    epoch = int(now.timestamp())
    return datetime.fromtimestamp(epoch - epoch % seconds, tz=timezone.utc)


def _upsert():
    return pg_insert if db.engine.dialect.name == "postgresql" else sqlite_insert


def consume(bucket: str) -> bool:
    """Count one attempt; True when it is within the budget (the caller may proceed)."""
    insert = _upsert()
    statement = insert(AuthRateLimitWindow).values(
        bucket=bucket, client_key=client_key(), window_start=_window_start(), attempts=1)
    statement = statement.on_conflict_do_update(
        index_elements=["bucket", "client_key", "window_start"],
        set_={"attempts": AuthRateLimitWindow.attempts + 1},
    ).returning(AuthRateLimitWindow.attempts)
    attempts = db.session.execute(statement).scalar()
    db.session.commit()
    return attempts <= _limit()


def is_limited(bucket: str) -> bool:
    """True when this client has no budget left for ``bucket`` (read-only check)."""
    row = AuthRateLimitWindow.query.filter_by(
        bucket=bucket, client_key=client_key(), window_start=_window_start()).first()
    return bool(row and row.attempts >= _limit())


def record_failure(bucket: str) -> None:
    """Kept for callers that count only failures: consumes one attempt."""
    consume(bucket)


def reset(bucket: str) -> None:
    """Forget this client's attempts after a successful authentication."""
    AuthRateLimitWindow.query.filter_by(bucket=bucket, client_key=client_key()).delete()
    db.session.commit()


def prune(max_age: timedelta = timedelta(days=1)) -> int:
    """Delete windows older than ``max_age``; returns the number removed."""
    cutoff = datetime.now(timezone.utc) - max_age
    removed = AuthRateLimitWindow.query.filter(AuthRateLimitWindow.window_start < cutoff).delete()
    db.session.commit()
    return removed
