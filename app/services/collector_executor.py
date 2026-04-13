"""Collector executor — runs a collector and persists results to the database.

The executor owns the lifecycle of a ``CollectorRun``:

1. Mark the run as ``running`` with a start time.
2. Resolve credentials (errors fail the run fast).
3. Instantiate the collector class from the registry.
4. Call ``collector.run()`` and receive ``CheckResult`` objects.
5. For each CheckResult, create a ``CollectorCheckResult`` row and (for
   pass/fail checks with an evidence description) an ``Evidence`` row.
6. Mark the run as ``success``, ``partial``, or ``failure`` and write counts.

All database work happens inside the caller's Flask app context so audit
triggers capture changes correctly.
"""

import logging
import uuid
from datetime import datetime, timezone

from app.models import CollectorCheckResult, CollectorRun, Evidence, TestRecord, db
from app.models.collector_config import CollectorConfig
from app.services.credential_resolver import (
    CredentialResolutionError,
    CredentialResolver,
)
from collectors.base import BaseCollector, CheckResult
from collectors.registry import get_collector_class

logger = logging.getLogger(__name__)


class CollectorExecutionError(Exception):
    pass


def _resolve_test_record(target_test_name: str | None) -> TestRecord | None:
    """Best-effort lookup of a TestRecord by name for evidence linking."""
    if not target_test_name:
        return None
    return TestRecord.query.filter_by(name=target_test_name).first()


def _maybe_create_evidence(
    check_result: CheckResult,
    test_record: TestRecord | None,
    collector_name: str,
) -> Evidence | None:
    """Create an Evidence row for a check result if appropriate.

    Skips rows when the check is error/skipped, or when no TestRecord could
    be resolved (we don't want orphan evidence in the database).
    """
    if check_result.status not in ("pass", "fail"):
        return None
    if test_record is None:
        return None
    if not check_result.evidence_description:
        return None

    evidence = Evidence(
        id=str(uuid.uuid4()),
        test_record_id=test_record.id,
        evidence_type="automated",
        description=check_result.evidence_description,
        collector_name=collector_name,
        collected_at=datetime.now(timezone.utc),
    )
    db.session.add(evidence)
    return evidence


def execute_run(
    run: CollectorRun,
    resolver: CredentialResolver | None = None,
) -> CollectorRun:
    """Execute a pre-created CollectorRun and persist its results.

    ``run`` must already be flushed to the DB with ``status='running'``.
    Returns the same ``run`` object with updated status/counters.
    """
    config: CollectorConfig = run.config
    resolver = resolver or CredentialResolver()

    collector_cls = get_collector_class(config.name)
    if collector_cls is None:
        run.status = "failure"
        run.error_message = f"No collector registered for name '{config.name}'"
        run.finished_at = datetime.now(timezone.utc)
        db.session.commit()
        return run

    # Resolve credentials up front so we fail fast with a clear error.
    try:
        resolver.resolve(config)
    except CredentialResolutionError as exc:
        run.status = "failure"
        run.error_message = f"Credential resolution failed: {exc}"
        run.finished_at = datetime.now(timezone.utc)
        db.session.commit()
        return run

    collector: BaseCollector = collector_cls(config=config, resolver=resolver)

    try:
        check_results = collector.run()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Collector %s raised during run()", config.name)
        run.status = "failure"
        run.error_message = str(exc)
        run.finished_at = datetime.now(timezone.utc)
        db.session.commit()
        return run

    pass_count = 0
    fail_count = 0
    evidence_count = 0

    for cr in check_results:
        test_record = _resolve_test_record(cr.target_test_name)
        evidence = _maybe_create_evidence(cr, test_record, collector_name=config.name)
        if evidence is not None:
            db.session.flush()  # populate evidence.id
            evidence_count += 1

        row = CollectorCheckResult(
            id=str(uuid.uuid4()),
            collector_run_id=run.id,
            check_name=cr.check_name,
            target_test_id=test_record.id if test_record else None,
            status=cr.status,
            evidence_id=evidence.id if evidence else None,
            message=cr.message,
            detail=cr.detail or None,
        )
        db.session.add(row)

        if cr.status == "pass":
            pass_count += 1
        elif cr.status == "fail":
            fail_count += 1

    run.check_pass_count = pass_count
    run.check_fail_count = fail_count
    run.evidence_count = evidence_count
    run.finished_at = datetime.now(timezone.utc)

    if fail_count == 0 and pass_count > 0:
        run.status = "success"
    elif pass_count > 0:
        run.status = "partial"
    else:
        run.status = "failure"

    # Propagate the last-run-status back onto the config for the dashboard.
    config.last_run_at = run.finished_at
    config.last_run_status = run.status

    db.session.commit()
    return run
