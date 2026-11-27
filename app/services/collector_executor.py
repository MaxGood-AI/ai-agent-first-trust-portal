"""Collector executor — runs a collector and persists results to the database.

The executor owns the lifecycle of a claimed ``CollectorRun`` (status
``running``; the scheduler's claim sets its ``executor_token``):

1. Read the collector's configuration into a detached copy and end the
   transaction, so no transaction (and no table lock) stays open while
   credentials are resolved and the collector works.
2. Resolve credentials (errors fail the run fast).
3. Instantiate the collector class from the registry with the copy.
4. Call ``collector.run()`` and receive ``CheckResult`` objects.
5. For each CheckResult, create a ``CollectorCheckResult`` row and (for
   pass/fail checks with an evidence description and a matching test) an
   ``Evidence`` row, committing each check on its own.
6. For each ``auto_assessment`` test the run's checks named, decide the test's
   result: any failing check records ``failure``; at least one passing check
   and no failing one records ``success``; a test only error/skipped checks
   reached is left as it is. The result goes through
   ``test_execution.apply_outcome``, the code path of the API's
   ``record-execution``. A ``self_assessment`` test named by a check receives
   the evidence link but never a result.
7. Record ``success``, ``partial`` or ``failure`` with the counts
   compare-and-set: the run changes only while it is still ``running`` under
   the executor's token, and only then does the configuration's last-run
   status follow.

Under the scheduler every commit also verifies that the executor still holds
the run's target lock (``scheduler.RunGuard``); an executor that lost it
records nothing further.

All database work happens inside the caller's Flask app context so audit
triggers capture changes correctly.
"""

import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import inspect as sa_inspect
from sqlalchemy import update

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


def _now():
    return datetime.now(timezone.utc)


def _resolve_test_record(target_test_name: str | None) -> TestRecord | None:
    """Look up the TestRecord a check names, for evidence linking.

    An exact name match wins. Otherwise the name matches ignoring case and
    surrounding spaces, so a check naming "Policy Management" links to a test
    record named "Policy management ". Among several matches of the same kind
    an ``auto_assessment`` record is preferred, then the lowest id, so the
    link is deterministic and a collector's result lands on the automated test
    rather than on a self-assessment record that shares its name.
    """
    if not target_test_name:
        return None
    exact = (TestRecord.query.filter_by(name=target_test_name)
             .order_by(_auto_assessment_first(), TestRecord.id).first())
    if exact is not None:
        return exact
    wanted = target_test_name.strip().lower()
    if not wanted:
        return None
    return (TestRecord.query
            .filter(db.func.lower(db.func.trim(TestRecord.name)) == wanted)
            .order_by(_auto_assessment_first(), TestRecord.id).first())


def _auto_assessment_first():
    """ORDER BY term that sorts ``auto_assessment`` records before the others."""
    return db.case((TestRecord.test_type == "auto_assessment", 0), else_=1)


class _TestTally:
    """The pass/fail check results of one run for one test."""

    MAX_FAILURES_LISTED = 5
    MAX_MESSAGE_LENGTH = 200

    def __init__(self, test_id: str):
        self.test_id = test_id
        self.passed = 0
        self.failed = 0
        self.failure_messages: list[str] = []
        self.evidence_created = False

    def add(self, cr: CheckResult, evidence_created: bool) -> None:
        if cr.status == "pass":
            self.passed += 1
        elif cr.status == "fail":
            self.failed += 1
            self.failure_messages.append((cr.message or cr.check_name)[:self.MAX_MESSAGE_LENGTH])
        self.evidence_created = self.evidence_created or evidence_created

    @property
    def outcome(self) -> str | None:
        """``failure``, ``success``, or None when no check passed or failed."""
        if self.failed:
            return "failure"
        return "success" if self.passed else None

    def finding(self, collector_name: str) -> str:
        total = self.passed + self.failed
        if self.failed == 0:
            return f"Collector {collector_name}: all {total} check(s) passed."
        listed = "; ".join(self.failure_messages[:self.MAX_FAILURES_LISTED])
        more = self.failed - len(self.failure_messages[:self.MAX_FAILURES_LISTED])
        suffix = f"; and {more} more" if more > 0 else ""
        return (f"Collector {collector_name}: {self.failed} of {total} check(s) failed. "
                f"Failing: {listed}{suffix}")


def _record_test_outcomes(tallies: dict[str, "_TestTally"], collector_name: str, run_id: str,
                          member_id: str | None) -> int:
    """Record each tallied test's result; returns how many tests changed.

    Only ``auto_assessment`` tests that apply are tallied by the caller. The
    write is attributed to the member who triggered the run, if any.
    """
    from app.models import TeamMember
    from app.services.test_execution import apply_outcome, attributed_to

    member = db.session.get(TeamMember, member_id) if member_id else None
    recorded = 0
    with attributed_to(member):
        for tally in tallies.values():
            outcome = tally.outcome
            if outcome is None:
                continue
            test = db.session.get(TestRecord, tally.test_id)
            if test is None or test.test_type != "auto_assessment" or test.status == "not_applicable":
                continue
            apply_outcome(
                test, outcome,
                finding=tally.finding(collector_name),
                comment=f"Recorded by collector run {run_id} ({collector_name}).",
                evidence_submitted=tally.evidence_created,
            )
            db.session.commit()
            recorded += 1
    return recorded


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
        collected_at=_now(),
    )
    db.session.add(evidence)
    return evidence


def _detached_copy(config: CollectorConfig) -> CollectorConfig:
    """A transient CollectorConfig carrying ``config``'s column values.

    The collector reads its settings from the copy, so nothing it reads
    needs the database session.
    """
    columns = sa_inspect(CollectorConfig).column_attrs
    return CollectorConfig(**{column.key: getattr(config, column.key) for column in columns})


def _record_outcome(run_id: str, token: str | None, config_id: str | None = None, **values) -> bool:
    """Write the run's terminal values compare-and-set; returns whether they applied.

    The update applies only while the run is ``running`` under ``token``.
    When it applies and ``config_id`` is given, the configuration's last-run
    time and status follow in the same transaction.
    """
    token_matches = (CollectorRun.executor_token.is_(None) if token is None
                     else CollectorRun.executor_token == token)
    recorded = db.session.execute(
        update(CollectorRun)
        .where(CollectorRun.id == run_id, CollectorRun.status == "running", token_matches)
        .values(**values)
        .execution_options(synchronize_session=False)
    ).rowcount
    if recorded != 1:
        db.session.rollback()
        logger.warning("Collector run %s is no longer running under this executor; "
                       "its outcome (%s) is not recorded", run_id, values.get("status"))
        return False
    if config_id is not None:
        db.session.execute(
            update(CollectorConfig)
            .where(CollectorConfig.id == config_id)
            .values(last_run_at=values["finished_at"], last_run_status=values["status"])
            .execution_options(synchronize_session=False)
        )
    db.session.commit()
    return True


def execute_run(
    run: CollectorRun,
    resolver: CredentialResolver | None = None,
) -> CollectorRun:
    """Execute a claimed CollectorRun and persist its results.

    ``run`` must already be committed with ``status='running'``. Returns the
    same ``run`` object; its attributes reload the recorded row on access.
    """
    run_id = run.id
    token = run.executor_token
    config_id = run.collector_config_id
    triggered_by = run.triggered_by_team_member_id
    config = _detached_copy(run.config)
    db.session.commit()  # no transaction stays open while the collector works

    resolver = resolver or CredentialResolver()

    collector_cls = get_collector_class(config.name)
    if collector_cls is None:
        _record_outcome(run_id, token, status="failure", finished_at=_now(),
                        error_message=f"No collector registered for name '{config.name}'")
        return run

    # Resolve credentials up front so we fail fast with a clear error.
    try:
        resolver.resolve(config)
    except CredentialResolutionError as exc:
        _record_outcome(run_id, token, status="failure", finished_at=_now(),
                        error_message=f"Credential resolution failed: {exc}")
        return run

    collector: BaseCollector = collector_cls(config=config, resolver=resolver)

    try:
        check_results = collector.run()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Collector %s raised during run()", config.name)
        db.session.rollback()
        _record_outcome(run_id, token, status="failure", finished_at=_now(), error_message=str(exc))
        return run

    pass_count = 0
    fail_count = 0
    error_count = 0
    evidence_count = 0
    tallies: dict[str, _TestTally] = {}

    for cr in check_results:
        test_record = _resolve_test_record(cr.target_test_name)
        evidence = _maybe_create_evidence(cr, test_record, collector_name=config.name)
        if evidence is not None:
            db.session.flush()  # the evidence row exists before the check result refers to it
            evidence_count += 1

        db.session.add(CollectorCheckResult(
            id=str(uuid.uuid4()),
            collector_run_id=run_id,
            check_name=cr.check_name,
            target_test_id=test_record.id if test_record else None,
            status=cr.status,
            evidence_id=evidence.id if evidence else None,
            message=cr.message,
            detail=cr.detail or None,
        ))
        db.session.commit()

        if (test_record is not None and test_record.test_type == "auto_assessment"
                and cr.status in ("pass", "fail")):
            tally = tallies.setdefault(test_record.id, _TestTally(test_record.id))
            tally.add(cr, evidence_created=evidence is not None)

        if cr.status == "pass":
            pass_count += 1
        elif cr.status == "fail":
            fail_count += 1
        elif cr.status == "error":
            error_count += 1

    _record_test_outcomes(tallies, config.name, run_id, triggered_by)

    # A check that errored verified nothing: the run succeeds only when every
    # check that ran passed. "skipped" checks do not count either way.
    if fail_count == 0 and error_count == 0 and pass_count > 0:
        status = "success"
    elif pass_count > 0:
        status = "partial"
    else:
        status = "failure"

    _record_outcome(
        run_id, token, config_id=config_id,
        status=status,
        finished_at=_now(),
        check_pass_count=pass_count,
        check_fail_count=fail_count,
        evidence_count=evidence_count,
    )
    return run
