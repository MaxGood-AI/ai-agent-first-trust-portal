"""Recording the result of a test execution.

One function decides how an outcome (``success`` or ``failure``) changes a
``TestRecord``. The API's ``record-execution`` routes and the collector
executor both call it, so every execution leaves the same fields behind and
the audit log's execution history reads the same way whoever recorded it.

Attribution: the audit trigger names the actor from the authenticated team
member (``g.current_team_member``). A collector run launched by a person is
attributed to that person (``attributed_to``); a scheduled run has no actor,
so its audit rows carry no team member and the finding names the collector
run instead.
"""

import contextlib
from datetime import datetime, timezone

from flask import g

from app.models import TestRecord

OUTCOMES = ("success", "failure")


def apply_outcome(test: TestRecord, outcome: str, finding=None, comment=None,
                  evidence_submitted: bool = False) -> None:
    """Set ``test``'s execution fields for ``outcome``; the caller commits.

    ``finding`` and ``comment`` replace the stored text when given (not None).
    ``evidence_submitted`` marks the test's evidence as submitted.
    """
    if outcome not in OUTCOMES:
        raise ValueError("outcome must be 'success' or 'failure'")
    test.execution_status = "completed"
    test.execution_outcome = outcome
    test.status = "passed" if outcome == "success" else "failed"
    test.last_executed_at = datetime.now(timezone.utc)
    if finding is not None:
        test.finding = finding
    if comment is not None:
        test.comment = comment
    if evidence_submitted:
        test.evidence_status = "submitted"


@contextlib.contextmanager
def attributed_to(member):
    """Attribute audited writes inside the block to ``member`` (None: no actor)."""
    previous = getattr(g, "current_team_member", None)
    if member is not None:
        g.current_team_member = member
    try:
        yield
    finally:
        if member is not None:
            g.current_team_member = previous
