"""Audit middleware — sets PostgreSQL session variable for trigger attribution."""

import logging

from flask import g
from sqlalchemy import event

logger = logging.getLogger(__name__)


def register_audit_middleware(db):
    """Register a SQLAlchemy event listener that sets app.current_team_member.

    Before each flush, if a team member is authenticated (g.current_team_member),
    the PostgreSQL session variable ``app.current_team_member`` is set via SET LOCAL.
    The audit trigger function reads this to populate the ``changed_by`` column.

    SET LOCAL scopes the variable to the current transaction, which is safe
    for connection pooling.
    """

    @event.listens_for(db.session, "before_flush")
    def set_current_user(session, flush_context, instances):
        member = getattr(g, "current_team_member", None)
        if member:
            try:
                session.execute(
                    db.text("SET LOCAL app.current_team_member = :user_id"),
                    {"user_id": member.id},
                )
            except Exception:
                logger.debug("Could not set app.current_team_member (likely SQLite in tests)")
