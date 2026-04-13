"""Collector check result model — one row per individual check within a collector run."""

from app.models import db


class CollectorCheckResult(db.Model):
    """A single check result from a collector run.

    Each collector run produces many check results (one per probe/check).
    Each result may link to a TestRecord it produces evidence for and to
    the Evidence row that was created.
    """

    __tablename__ = "collector_check_result"

    id = db.Column(db.String(36), primary_key=True)
    collector_run_id = db.Column(
        db.String(36),
        db.ForeignKey("collector_run.id"),
        nullable=False,
    )
    check_name = db.Column(db.String(128), nullable=False)
    target_test_id = db.Column(
        db.String(36),
        db.ForeignKey("test_records.id"),
        nullable=True,
        comment="TestRecord this check produces evidence for, if any",
    )
    status = db.Column(
        db.String(16),
        nullable=False,
        comment="pass | fail | error | skipped",
    )
    evidence_id = db.Column(
        db.String(36),
        db.ForeignKey("evidence.id"),
        nullable=True,
        comment="Evidence row created by this check, if any",
    )
    message = db.Column(db.Text, nullable=True)
    detail = db.Column(db.JSON, nullable=True, comment="Structured check detail")

    def __repr__(self):
        return f"<CollectorCheckResult {self.check_name} status={self.status}>"
