"""Collector run model — one row per execution of a collector."""

from datetime import datetime, timezone

from app.models import db


class CollectorRun(db.Model):
    """A single execution of an evidence collector.

    Records who triggered it, when it ran, how long it took, and aggregate
    results. Per-check detail lives in CollectorCheckResult.
    """

    __tablename__ = "collector_run"

    id = db.Column(db.String(36), primary_key=True)
    collector_config_id = db.Column(
        db.String(36),
        db.ForeignKey("collector_config.id"),
        nullable=False,
    )
    triggered_by_team_member_id = db.Column(
        db.String(36),
        db.ForeignKey("team_members.id"),
        nullable=True,
        comment="Null for scheduled runs",
    )
    trigger_type = db.Column(
        db.String(16),
        nullable=False,
        default="manual",
        comment="manual | scheduled | wizard",
    )
    started_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    finished_at = db.Column(db.DateTime(timezone=True), nullable=True)
    status = db.Column(
        db.String(16),
        nullable=False,
        default="running",
        comment="queued | running | success | failure | partial",
    )
    evidence_count = db.Column(db.Integer, default=0, nullable=False)
    check_pass_count = db.Column(db.Integer, default=0, nullable=False)
    check_fail_count = db.Column(db.Integer, default=0, nullable=False)
    error_message = db.Column(db.Text, nullable=True)
    heartbeat_at = db.Column(db.DateTime(timezone=True), nullable=True,
                             comment="Refreshed by the executing process while it holds the run's lock")
    executor_token = db.Column(db.String(36), nullable=True,
                               comment="Identifies the executor allowed to record this run's result")
    raw_log = db.Column(db.Text, nullable=True)

    __table_args__ = (
        db.Index(
            "uq_collector_run_one_active",
            "collector_config_id",
            unique=True,
            postgresql_where=db.text("status IN ('queued', 'running')"),
            sqlite_where=db.text("status IN ('queued', 'running')"),
        ),
    )

    check_results = db.relationship(
        "CollectorCheckResult",
        backref="run",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<CollectorRun {self.id} status={self.status}>"
