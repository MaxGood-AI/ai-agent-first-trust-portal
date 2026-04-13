"""Collector configuration model — stores evidence collector setup per collector."""

from datetime import datetime, timezone

from app.models import db


class CollectorConfig(db.Model):
    """Configuration for an evidence collector.

    One row per named collector (e.g., 'aws', 'git', 'platform', 'policy', 'vendor').
    Holds credentials (encrypted at rest), schedule, and cached permission probe results.
    """

    __tablename__ = "collector_config"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(
        db.String(64),
        unique=True,
        nullable=False,
        comment="Collector identifier: aws, git, platform, policy, vendor",
    )
    enabled = db.Column(db.Boolean, default=False, nullable=False)
    credential_mode = db.Column(
        db.String(32),
        nullable=False,
        default="task_role",
        comment="task_role | task_role_assume | access_keys | none",
    )
    encrypted_credentials = db.Column(
        db.LargeBinary,
        nullable=True,
        comment="Fernet ciphertext of credential JSON; null for task_role / none modes",
    )
    config = db.Column(
        db.JSON,
        nullable=True,
        comment="Non-secret configuration (regions, URLs, filters, schedule options)",
    )
    schedule_cron = db.Column(
        db.String(64),
        nullable=True,
        comment="Cron expression for scheduled runs; null if disabled",
    )
    last_run_at = db.Column(db.DateTime(timezone=True), nullable=True)
    next_run_at = db.Column(db.DateTime(timezone=True), nullable=True)
    last_run_status = db.Column(
        db.String(16),
        nullable=True,
        comment="success | failure | partial | running",
    )
    permission_check_at = db.Column(db.DateTime(timezone=True), nullable=True)
    permission_check_result = db.Column(
        db.JSON,
        nullable=True,
        comment="Cached permission probe result",
    )
    created_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at = db.Column(
        db.DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    created_by_id = db.Column(
        db.String(36),
        db.ForeignKey("team_members.id"),
        nullable=True,
    )
    updated_by_id = db.Column(
        db.String(36),
        db.ForeignKey("team_members.id"),
        nullable=True,
    )

    runs = db.relationship(
        "CollectorRun",
        backref="config",
        lazy="dynamic",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<CollectorConfig {self.name} enabled={self.enabled}>"
