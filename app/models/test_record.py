"""Compliance test record model."""

from datetime import datetime, timezone

from app.models import db


class TestRecord(db.Model):
    __tablename__ = "test_records"

    id = db.Column(db.String(36), primary_key=True)
    control_id = db.Column(db.String(36), db.ForeignKey("controls.id"), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    question = db.Column(db.Text, comment="The test question/criteria to evaluate")
    recommendation = db.Column(db.Text, comment="Guidance for passing this test")
    status = db.Column(
        db.String(50), default="pending",
        comment="pending, passed, failed, not_applicable"
    )
    evidence_status = db.Column(
        db.String(50), default="missing",
        comment="missing, submitted, outdated, due_soon"
    )
    last_executed_at = db.Column(db.DateTime)
    due_at = db.Column(db.DateTime)
    trustcloud_id = db.Column(db.String(36), comment="Original TrustCloud test ID")
    other_data = db.Column(db.JSON, server_default="{}", comment="Unmapped fields from data imports")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    evidence = db.relationship("Evidence", backref="test_record", lazy="dynamic")

    def __repr__(self):
        return f"<TestRecord {self.name}>"
