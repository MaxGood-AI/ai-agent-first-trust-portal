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
        comment="Model: pending, passed, failed, not_applicable. Data import maps: success→passed, failure→failed, not_run→pending, excluded→not_applicable"
    )
    evidence_status = db.Column(
        db.String(50), default="missing",
        comment="Model: missing, submitted, outdated, due_soon. Data import maps: up_to_date→submitted, not_required→submitted, due→due_soon"
    )
    last_executed_at = db.Column(db.DateTime)
    due_at = db.Column(db.DateTime)
    system_id = db.Column(db.String(36), db.ForeignKey("systems.id"), nullable=True, comment="System under test")
    test_type = db.Column(db.String(50), comment="auto_assessment or self_assessment")
    execution_status = db.Column(db.String(50), comment="completed or null")
    execution_outcome = db.Column(db.String(50), comment="success, failure, or null")
    finding = db.Column(db.Text, comment="Test finding/result description")
    comment = db.Column(db.Text, comment="Additional reviewer notes")
    owner_id = db.Column(db.String(36), comment="Test owner UUID")
    owner_name = db.Column(db.String(255), comment="Denormalized owner name")
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
