"""System inventory model."""

from datetime import datetime, timezone

from app.models import db


class System(db.Model):
    __tablename__ = "systems"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    short_name = db.Column(db.String(100), comment="Kebab-case identifier (e.g., aws-code-commit)")
    purpose = db.Column(db.Text)
    risk_score = db.Column(db.Float, comment="Risk score 0-100")
    system_type = db.Column(db.JSON, comment="Array of type strings: application, infrastructure")
    provider = db.Column(db.String(255), comment="Vendor/provider name (e.g., AWS)")
    data_classifications = db.Column(db.JSON, comment="Array: customer_confidential, company_restricted, etc.")
    group_name = db.Column(db.String(255), comment="Ownership group")
    trustcloud_id = db.Column(db.String(36), comment="Legacy TrustCloud ID")
    other_data = db.Column(db.JSON, server_default="{}", comment="Unmapped fields from data imports")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    tests = db.relationship("TestRecord", backref="system", lazy="dynamic")

    def __repr__(self):
        return f"<System {self.name}>"
