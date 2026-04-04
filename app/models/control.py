"""SOC 2 control model."""

from datetime import datetime, timezone

from app.models import db


class Control(db.Model):
    __tablename__ = "controls"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(
        db.String(50), nullable=False,
        comment="TSC category: security, availability, confidentiality, privacy, processing_integrity"
    )
    state = db.Column(db.String(50), default="adopted")
    control_id_short = db.Column(db.String(50), comment="Human-readable ID (e.g., INFRA-8)")
    frequency = db.Column(db.String(50), comment="Assessment cadence: monthly, quarterly, annual")
    maturity_level = db.Column(db.Integer, comment="Implementation maturity 1-3")
    group_name = db.Column(db.String(255), comment="Ownership group (e.g., DevOps, Engineering)")
    owner_id = db.Column(db.String(36), comment="Control owner UUID")
    owner_name = db.Column(db.String(255), comment="Denormalized owner name")
    soc2_references = db.Column(db.JSON, comment="Array of {referenceId, description} SOC 2 mappings")
    source_category = db.Column(db.String(255), comment="Original organizational category (e.g., Cloud Infrastructure)")
    trustcloud_id = db.Column(db.String(36), comment="Original TrustCloud control ID for migration tracking")
    other_data = db.Column(db.JSON, server_default="{}", comment="Unmapped fields from data imports")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    tests = db.relationship("TestRecord", backref="control", lazy="dynamic")

    def __repr__(self):
        return f"<Control {self.name}>"
