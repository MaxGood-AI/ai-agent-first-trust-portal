"""Risk register model."""

from datetime import datetime, timezone

from app.models import db


class RiskRegister(db.Model):
    __tablename__ = "risk_register"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    likelihood = db.Column(db.Integer, comment="Likelihood score 1-5")
    impact = db.Column(db.Integer, comment="Impact score 1-5")
    risk_score = db.Column(db.Float, comment="Calculated risk score")
    treatment = db.Column(db.String(50), comment="accept, mitigate, transfer, avoid")
    treatment_plan = db.Column(db.Text)
    status = db.Column(db.String(50), default="open", comment="open, mitigated, accepted, closed")
    owner_id = db.Column(db.String(36), comment="Risk owner UUID")
    owner_name = db.Column(db.String(255), comment="Denormalized owner name")
    group_name = db.Column(db.String(255), comment="Ownership group")
    review_date = db.Column(db.DateTime)
    trustcloud_id = db.Column(db.String(36))
    other_data = db.Column(db.JSON, server_default="{}", comment="Unmapped fields from data imports")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self):
        return f"<RiskRegister {self.name}>"
