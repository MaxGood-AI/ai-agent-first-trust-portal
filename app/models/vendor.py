"""Vendor inventory model."""

from datetime import datetime, timezone

from app.models import db

vendor_systems = db.Table(
    "vendor_systems",
    db.Column("vendor_id", db.String(36), db.ForeignKey("vendors.id"), primary_key=True),
    db.Column("system_id", db.String(36), db.ForeignKey("systems.id"), primary_key=True),
)


class Vendor(db.Model):
    __tablename__ = "vendors"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default="active", comment="active, inactive, under_review")
    is_subprocessor = db.Column(db.Boolean, default=False)
    classification = db.Column(db.JSON, comment="Data classification array")
    locations = db.Column(db.JSON, comment="Array of {label, value} location objects")
    group_name = db.Column(db.String(255), comment="Ownership group")
    purpose = db.Column(db.Text)
    website_url = db.Column(db.String(1000))
    privacy_policy_url = db.Column(db.String(1000))
    security_page_url = db.Column(db.String(1000))
    tos_url = db.Column(db.String(1000))
    certifications = db.Column(db.JSON, comment="Array of certification strings")
    trustcloud_id = db.Column(db.String(36), comment="Legacy TrustCloud ID")
    other_data = db.Column(db.JSON, server_default="{}", comment="Unmapped fields from data imports")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    systems = db.relationship("System", secondary=vendor_systems, backref="vendors")

    def __repr__(self):
        return f"<Vendor {self.name}>"
