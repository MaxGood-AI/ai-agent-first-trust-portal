"""Compliance policy model."""

from datetime import datetime, timezone

from app.models import db


class Policy(db.Model):
    __tablename__ = "policies"

    id = db.Column(db.String(36), primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    category = db.Column(
        db.String(50), nullable=False,
        comment="TSC category: security, availability, confidentiality, privacy, processing_integrity"
    )
    version = db.Column(db.String(20), default="1.0")
    file_path = db.Column(db.String(500), comment="Relative path to markdown file in policies/ directory")
    status = db.Column(
        db.String(50), default="draft",
        comment="draft, pending_approval, approved, retired"
    )
    approved_at = db.Column(db.DateTime)
    approved_by = db.Column(db.String(255))
    next_review_at = db.Column(db.DateTime)
    trustcloud_id = db.Column(db.String(36), comment="Original TrustCloud policy ID")
    other_data = db.Column(db.JSON, server_default="{}", comment="Unmapped fields from data imports")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    def __repr__(self):
        return f"<Policy {self.title} v{self.version}>"
