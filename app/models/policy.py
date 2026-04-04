"""Compliance policy model."""

from datetime import datetime, timezone

from app.models import db

policy_controls = db.Table(
    "policy_controls",
    db.Column("policy_id", db.String(36), db.ForeignKey("policies.id"), primary_key=True),
    db.Column("control_id", db.String(36), db.ForeignKey("controls.id"), primary_key=True),
)


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
    short_name = db.Column(db.String(50), comment="Short identifier (e.g., POL-1)")
    security_group = db.Column(db.String(255), comment="Security domain grouping")
    effective_date = db.Column(db.DateTime, comment="When the policy became effective")
    group_name = db.Column(db.String(255), comment="Ownership group")
    owner_id = db.Column(db.String(36), comment="Policy owner UUID")
    owner_name = db.Column(db.String(255), comment="Denormalized owner name")
    parent_policy_id = db.Column(db.String(36), db.ForeignKey("policies.id"), nullable=True, comment="Parent policy for procedure docs")
    notes = db.Column(db.Text)
    trustcloud_id = db.Column(db.String(36), comment="Original TrustCloud policy ID")
    other_data = db.Column(db.JSON, server_default="{}", comment="Unmapped fields from data imports")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    controls = db.relationship("Control", secondary=policy_controls, backref="policies")

    def __repr__(self):
        return f"<Policy {self.title} v{self.version}>"
