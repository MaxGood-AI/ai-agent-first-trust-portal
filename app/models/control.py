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
    trustcloud_id = db.Column(db.String(36), comment="Original TrustCloud control ID for migration tracking")
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
    )

    tests = db.relationship("TestRecord", backref="control", lazy="dynamic")

    def __repr__(self):
        return f"<Control {self.name}>"
